(ns net.ignorare.links.http
  (:require [bidi.ring]
            [cheshire.core :as json]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [hiccup.page :refer [html5]]
            [integrant.core :as ig]
            [net.ignorare.links.http.auth :as auth]
            [org.httpkit.server :as http-kit]
            [ring.middleware.defaults :refer [wrap-defaults site-defaults]]
            [ring.util.response :as res]
            [taoensso.sente :as sente]
            [taoensso.sente.server-adapters.http-kit :refer (get-sch-adapter)]
            [taoensso.timbre :refer [spy]]))


;;
;; https://github.com/ptaoussanis/sente
;;

(defn- log-connections [_key _connected_uids old-state new-state]
  (when (not= old-state new-state)
    (spy :info "connected-uids" new-state)))


(defmethod ig/init-key :http/sente [_ _]
  (let [sente (sente/make-channel-socket! (get-sch-adapter) {})]
    (add-watch (:connected-uids sente) :connection-log log-connections)
    sente))

(defmethod ig/halt-key! :http/sente [_ sente]
  (some-> (:connected-uids sente) (remove-watch :connection-log)))


;;
;; https://www.http-kit.org/server.html
;;

(defn- load-css-name []
  (if-some [path (some-> (io/resource "links/manifest.json")
                         (slurp)
                         (json/parse-string)
                         (get "links.css"))]
    path
    "links.css"))

(def css-name (memoize load-css-name))


(defn- load-js-name []
  (if-some [path (some-> (io/resource "links/modules.edn")
                         (slurp)
                         (edn/read-string)
                         (get-in [0 :output-name]))]
    path
    "links.js"))

(def js-name (memoize load-js-name))


(defn- render-page
  [req]
  (html5 [:head
          [:meta {:charset "utf-8"}]
          [:meta {:name "viewport", :content "width=device-width, initial-scale=1"}]
          [:title "Links"]
          [:link {:rel "stylesheet", :href (str "/static/" (css-name))}]
          [:script {:defer true, :src (str "/static/" (js-name))}]]
         [:body {:data-csrf-token (:anti-forgery-token req)}]))

(defn- index-handler
  [req]
  (case (:request-method req)
    :get (-> (res/response (render-page req))
             (res/content-type "text/html"))
    (res/status 405)))


(defn- chsk-handler [{:keys [ajax-get-or-ws-handshake-fn ajax-post-fn]}]
  (fn [req]
    (case (:request-method req)
      :get (ajax-get-or-ws-handshake-fn req)
      :post (ajax-post-fn req)
      (res/status 405))))


(defn- routes [crux sente]
  ["/" {"" index-handler
        "auth" {"" (auth/auth-handler crux)}
        "chsk" (chsk-handler sente)
        "static/" (bidi.ring/resources {:prefix "public/"})}])


(defn- app [crux sente]
  (-> (bidi.ring/make-handler (routes crux sente))
      (wrap-defaults site-defaults)))


(defmethod ig/init-key :http/server [_ {:keys [config crux sente]}]
  (let [stop-fn (http-kit/run-server (app crux sente)
                                     {:port (-> config :http :port)})]
    {:stop-fn stop-fn}))

(defmethod ig/halt-key! :http/server [_ {:keys [stop-fn]}]
  (when stop-fn
    (stop-fn)))
