(ns net.ignorare.links.http
  (:require [bidi.ring]
            [cheshire.core :as json]
            [clojure.edn :as edn]
            [clojure.java.io :as io]
            [clojure.spec.alpha :as s]
            [hiccup.page :refer [html5]]
            [integrant.core :as ig]
            [net.ignorare.links.db :as db]
            [net.ignorare.links.http.auth :as auth]
            [net.ignorare.links.webauthn :as webauthn]
            [org.httpkit.server :as http-kit]
            [ring.middleware.defaults :refer [wrap-defaults site-defaults]]
            [ring.middleware.format :refer [wrap-restful-format]]
            [ring.util.response :as res]))


;; Request keys.
(s/def ::crux ::db/crux)
(s/def ::webauthn ::webauthn/webauthn)

;; Session keys
(s/def ::credential-ids (s/coll-of uuid?, :kind set?))


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
         [:body {:data-csrf-token (:anti-forgery-token req)}
          [:section#links.section]]))

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


(defn- api-handler
  [routes]
  (-> (bidi.ring/make-handler routes)
      (wrap-restful-format)))

(s/fdef api-handler
  :args (s/cat :routes vector?)
  :ret fn?)


(defn- routes
  [sente]
  ["/" {;; HTML and static assets.
        "" index-handler
        "static/" (bidi.ring/resources {:prefix "public/"})

        ;; Conventional AJAX APIs for authentication and session management.
        "auth/" (api-handler ["" {"webauthn/" {"register" auth/webauthn-register-handler
                                               "login" auth/webauthn-login-handler}
                                  "device" auth/device-handler
                                  "logout" auth/logout-handler}])

        ;; Everything else is over sente.
        "chsk" (chsk-handler sente)}])

(s/fdef routes
  :args (s/cat :sente ::sente)
  :ret vector?)


(defn- wrap-system
  "Adds relevant system components to requests."
  [handler crux webauthn]
  (fn [request]
    (-> request
        (assoc ::crux crux
               ::webauthn webauthn)
        (handler))))


(defn- app
  [crux webauthn sente]
  (-> (bidi.ring/make-handler (routes sente))
      (wrap-system crux webauthn)
      (wrap-defaults site-defaults)))


(defmethod ig/init-key :http/server [_ {:keys [config crux webauthn sente]}]
  (let [stop-fn (http-kit/run-server (app crux webauthn sente)
                                     {:port (get-in config [:http :port])})]
    {:stop-fn stop-fn}))

(defmethod ig/halt-key! :http/server [_ {:keys [stop-fn]}]
  (when stop-fn
    (stop-fn)))
