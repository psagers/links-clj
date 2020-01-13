(ns net.ignorare.links
  (:require [clojure.core.async :as async]
            [day8.re-frame.http-fx]
            [goog.dom.dataset :as dataset]
            [maximgb.re-state.core :as rs]
            [net.ignorare.links.auth :as auth]
            [net.ignorare.links.conn :as conn]
            [re-frame.core :as rf]
            [reagent.core :as r]
            [taoensso.sente :as sente]))


;; (defn- csrf-token []
;;   (dataset/get js/document.body "csrfToken"))


(defn view []
  (r/with-let [auth-required? (rf/subscribe [::conn/auth-required?])]
    [:div
     [conn/status-view]
     (when @auth-required?
       [auth/login-view])]))


(defn ^:dev/after-load install-view []
  (r/render [view] (js/document.getElementById "links")))
  ;; (r/render [auth/login-view] (js/document.getElementById "links")))


(defn init []
  (rf/dispatch-sync [::conn/init])
  (install-view))


(rf/add-post-event-callback ::log (fn [event _queue] (js/console.log "Handled event:" event)))


  ;; (let [{:keys [ch-recv]} (sente/make-channel-socket! "/chsk" (csrf-token) {:type :ws})]
  ;;   (async/go-loop [msg (async/<! ch-recv)]
  ;;     (when msg
  ;;       (js/console.log msg)
  ;;       (recur (async/<! ch-recv))))))


