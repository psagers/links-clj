(ns net.ignorare.links
  (:require [day8.re-frame.http-fx]
            [goog.dom.dataset :as dataset]
            [net.ignorare.links.ui.auth :as auth]
            [reagent.core :as r]
            [taoensso.sente :as sente]))


(defn- csrf-token []
  (dataset/get js/document.body "csrfToken"))


(defn ^:dev/after-load install-view []
  (r/render [auth/login-view] (js/document.getElementById "links")))


(defn init []
  ;; (sente/make-channel-socket! "/chsk" (csrf-token))
  (install-view))
