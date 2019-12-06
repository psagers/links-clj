(ns net.ignorare.links
  (:require [taoensso.sente :as sente]
            [goog.dom.dataset :as dataset]))


(defn- csrf-token []
  (dataset/get js/document.body "csrfToken"))


(defn init []
  (sente/make-channel-socket! "/chsk" (csrf-token)))
