(ns net.ignorare.links.sys
  (:require [aero.core :as aero]
            [clojure.java.io :as io]
            [integrant.core :as ig]
            [taoensso.timbre :as timbre]))


(defmethod ig/init-key :sys/config [_ aero-opts]
  (let [url (io/resource "links/config.edn")]
    (aero/read-config url aero-opts)))


(defmethod ig/init-key :sys/logging [_ {:keys [config]}]
  (timbre/merge-config! (:timbre config))
  nil)
