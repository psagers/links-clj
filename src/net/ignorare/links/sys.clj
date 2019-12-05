(ns net.ignorare.links.sys
  (:require [aero.core :as aero]
            [clojure.java.io :as io]
            [integrant.core :as ig]))


(defmethod ig/init-key :sys/config [_ _]
  (aero/read-config (io/resource "links/config.edn")))
