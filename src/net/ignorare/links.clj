(ns net.ignorare.links
  (:require [clojure.java.io :as io]
            [integrant.core :as ig])
  (:gen-class))


(defn ig-config []
  (ig/read-string (slurp (io/resource "links/system.edn"))))


(defn -main [& _args]
  (let [system (ig/init (ig-config))]
    (.addShutdownHook (Runtime/getRuntime) (Thread. #(ig/halt! system)))))
