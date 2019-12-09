(ns net.ignorare.links
  (:require [clojure.java.io :as io]
            [integrant.core :as ig]
            [net.ignorare.links.db :as db]
            [net.ignorare.links.http :as http]
            [net.ignorare.links.sys :as sys])
  (:gen-class))


(defn ig-config
  [profile]
  (let [config (slurp (io/resource "links/system.edn"))]
    (-> (ig/read-string config)
        (assoc-in [:sys/config :profile] profile))))


(defn -main [& _args]
  (let [system (ig/init (ig-config :default))]
    (.addShutdownHook (Runtime/getRuntime) (Thread. #(ig/halt! system)))))
