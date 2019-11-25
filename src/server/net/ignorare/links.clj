(ns net.ignorare.links
  (:require [clojure.java.io :as io])
  (:gen-class))


(defn -main [& _args]
  (let [manifest (slurp (io/resource "manifest.json"))]
    (println manifest)))
