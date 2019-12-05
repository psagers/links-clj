(ns user
  (:require [integrant.repl :refer [clear go halt prep init reset reset-all]]
            [net.ignorare.links]))


(integrant.repl/set-prep! (fn [] net.ignorare.links/ig-config))
