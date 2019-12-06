(ns user
  (:require [integrant.repl :refer [clear go halt prep init reset reset-all]]
            [integrant.repl.state :refer [system]]
            [net.ignorare.links]
            [net.ignorare.links.db :as db]
            [net.ignorare.links.http :as http]
            [net.ignorare.links.sys :as sys]))


(integrant.repl/set-prep! net.ignorare.links/ig-config)


;;
;; Access to top-level integrant components.
;;

(defn config []
  (::sys/config system))

(defn crux []
  (::db/crux system))

(defn transactor []
  (::db/transactor system))

(defn sente []
  (::http/sente system))

(defn server []
  (::http/server system))
