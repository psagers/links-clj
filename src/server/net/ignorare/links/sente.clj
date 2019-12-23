(ns net.ignorare.links.sente
  (:require [clojure.spec.alpha :as s]
            [integrant.core :as ig]
            [taoensso.sente :as sente]
            [taoensso.sente.server-adapters.http-kit :refer (get-sch-adapter)]
            [taoensso.timbre :as log :refer [spy]]))


;;
;; https://github.com/ptaoussanis/sente
;;

(defn- log-connections [_key _connected_uids old-state new-state]
  (when (not= old-state new-state)
    (spy :info "connected-uids" new-state)))


(defmethod ig/init-key :http/sente [_ _]
  (let [sente (sente/make-channel-socket! (get-sch-adapter) {})]
    (add-watch (:connected-uids sente) :connection-log log-connections)
    sente))

(defmethod ig/halt-key! :http/sente [_ sente]
  (some-> (:connected-uids sente) (remove-watch :connection-log)))


(s/def ::sente map?)
