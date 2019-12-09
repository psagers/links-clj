(ns user
  (:require [crux.api :as crux]
            [clojure.core.async :as async :refer [<!!]]
            [integrant.repl :refer [clear go halt prep init reset reset-all]]
            [integrant.repl.state :refer [system]]
            [net.ignorare.links]
            [net.ignorare.links.db :as db]
            [net.ignorare.links.http :as http]
            [net.ignorare.links.sys :as sys])
  (:import java.util.UUID))


(integrant.repl/set-prep! #(net.ignorare.links/ig-config :dev))


;;
;; Access to top-level integrant components.
;;

(defn config []
  (:sys/config system))

(defn crux []
  (:db/crux system))

(defn transactor []
  (:db/transactor system))

(defn sente []
  (:http/sente system))

(defn server []
  (:http/server system))


(defn q [query]
  (crux/q (-> (crux) :node crux/db) query))


(comment
  (-> (db/transact! (crux)
                    (constantly [[:crux.tx/put {:crux.db/id (UUID/randomUUID)
                                                :links.user/email "psagers@ignorare.net"
                                                :links.user/name "Peter Sagerson"}]]))
      (<!!))

  (q '{:find [uid email name]
       :where [[uid :links.user/email email]
               [uid :links.user/name name]]})

  {:crux.db/id "uuid"
   :links.user/email "psagers@ignorare.net"
   :links.user/name "Peter Sagerson"
   :links.user/credentials #{}
   :links.user/devices #{}}

  {:crux.db/id "uuid"
   :links.credential/mechanism #{:webauthn}
   :links.credential.webauthn/id ""
   :links.credential.webauthn/public-key ""
   :links.credential.webauthn/signature-count 0}

  {:crux.db/id "uuid"
   :links.device/name ""
   :links.device/key ""})
