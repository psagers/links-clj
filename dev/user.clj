(ns user
  (:require [clojure.core.async :as async :refer [<!!]]
            [clojure.spec.test.alpha :as stest]
            [crux.api :as crux]
            [integrant.repl :refer [clear go halt prep init reset reset-all]]
            [integrant.repl.state :refer [system]]
            [net.ignorare.links]
            [net.ignorare.links.db :as db]
            [net.ignorare.links.http :as http]
            [net.ignorare.links.models.users :as users]
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


(defn db []
  (-> (crux) :node crux/db))

(defn q [query]
  (crux/q (-> (crux) :node crux/db) query))


(comment
  (-> (db/transact! (crux)
                    (constantly [[:crux.tx/put {:crux.db/id #uuid "78c7f19e-2d2e-4959-951b-2f6bd8cc2690"
                                                :links.user/email "psagers@ignorare.net"
                                                :links.user/name "Peter Sagerson"}]]))
      (<!!))


  (def user-id #uuid "78c7f19e-2d2e-4959-951b-2f6bd8cc2690")
  (def user (crux/entity (db) user-id))

  (crux/entity (db) (:crux.db/id user))

  (-> (db/transact! (crux) (users/tx-remove-all-credentials user-id))
      <!!)

  (q {:find '[c]
      :where '[[c :links.credential/mechanism m]]
      :args [{'m #{:webauthn}}]})

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
