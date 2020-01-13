(ns net.ignorare.links.db
  (:require [clojure.core.async :as async :refer [<! >! go-loop]]
            [clojure.spec.alpha :as s]
            [crux.api :as crux]
            [integrant.core :as ig]
            [taoensso.timbre :as log]))


(s/def ::base64url (s/and string? #(re-matches #"^[A-Za-z0-9_-]+={0,3}$" %)))

;; A transactor function takes a Crux data source and (optionally) returns a
;; vector of transaction operations (tx-ops).
(s/def ::tx-fn (s/fspec :args (s/cat :db #(instance? crux.api.ICruxDatasource %))
                        :ret (s/nilable (s/coll-of vector?, :kind vector?))))


(defprotocol IntoCruxDatasource
  "A protocol for turning values into ICruxDatasource.

  This is a convenience that can simplify high-level database API definitions.
  Things that implement this:

    - ICruxDatasource itself, obviously.
    - The crux node.
    - Our crux integrant component.
  "
  :extend-via-metadata true
  (to-db [this]))

;; clojure.core/satisfies? does not see metadata-based protocol implementations.
(s/def ::datasource (s/or :proto #(satisfies? IntoCruxDatasource %)
                          :meta #(contains? (meta %) `to-db)))


(extend-protocol IntoCruxDatasource
  crux.api.ICruxDatasource
  (to-db [this]
    this)

  crux.api.ICruxAPI
  (to-db [this]
    (crux/db this)))

(s/fdef to-db
  :args (s/cat :this ::datasource)
  :ret #(instance? crux.api.ICruxDatasource %))


(defn q
  "A simple crux.api/q wrapper that takes any IntoCruxDatasource value."
  ([db query]
   (crux/q (to-db db) query))

  ([db query xform]
   (into #{} xform (q db query))))

(s/fdef q
  :args (s/cat :db ::datasource
               :query map?
               :xform (s/? fn?))
  :ret set?)


(defn entity
  "A simple crux.api/entity wrapper that takes any IntoCruxDatasource value."
  [db entity-id]
  (crux/entity (to-db db) entity-id))

(s/fdef entity
  :args (s/cat :db ::datasource
               :entity-id any?)
  :ret (s/nilable map?))


(defn ^:private transactor
  "Runs the Crux transactor as a core.async thread.

  node: An ICruxAPI.

  tx-chan: A core.async channel, which effectively pipes to crux.api/submit-tx.
  It expects values of the form [tx-fn, result-chan]. tx-fn is a function that
  takes an ICruxDatasource and returns a vector of transaction operations (the
  second argument to crux.api/submit-tx). result-chan is a promise-chan that
  will receive the transaction details."
  [node tx-chan]
  (go-loop []
    (when-some [[tx-fn result-chan] (<! tx-chan)]
      (try
        (let [tx-ops (tx-fn (crux/db node))
              tx-info (crux/submit-tx node tx-ops)]
          (when (some? tx-info)
            (>! result-chan tx-info)))
        (catch Exception e
          (log/error e)))

      ;; Always make sure result-chan is closed, whether or not we put a result
      ;; on it.
      (async/close! result-chan)

      (recur))))


(defmethod ig/init-key :db/crux [_ {:keys [config]}]
  (let [node (crux/start-node (:crux config))
        tx-chan (async/chan)
        transactor-chan (transactor node tx-chan)]
    (with-meta
      {:node node, :tx-chan tx-chan, :transactor-chan transactor-chan}
      {`to-db #(crux/db (:node %))})))


;; Stop accepting transactions and give the transactor a second to terminate.
(defmethod ig/halt-key! :db/crux [_ {:keys [node tx-chan transactor-chan]}]
  (when tx-chan
    (async/close! tx-chan))
  (when transactor-chan
    (async/alts!! [transactor-chan (async/timeout 1000)]))
  (when node
    (.close node)))


(s/def ::node #(instance? crux.api.ICruxAPI %))
(s/def ::tx-chan some?)  ;; async/chan?
(s/def ::transactor-chan some?)  ;; async/chan?

(s/def ::crux (s/keys :req-un [::node ::tx-chan ::transactor-chan]))


(defn transact!
  "Applies a transaction function to our Crux node.

  The first argument is the value of :db/crux from the integrant system.

  tx-fn is a function that takes an ICruxDatasource and returns a vector of
  transaction operations (the second argument to crux.api/submit-tx).

  The :sync? keyword argument may be passed to block until this node has
  processed the new transaction.

  Returns a promise-chan that will convey the result of crux.api/submit-tx, if
  any. If tx-fn throws an exception, it will be logged and no transaction will
  be submitted."
  [{:keys [node tx-chan]} tx-fn & {:keys [sync?]}]
  (let [result-chan (async/promise-chan)]
    (async/put! tx-chan [tx-fn result-chan])

    (when sync?
      (when-some [{:crux.tx/keys [tx-time]} (async/<!! result-chan)]
        (crux/sync node tx-time nil)))

    result-chan))

(s/def ::sync? boolean?)

(s/fdef transact!
  :args (s/cat :crux ::crux
               :tx-fn ::tx-fn
               :optional (s/keys* :opt-un [::sync?])))
