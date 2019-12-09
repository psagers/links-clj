(ns net.ignorare.links.db
  (:require [clojure.core.async :as async :refer [<! >! go-loop]]
            [crux.api :as crux]
            [integrant.core :as ig]
            [taoensso.timbre :as log]))


(defn ^:private transactor
  "Runs the Crux transactor as a core.async thread.

  node: An ICruxNode.

  tx-chan: A core.async channel, which effectively pipes to crux.api/submit-tx.
  It expects values of the form [tx-fn, result-chan]. tx-fn is a function that
  takes an ICruxDatasource and returns a vector of zero or more transaction
  operations (the second argument to crux.api/submit-tx). result-chan is a
  promise-chan that will receive the transaction details."
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
    {:node node, :tx-chan tx-chan, :transactor-chan transactor-chan}))


;; Stop accepting transactions and give the transactor a second to terminate.
(defmethod ig/halt-key! :db/crux [_ {:keys [node tx-chan transactor-chan]}]
  (when tx-chan
    (async/close! tx-chan))
  (when transactor-chan
    (async/alts!! [transactor-chan (async/timeout 1000)]))
  (when node
    (.close node)))


(defn transact!
  "Applies a transaction function to our Crux node.

  The first argument is the value of :db/crux from the integrant system.

  tx-fn is a function that takes an ICruxDatasource and returns a vector of
  transaction operations (the second argument to crux.api/submit-tx).

  The :sync? keyword argument may be passed to block until this node has
  processed the new transaction.

  Returns a promise-chan that will convey the result of crux.api/submit-tx, if
  any. If tx-fn throws an exception, it will be ignored and no transaction will
  be submitted."
  [{:keys [node tx-chan] :as _crux} tx-fn & {:keys [sync?]}]
  (let [result-chan (async/promise-chan)]
    (async/put! tx-chan [tx-fn result-chan])

    (when sync?
      (when-some [{:crux.tx/keys [tx-time]} (async/<!! result-chan)]
        (crux/sync node tx-time nil)))

    result-chan))
