(ns net.ignorare.links.db
  (:require [clojure.core.async :as async :refer [<! >! go-loop]]
            [crux.api :as crux]
            [integrant.core :as ig]
            [taoensso.timbre :as log]))


;; Starts Crux and returns the ICruxNode.
(defmethod ig/init-key :db/crux [_ {:keys [config]}]
  (crux/start-node (:crux config)))

(defmethod ig/halt-key! :db/crux [_ node]
  (when (some? node)
    (.close node)))


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

(defmethod ig/init-key :db/transactor [_ {:keys [node]}]
  (let [tx-chan (async/chan)
        transactor-chan (transactor node tx-chan)]
    {:tx-chan tx-chan, :transactor-chan transactor-chan}))

;; Stop accepting transactions and give the transactor a second to terminate.
(defmethod ig/halt-key! :db/transactor [_ {:keys [tx-chan transactor-chan]}]
  (async/close! tx-chan)
  (async/alts!! [transactor-chan (async/timeout 1000)]))


(defn transact!
  "Applies a transaction function to our Crux node.

  tx-fn is a function that takes an ICruxDatasource and returns a vector of
  transaction operations (the second argument to crux.api/submit-tx).

  Returns a promise-chan that will convey the result of crux.api/submit-tx, if
  any. If tx-fn throws an exception, it will be ignored and no transaction will
  be submitted."
  [{:keys [tx-chan]} tx-fn]
  (let [result-chan (async/promise-chan)]
    (async/put! tx-chan [tx-fn result-chan])
    result-chan))
