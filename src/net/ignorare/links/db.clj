(ns net.ignorare.links.db
  (:require [crux.api :as crux]
            [integrant.core :as ig]))


;; Starts Crux and returns the ICruxNode.
(defmethod ig/init-key :db/crux [_ {:keys [_config]}]
  (crux/start-node {:crux.node/topology :crux.jdbc/topology
                    :crux.jdbc/dbtype "postgresql"
                    :crux.jdbc/dbname "links"
                    :crux.jdbc/user "postgres"
                    :crux.kv/db-dir ".crux-data"}))

(defmethod ig/halt-key! :db/crux [_ node]
  (when (some? node)
    (.close node)))


;; Creates an agent to process transactions on our Crux node.
(defmethod ig/init-key :db/transactor [_ {:keys [node]}]
  (agent {:node node}, :error-mode :continue))

(defmethod ig/halt-key! :db/transactor [_ transactor]
  (send transactor #(assoc % :node nil))
  (await transactor))


(defn ^:private transact-inner
  "The function that runs inside the transactor agent."
  [{:keys [node] :as state} tx-fn cb-fn]
  (let [tx-info (when node
                  (when-some [tx-ops (try (tx-fn (crux/db node)) (catch Exception _))]
                    (crux/submit-tx node tx-ops)))]
    (when cb-fn
      (future (cb-fn tx-info))))

  state)

(defn transact!
  "Applies a transaction function to our Crux node.

  tx-fun is a function that takes an ICruxDatasource and returns a vector of
  zero or more transaction operations (the second argument to
  crux.api/submit-tx).

  The optional cb-fn is a callback to receive details (on another thread) of the
  submitted Crux transaction, if any.
  "
  ([transactor tx-fn]
   (transact! transactor tx-fn nil))

  ([transactor tx-fn cb-fn]
   (send transactor transact-inner tx-fn cb-fn)
   nil))
