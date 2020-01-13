(ns net.ignorare.links.test
  (:require [clojure.spec.test.alpha :as stest]
            [integrant.core :as ig]
            [net.ignorare.links :refer [ig-config]]))


;; An initialized integrant system during tests.
(def ^:dynamic *system* nil)


(defn with-ig
  "Returns a test fixture for testing under a running Integrant system.

  keys: System keys to initialize.

  Example:

    (use-fixtures :each (with-ig #{:db/crux}))

  "
  [keys]
  (fn [f]
    (binding [*system* (ig/init (ig-config :test) keys)]
      (f)
      (ig/halt! *system*))))


(defn with-instrumentation [f]
  (stest/instrument)
  (f)
  (stest/unstrument))
