(ns net.ignorare.links.test
  (:require [clojure.spec.test.alpha :as stest]
            [integrant.core :as ig]
            [net.ignorare.links :refer [ig-config]]))


;; An initialized integrant system during tests.
(def ^:dynamic *system* nil)


(defn with-ig
  "Returns a test fixture for testing under a running Integrant system.

  config-fn: A function that transforms a configuration map. This is typically
  used to remove irrelevant keys for faster tests. The aero profile is already
  set to :test.

  args: Additional args to config-fn.

  Example:

    (use-fixtures :each (ig-fixture dissoc :http/server :http/sente))

  "
  ([]
   (with-ig identity))

  ([config-fn & args]
   (let [config (apply config-fn (ig-config :test) args)]
     (fn [f]
       (binding [*system* (ig/init config)]
         (f)
         (ig/halt! *system*))))))


(defn with-instrumentation [f]
  (stest/instrument)
  (f)
  (stest/unstrument))
