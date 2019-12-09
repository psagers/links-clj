(ns net.ignorare.links.test
  (:require [integrant.core :as ig]
            [net.ignorare.links :refer [ig-config]]))


;; An initialized integrant system during tests.
(def ^:dynamic *system* nil)


(defn ig-fixture
  "Returns a test fixture for testing under a running Integrant system.

  config-fn: A function that transforms a configuration map. This is typically
  used to remove irrelevant keys for faster tests. The aero profile is already
  set to :test.

  args: Additional args to config-fn.

  Example:

    (use-fixtures :each (ig-fixture dissoc :http/server :http/sente))

  "
  ([]
   (ig-fixture identity))

  ([config-fn & args]
   (let [config (apply config-fn (ig-config :test) args)]
     (fn [f]
       (binding [*system* (ig/init config)]
         (f)
         (ig/halt! *system*))))))
