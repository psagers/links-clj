(ns net.ignorare.links
  (:require [clojure.edn :as edn]
            [clojure.java.io :as io]
            [integrant.core :as ig]
            [net.ignorare.links.db]
            [net.ignorare.links.http]
            [net.ignorare.links.sys])
  (:gen-class))


(def ig-config
  {:sys/config {}
   :db/crux {:config (ig/ref :sys/config)}
   :db/transactor {:node (ig/ref :db/crux)}})
   ;; :http/sente {:transactor (ig/ref :db/transactor)}
   ;; :http/http-kit {:sente (ig/ref :http/sente)}})


(defn -main [& _args]
  (with-open [rdr (-> "private/modules.edn" io/resource io/reader)
              pb (java.io.PushbackReader. rdr)]
    (let [manifest (edn/read pb)]
      (prn manifest))))
