(ns net.ignorare.links.http.util
  (:require [ring.util.response :as res]))


(defn transit-response [body]
  (-> (res/response body)
      (res/content-type "application/transit+json")))
