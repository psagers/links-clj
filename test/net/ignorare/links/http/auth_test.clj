(ns net.ignorare.links.http.auth-test
  (:require [clojure.test :refer [deftest is]]
            [net.ignorare.links.http.auth :as auth])
  (:import (java.util UUID)))


(deftest roundtrip-uuid
  (let [uuid (UUID/randomUUID)]
    (is (= uuid
           (-> uuid auth/uuid->ByteArray auth/ByteArray->uuid)))))
