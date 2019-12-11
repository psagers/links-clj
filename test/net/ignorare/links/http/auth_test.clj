(ns net.ignorare.links.http.auth-test
  (:require [clojure.test :refer [deftest is]]
            [net.ignorare.links.http.auth :as auth])
  (:import (com.yubico.webauthn.data ByteArray)))


(deftest uuid-encoding
  (let [uuid #uuid "cb877467-71c7-49e2-8bf9-c96ad927e973"]
    (is (= (ByteArray/fromHex "cb87746771c749e28bf9c96ad927e973")
           (auth/uuid->ByteArray uuid))
        "uuid->ByteArray did not preserve byte order.")

    (is (= uuid
           (-> uuid auth/uuid->ByteArray auth/ByteArray->uuid))
        "Failed to round-trip a UUID through ByteArray.")))
