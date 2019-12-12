(ns net.ignorare.links.http.credentials-test
  "Tests for net.ignorare.links.http.webauthn/CruxCredentials"
  (:require [clojure.test :refer [use-fixtures deftest is join-fixtures]]
            [crux.api :as crux]
            [net.ignorare.links.models.users :as users]
            [net.ignorare.links.test :refer [with-ig with-instrumentation *system*]]
            [net.ignorare.links.webauthn :as webauthn :refer [uuid->ByteArray]])
  (:import (com.yubico.webauthn.data ByteArray)
           (java.util UUID Optional)))


(def alice-id #uuid "ac71fc2b-3e42-4eea-9cb2-cf8f62aff1f1")
(def bob-id #uuid "0b23e5b5-78e4-4c50-95ce-1553c013a6cd")
(def carol-id #uuid "aba84f0d-8746-45d8-a0aa-14194178eedb")

(def cred-1-id #uuid "810a8947-c93f-4d3b-8e8d-35a201d7a117")
(def cred-2-id #uuid "084ce69a-ae0d-4507-8cc8-6dd0dc67b555")
(def cred-3-id #uuid "25cc4d91-4b96-40b8-8939-8f4787df6803")
(def cred-4-id #uuid "2cd7cb9d-8e93-43de-be9a-2fda3f4cab01")
(def cred-5-id #uuid "6a30c8a2-e326-4a38-871e-12082a0134ca")
(def cred-6-id #uuid "7177a125-dbfe-4af9-a07f-6f79b2c8fdba")

(def webauthn-1-id (-> "cred-1-id" .getBytes ByteArray. .getBase64Url))
(def webauthn-2-id (-> "cred-2-id" .getBytes ByteArray. .getBase64Url))
(def webauthn-3-id (-> "cred-3-id" .getBytes ByteArray. .getBase64Url))
(def webauthn-4-id (-> "cred-4-id" .getBytes ByteArray. .getBase64Url))

(def fake-public-key (-> "public-key" .getBytes ByteArray. .getBase64Url))


(def fixture-docs
  {alice-id
   {:crux.db/id alice-id
    :links.user/email "alice@example.com"
    :links.user/credentials #{cred-1-id cred-2-id}}

   bob-id
   {:crux.db/id bob-id
    :links.user/email "bob@example.com"
    :links.user/credentials #{cred-3-id cred-4-id cred-5-id}}

   carol-id
   {:crux.db/id carol-id
    :links.user/email "carol@example.com"
    :links.user/credentials #{cred-6-id}}

   cred-1-id
   {:crux.db/id cred-1-id
    :links.credential/mechanism :webauthn
    :links.credential.webauthn/id webauthn-1-id
    :links.credential.webauthn/public-key fake-public-key}

   cred-2-id
   {:crux.db/id cred-2-id}

   cred-3-id
   {:crux.db/id cred-3-id
    :links.credential/mechanism :webauthn
    :links.credential.webauthn/id webauthn-3-id
    :links.credential.webauthn/public-key fake-public-key
    :links.credential.webauthn/signature-count 10}

   cred-4-id
   {:crux.db/id cred-4-id
    :links.credential/mechanism :webauthn
    :links.credential.webauthn/id webauthn-4-id
    :links.credential.webauthn/public-key fake-public-key}

   cred-5-id
   {:crux.db/id cred-5-id}

   cred-6-id
   {:crux.db/id cred-6-id
    :links.credential/mechanism :webauthn
    :links.credential.webauthn/id webauthn-3-id
    :links.credential.webauthn/public-key fake-public-key}})


(defn fixture-tx-ops []
  (mapv #(vector :crux.tx/put %) (vals fixture-docs)))


(defn load-data []
  (let [node (-> *system* :db/crux :node)]
    (when-some [{:crux.tx/keys [tx-time]} (crux/submit-tx node (fixture-tx-ops))]
      (crux/sync node tx-time nil))))


(defn with-data [f]
  (load-data)
  (f))


(use-fixtures :once (join-fixtures [(with-ig dissoc :http/server :http/sente)
                                    with-data
                                    with-instrumentation]))


(defn public-key-credential-descriptor
  [webauthn-id]
  (webauthn/public-key-credential-descriptor (ByteArray/fromBase64Url webauthn-id)))


(defn registered-credential
  [user-id webauthn-id]
  (let [db (:db/crux *system*)]
    (when-some [credential-id (users/webauthn-credential-id-for-user db user-id webauthn-id)]
      (webauthn/registered-credential user-id (fixture-docs credential-id)))))


(deftest get-credential-ids-for-username
  (let [credentials (webauthn/->CruxCredentials (-> *system* :db/crux :node))]
    (is (= #{(public-key-credential-descriptor webauthn-1-id)}
           (.getCredentialIdsForUsername credentials "alice@example.com")))
    (is (= #{(public-key-credential-descriptor webauthn-3-id)
             (public-key-credential-descriptor webauthn-4-id)}
           (.getCredentialIdsForUsername credentials "bob@example.com")))
    (is (= #{(public-key-credential-descriptor webauthn-3-id)}
           (.getCredentialIdsForUsername credentials "carol@example.com")))))


(deftest get-user-handle-for-username
  (let [credentials (webauthn/->CruxCredentials (-> *system* :db/crux :node))]
    (is (= (Optional/of (uuid->ByteArray alice-id))
           (.getUserHandleForUsername credentials "alice@example.com")))
    (is (= (Optional/of (uuid->ByteArray bob-id))
           (.getUserHandleForUsername credentials "bob@example.com")))
    (is (= (Optional/empty)
           (.getUserHandleForUsername credentials "bogus@example.com")))))


(deftest get-username-for-user-handle
  (let [credentials (webauthn/->CruxCredentials (-> *system* :db/crux :node))]
    (is (= (Optional/of "alice@example.com")
           (.getUsernameForUserHandle credentials (uuid->ByteArray alice-id))))
    (is (= (Optional/of "bob@example.com")
           (.getUsernameForUserHandle credentials (uuid->ByteArray bob-id))))
    (is (= (Optional/empty)
           (.getUsernameForUserHandle credentials (uuid->ByteArray (UUID/randomUUID)))))))


(deftest lookup-credential
  (let [credentials (webauthn/->CruxCredentials (-> *system* :db/crux :node))]
    (is (= (Optional/of (registered-credential alice-id webauthn-1-id))
           (.lookup credentials (ByteArray/fromBase64Url webauthn-1-id) (uuid->ByteArray alice-id))))
    (is (= (Optional/of (registered-credential bob-id webauthn-3-id))
           (.lookup credentials (ByteArray/fromBase64Url webauthn-3-id) (uuid->ByteArray bob-id))))
    (is (= (Optional/empty)
           (.lookup credentials (ByteArray/fromBase64Url webauthn-1-id) (uuid->ByteArray bob-id))))))


(deftest lookup-all-credentials
  (let [credentials (webauthn/->CruxCredentials (-> *system* :db/crux :node))]
    (is (= #{(registered-credential alice-id webauthn-1-id)}
           (.lookupAll credentials (ByteArray/fromBase64Url webauthn-1-id))))
    (is (= #{(registered-credential bob-id webauthn-3-id)
             (registered-credential carol-id webauthn-3-id)}
           (.lookupAll credentials (ByteArray/fromBase64Url webauthn-3-id))))
    (is (= #{}
           (.lookupAll credentials (ByteArray. (.getBytes "bogus-credential-id")))))))
