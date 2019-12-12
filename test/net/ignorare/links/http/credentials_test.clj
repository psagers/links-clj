(ns net.ignorare.links.http.credentials-test
  "Tests for net.ignorare.links.http.webauthn/CruxCredentials"
  (:require [clojure.test :refer [use-fixtures deftest is compose-fixtures]]
            [crux.api :as crux]
            [net.ignorare.links.db :as db]
            [net.ignorare.links.webauthn :as webauthn]
            [net.ignorare.links.models.users :as users]
            [net.ignorare.links.test :refer [ig-fixture *system*]])
  (:import (com.yubico.webauthn.data ByteArray)
           (java.util UUID Optional)))


(def alice-uuid #uuid "ac71fc2b-3e42-4eea-9cb2-cf8f62aff1f1")
(def bob-uuid #uuid "0b23e5b5-78e4-4c50-95ce-1553c013a6cd")
(def carol-uuid #uuid "aba84f0d-8746-45d8-a0aa-14194178eedb")

(def webauthn-1-id (ByteArray. (.getBytes "cred-1-id")))
(def webauthn-3-id (ByteArray. (.getBytes "cred-3-id")))
(def webauthn-4-id (ByteArray. (.getBytes "cred-4-id")))

(def fake-public-key (ByteArray. (.getBytes "public-key")))


(defn fixture-docs []
  (let [cred-1-id #uuid "810a8947-c93f-4d3b-8e8d-35a201d7a117"
        cred-2-id #uuid "084ce69a-ae0d-4507-8cc8-6dd0dc67b555"
        cred-3-id #uuid "25cc4d91-4b96-40b8-8939-8f4787df6803"
        cred-4-id #uuid "2cd7cb9d-8e93-43de-be9a-2fda3f4cab01"
        cred-5-id #uuid "6a30c8a2-e326-4a38-871e-12082a0134ca"
        cred-6-id #uuid "7177a125-dbfe-4af9-a07f-6f79b2c8fdba"]

    [{:crux.db/id alice-uuid
      :links.user/email "alice@example.com"
      :links.user/credentials #{cred-1-id cred-2-id}}

     {:crux.db/id bob-uuid
      :links.user/email "bob@example.com"
      :links.user/credentials #{cred-3-id cred-4-id cred-5-id}}

     {:crux.db/id carol-uuid
      :links.user/email "carol@example.com"
      :links.user/credentials #{cred-6-id}}

     {:crux.db/id cred-1-id
      :links.credential/mechanism :webauthn
      :links.credential.webauthn/id (.getBase64Url webauthn-1-id)
      :links.credential.webauthn/public-key (.getBase64Url fake-public-key)}

     {:crux.db/id cred-2-id}

     {:crux.db/id cred-3-id
      :links.credential/mechanism :webauthn
      :links.credential.webauthn/id (.getBase64Url webauthn-3-id)
      :links.credential.webauthn/public-key (.getBase64Url fake-public-key)
      :links.credential.webauthn/signature-count 10}

     {:crux.db/id cred-4-id
      :links.credential/mechanism :webauthn
      :links.credential.webauthn/id (.getBase64Url webauthn-4-id)
      :links.credential.webauthn/public-key (.getBase64Url fake-public-key)}

     {:crux.db/id cred-5-id}

     {:crux.db/id cred-6-id
      :links.credential/mechanism :webauthn
      :links.credential.webauthn/id (.getBase64Url webauthn-3-id)
      :links.credential.webauthn/public-key (.getBase64Url fake-public-key)}]))


(defn fixture-tx-ops []
  (mapv #(vector :crux.tx/put %) (fixture-docs)))


(defn load-data []
  (let [node (-> *system* :db/crux :node)]
    (when-some [{:crux.tx/keys [tx-time]} (crux/submit-tx node (fixture-tx-ops))]
      (crux/sync node tx-time nil))))


(defn with-data [f]
  (load-data)
  (f))


(use-fixtures :once (compose-fixtures (ig-fixture dissoc :http/server :http/sente)
                                      with-data))


(defn registered-credential
  [user-id ^ByteArray webauthn-id]
  (let [db (:db/crux *system*)]
    (when-some [credential-id (users/webauthn-credential-id-for-user db user-id (.getBase64Url webauthn-id))]
      (webauthn/registered-credential user-id (db/entity db credential-id)))))


(deftest get-credential-ids-for-username
  (let [credentials (webauthn/->CruxCredentials (-> *system* :db/crux :node))]
    (is (= #{(webauthn/public-key-credential-descriptor webauthn-1-id)}
           (.getCredentialIdsForUsername credentials "alice@example.com")))
    (is (= #{(webauthn/public-key-credential-descriptor webauthn-3-id)
             (webauthn/public-key-credential-descriptor webauthn-4-id)}
           (.getCredentialIdsForUsername credentials "bob@example.com")))
    (is (= #{(webauthn/public-key-credential-descriptor webauthn-3-id)}
           (.getCredentialIdsForUsername credentials "carol@example.com")))))


(deftest get-user-handle-for-username
  (let [credentials (webauthn/->CruxCredentials (-> *system* :db/crux :node))]
    (is (= (Optional/of (webauthn/uuid->ByteArray alice-uuid))
           (.getUserHandleForUsername credentials "alice@example.com")))
    (is (= (Optional/of (webauthn/uuid->ByteArray bob-uuid))
           (.getUserHandleForUsername credentials "bob@example.com")))
    (is (= (Optional/empty)
           (.getUserHandleForUsername credentials "bogus@example.com")))))


(deftest get-username-for-user-handle
  (let [credentials (webauthn/->CruxCredentials (-> *system* :db/crux :node))]
    (is (= (Optional/of "alice@example.com")
           (.getUsernameForUserHandle credentials (webauthn/uuid->ByteArray alice-uuid))))
    (is (= (Optional/of "bob@example.com")
           (.getUsernameForUserHandle credentials (webauthn/uuid->ByteArray bob-uuid))))
    (is (= (Optional/empty)
           (.getUsernameForUserHandle credentials (webauthn/uuid->ByteArray (UUID/randomUUID)))))))


(deftest lookup-credential
  (let [credentials (webauthn/->CruxCredentials (-> *system* :db/crux :node))
        alice-id (webauthn/uuid->ByteArray alice-uuid)
        bob-id (webauthn/uuid->ByteArray bob-uuid)]
    (is (= (Optional/of (registered-credential alice-uuid webauthn-1-id))
           (.lookup credentials webauthn-1-id alice-id)))
    (is (= (Optional/of (registered-credential bob-uuid webauthn-3-id))
           (.lookup credentials webauthn-3-id bob-id)))
    (is (= (Optional/empty)
           (.lookup credentials webauthn-1-id bob-id)))))


(deftest lookup-all-credentials
  (let [credentials (webauthn/->CruxCredentials (-> *system* :db/crux :node))]
    (is (= #{(registered-credential alice-uuid webauthn-1-id)}
           (.lookupAll credentials webauthn-1-id)))
    (is (= #{(registered-credential bob-uuid webauthn-3-id)
             (registered-credential carol-uuid webauthn-3-id)}
           (.lookupAll credentials webauthn-3-id)))
    (is (= #{}
           (.lookupAll credentials (ByteArray. (.getBytes "bogus-credential-id")))))))
