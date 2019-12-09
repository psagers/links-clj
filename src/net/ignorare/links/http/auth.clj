(ns net.ignorare.links.http.auth
  (:require [crux.api :as crux]
            [integrant.core :as ig]
            [ring.util.response :as res]
            [taoensso.timbre :as log])
  (:import (com.yubico.webauthn CredentialRepository RegisteredCredential RelyingParty)
           (com.yubico.webauthn.data ByteArray PublicKeyCredentialDescriptor RelyingPartyIdentity)
           (java.nio ByteBuffer)
           (java.util Optional UUID)))


(defn user-id-for-email
  "Returns the UUID (:crux.db/id) of the user with the given email, if any."
  [db email]
  (let [user-ids (->> (crux/q db
                         {:find '[?user-id]
                          :where '[[?user-id :links.user/email email]]
                          :args [{'email email}]})
                      (mapv first))]
    (when (> (count user-ids) 1)
      (log/error (str "Found " (count user-ids) " for " email)))

    (first user-ids)))


(defn uuid->ByteArray
  ^ByteArray [^UUID uuid]
  (when (some? uuid)
    (-> (ByteBuffer/allocate (* Long/BYTES 2))
        (.putLong (.getMostSignificantBits uuid))
        (.putLong (.getLeastSignificantBits uuid))
        (.array)
        (ByteArray.))))

(defn ByteArray->uuid
  ^UUID [^ByteArray ba]
  (when (some? ba)
    (let [long-buf (-> (.getBytes ba)
                       (ByteBuffer/wrap)
                       (.asLongBuffer))]
      (UUID. (.get long-buf) (.get long-buf)))))


(defn public-key-credential-descriptor
  ^PublicKeyCredentialDescriptor [^ByteArray credential-id]
  (-> (PublicKeyCredentialDescriptor/builder)
      (.id credential-id)
      (.build)))

(defn registered-credential
  ^RegisteredCredential [^ByteArray credential-id ^ByteArray user-handle ^ByteArray public-key]
  (-> (RegisteredCredential/builder)
      (.credentialId credential-id)
      (.userHandle user-handle)
      (.publicKeyCose public-key)
      (.build)))


(defrecord CruxCredentials [node]
  CredentialRepository
  (^java.util.Set getCredentialIdsForUsername [this ^String username]
    (->> (crux/q (crux/db node)
                 {:find '[?webauthn-id]
                  :where '[[?user-id :links.user/email email]
                           [?user-id :links.user/credentials ?credential-id]
                           [?credential-id :links.credential/mechanism :webauthn]
                           [?credential-id :links.credential.webauthn/id ?webauthn-id]]
                  :args [{'email username}]})
         (into #{}
               (comp (map first)
                     (map #(ByteArray/fromBase64Url %))
                     (map public-key-credential-descriptor)))))

  (^Optional getUserHandleForUsername [this ^String username]
    (-> (user-id-for-email (crux/db node) username)
        (uuid->ByteArray)
        (Optional/ofNullable)))

  (^Optional getUsernameForUserHandle [this ^ByteArray user-handle]
    (-> (crux/entity (crux/db node) (ByteArray->uuid user-handle))
        (:links.user/email)
        (Optional/ofNullable)))

  (^Optional lookup [this ^ByteArray credential-id ^ByteArray user-handle]
   (if-some [public-key (-> (crux/q (crux/db node)
                                    {:find '[?public-key]
                                     :where '[[user-id :links.user/credentials ?credential-id]
                                              [?credential-id :links.credential/mechanism :webauthn]
                                              [?credential-id :links.credential.webauthn/id webauthn-id]
                                              [?credential-id :links.credential.webauthn/public-key ?public-key]]
                                     :args [{'webauthn-id (.getBase64Url credential-id)
                                             'user-id (ByteArray->uuid user-handle)}]})
                            (ffirst))]
     (Optional/of (registered-credential credential-id
                                         user-handle
                                         (ByteArray/fromBase64Url public-key)))
     (Optional/empty)))

  (^java.util.Set lookupAll [this ^ByteArray credential-id]
    (->> (crux/q (crux/db node)
                 {:find '[?user-id ?public-key]
                   :where '[[?user-id :links.user/credentials ?credential-id]
                            [?credential-id :links.credential/mechanism :webauthn]
                            [?credential-id :links.credential.webauthn/id webauthn-id]
                            [?credential-id :links.credential.webauthn/public-key ?public-key]]
                   :args [{'webauthn-id (.getBase64Url credential-id)}]})
         (into #{}
               (map (fn [[user-id public-key]]
                      (registered-credential credential-id
                                             (uuid->ByteArray user-id)
                                             (ByteArray/fromBase64Url public-key))))))))


(defn relying-party [config crux]
  (-> (RelyingParty/builder)
      (.identity (-> (RelyingPartyIdentity/builder)
                     (.id (-> config :webauthn :rpid))
                     (.name "Links")
                     (.build)))
      (.credentialRepository (->CruxCredentials (:node crux)))
      (.build)))


(defmethod ig/init-key :http/webauthn [_ {:keys [config crux]}]
  {:rp (delay (relying-party config crux))
   :requests (atom {})})


(defn auth-handler
  [crux]
  (fn [_req]
    (res/status 405)))
