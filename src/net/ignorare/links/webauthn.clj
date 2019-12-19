(ns net.ignorare.links.webauthn
  "A WebAuthn implementation that integrates with our Crux database.

  WebAuthn ceremonies are stateful, so this includes an Integrant component to
  hold requests while we're waiting for the client to sign our challenges. The
  top-level APIs take a reference to the initialized component as their first
  arguments.

  The underlying implementation is provided by a Java library from Yubico:
  https://github.com/Yubico/java-webauthn-server.

  ## Conventions

  - Our database identifies users by UUID (:crux.db/id) and email
    (:links.user/email). We use the UUID as the user handle and the email as the
    username.

  - credential-id refers to the :crux.db/id of a credential entity. webauthn-id
    refers to a credential identifier per the WebAuthn standard.

  - We handle all binary data encoded with base64-url (or, in the case of user
    handles, native UUIDs). Data is converted to and from ByteArray objects at
    the Java API boundary.

  "
  (:require [clojure.spec.alpha :as s]
            [crux.api :as crux]
            [integrant.core :as ig]
            [net.ignorare.links.db :as db]
            [net.ignorare.links.models.users :as users]
            [taoensso.timbre :as log])
  (:import (com.yubico.webauthn AssertionRequest CredentialRepository FinishAssertionOptions FinishRegistrationOptions RegisteredCredential RelyingParty StartAssertionOptions StartRegistrationOptions)
           (com.yubico.webauthn.data ByteArray PublicKeyCredential PublicKeyCredentialCreationOptions PublicKeyCredentialDescriptor RelyingPartyIdentity UserIdentity)
           (com.yubico.webauthn.exception AssertionFailedException RegistrationFailedException)
           (java.nio ByteBuffer)
           (java.util Optional UUID)))


(s/def ::ceremony-id string?)


(def random (delay (java.security.SecureRandom.)))

(defn new-ceremony-id []
  (let [buf (byte-array 20)]
    (.nextBytes @random buf)
    (.toBase64Url (ByteArray. buf))))

(s/fdef new-ceremony-id
  :args (s/cat)
  :ret ::ceremony-id)


;;
;; WebAuthn/Crux integration
;;

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
  ^PublicKeyCredentialDescriptor [^ByteArray webauthn-id]
  (-> (PublicKeyCredentialDescriptor/builder)
      (.id webauthn-id)
      (.build)))


(defn registered-credential
  "Builds a RegisteredCredential out of a user-id and a credential entity."
  ^RegisteredCredential [user-id credential]
  (let [{:links.credential.webauthn/keys [id public-key signature-count]} credential]
    (cond-> (RegisteredCredential/builder)
      :mandatory (.credentialId (ByteArray/fromBase64Url id))
      :mandatory (.userHandle (uuid->ByteArray user-id))
      :mandatory (.publicKeyCose (ByteArray/fromBase64Url public-key))
      (some? signature-count) (.signatureCount signature-count)
      :finally (.build))))

(s/fdef registered-credential
  :args (s/cat :user-id uuid?
               :credential ::users/webauthn-credential)
  :ret #(instance? RegisteredCredential %))


(defn webauthn-ids-for-email
  "Finds all WebAuthn credential IDs for the user with the given email."
  [db email]
  (let [query {:find '[?webauthn-id]
               :where '[[?user-id :links.user/email email]
                        [?user-id :links.user/credentials ?credential-id]
                        [?credential-id :links.credential.webauthn/id ?webauthn-id]]
               :args [{'email email}]}]

    (db/q db query (map first))))

(s/fdef webauthn-ids-for-email
  :args (s/cat :db ::db/datasource
               :email :links.user/email)
  :ret (s/coll-of :links.credential.webauthn/id, :kind set?))


(defn public-key-for-webauthn-id
  "Looks up the public key for a webauthn-id. The user-id is a sanity check."
  [db webauthn-id user-id]
  (-> (db/q db {:find '[?public-key]
                :where '[[user-id :links.user/credentials ?credential-id]
                         [?credential-id :links.credential.webauthn/id webauthn-id]
                         [?credential-id :links.credential.webauthn/public-key ?public-key]]
                :args [{'webauthn-id webauthn-id
                        'user-id user-id}]})
      (ffirst)))

(s/fdef public-key-for-webauthn-id
  :args (s/cat :db ::db/datasource
               :webauthn-id :links.credential.webauthn/id
               :user-id uuid?)
  :ret (s/nilable :links.credential.webauthn/public-key))


(defrecord CruxCredentials [node]
  ;; https://developers.yubico.com/java-webauthn-server/JavaDoc/webauthn-server-core/latest/com/yubico/webauthn/CredentialRepository.html
  CredentialRepository
  (^java.util.Set getCredentialIdsForUsername [this ^String username]
    (->> (webauthn-ids-for-email node username)
         (into #{} (comp (map #(ByteArray/fromBase64Url %))
                         (map public-key-credential-descriptor)))))

  (^Optional getUserHandleForUsername [this ^String username]
    (-> (users/user-id-for-email node username)
        (uuid->ByteArray)
        (Optional/ofNullable)))

  (^Optional getUsernameForUserHandle [this ^ByteArray user-handle]
    (-> (db/entity node (ByteArray->uuid user-handle))
        (:links.user/email)
        (Optional/ofNullable)))

  (^Optional lookup [this ^ByteArray webauthn-id ^ByteArray user-handle]
    (let [webauthn-id (.getBase64Url webauthn-id)
          user-id (ByteArray->uuid user-handle)]
      (if-some [credential-id (users/webauthn-credential-id-for-user node user-id webauthn-id)]
        (Optional/of (registered-credential user-id (db/entity node credential-id)))
        (Optional/empty))))

  (^java.util.Set lookupAll [this ^ByteArray webauthn-id]
    (->> (crux/q (crux/db node)
                 {:find '[?user-id ?credential-id]
                   :where '[[?user-id :links.user/credentials ?credential-id]
                            [?credential-id :links.credential.webauthn/id webauthn-id]]
                   :args [{'webauthn-id (.getBase64Url webauthn-id)}]})
         (into #{}
               (map (fn [[user-id credential-id]]
                      (registered-credential user-id (db/entity node credential-id))))))))


;;
;; Transactor functions
;;

(defn tx-add-webauthn-credential
  "Returns a transactor function for adding a new WebAuthn credential to a
  user."
  [user-id webauthn-id public-key]
  (fn tx-add-webauthn-credential-inner [db]
    (when-some [user (crux/entity db user-id)]
      (if-some [credential-id (users/lookup-webauthn-id db webauthn-id)]
        ;; Attach an existing credential entity to the user.
        (do
          (log/debug "Attaching existing credential" credential-id "to user" user-id "(" (:links.user/email user) ")")
          [[:crux.tx/cas user (users/conj-credential-id user credential-id)]])

        ;; Create a new credential entity and attach it to the user.
        (let [credential-id (UUID/randomUUID)]
          (log/debug "Adding new credential" credential-id "to user" user-id "(" (:links.user/email user) ")")
          [[:crux.tx/cas user (users/conj-credential-id user credential-id)]
           [:crux.tx/put {:crux.db/id credential-id
                          :links.credential/description "WebAuthn"
                          :links.credential.webauthn/id webauthn-id
                          :links.credential.webauthn/public-key public-key}]])))))

(s/fdef tx-add-webauthn-credential
  :args (s/cat :user-id uuid?
               :webauthn-id :links.credential.webauthn/id
               :public-key :links.credential.webauthn/public-key)
  :ret ::db/tx-fn)


(defn tx-set-webauthn-signature-count
  "Returns a transactor function to update the signature count on an existing
  credential entity."
  [user-id webauthn-id signature-count]
  (fn tx-set-webauthn-signature-count-inner [db]
    (let [query {:find '[?credential-id]
                 :where '[[user-id :links.user/credentials ?credential-id]
                          [?credential-id :links.credential.webauthn/id webauthn-id]]
                 :args [{'user-id user-id
                         'webauthn-id webauthn-id}]}]
      (when-some [credential-id (ffirst (crux/q db query))]
        (let [credential (crux/entity db credential-id)]
          (log/debug "Setting credential" credential-id "signature count to" signature-count)
          [[:crux.tx/cas credential (assoc credential :links.credential.webauthn/signature-count signature-count)]])))))

(s/fdef tx-set-webauthn-signature-count
  :args (s/cat :user-id uuid?
               :webauthn-id :links.credential.webauthn/id
               :signature-count :links.credential.webauthn/signature-count)
  :ret ::db/tx-fn)


;;
;; Registration (aka creation)
;;

(defn- creation-request
  ^PublicKeyCredentialCreationOptions [^RelyingParty rp user]
  (let [email (:links.user/email user)
        options (-> (StartRegistrationOptions/builder)
                    (.user (-> (UserIdentity/builder)
                               (.name email)
                               (.displayName (or (:links.user/name user) email))
                               (.id (uuid->ByteArray (:crux.db/id user)))
                               (.build)))
                    (.build))]

    (.startRegistration rp options)))


(defn- encoded-registration-options
  [^PublicKeyCredentialCreationOptions request]
  (let [rp-identity (.getRp request)
        user-identity (.getUser request)]
    {:rp {:name (.getName rp-identity)
          :id (.getId rp-identity)}
     :user {:id (-> user-identity .getId .getBase64Url)
            :name (.getName user-identity)
            :displayName (.getDisplayName user-identity)}
     :challenge (-> request .getChallenge .getBase64Url)
     :pubKeyCredParams (vec (for [param (.getPubKeyCredParams request)]
                               {:type (-> param .getType .toJsonString)
                                :alg (-> param .getAlg .toJsonNumber)}))
     :excludeCredentials (vec (for [desc (-> request .getExcludeCredentials (.orElse #{}))]
                                 {:type (-> desc .getType .toJsonString)
                                  :id (-> desc .getId .getBase64Url)}))}))


(defn start-registration
  "Begins the registration ceremony.

  Returns a PublicKeyCredentialCreationOptions structure with BufferSource
  values encoded as base64-url.

  https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialCreationOptions
  "
  [{:keys [rp requests]} user]
  (when-some [request (creation-request rp user)]
    (let [ceremony-id (new-ceremony-id)]
      (swap! requests assoc ceremony-id request)
      [ceremony-id (encoded-registration-options request)])))

(s/fdef start-registration
  :args (s/cat :webauthn ::webauthn
               :user ::users/user)
  :ret (s/nilable (s/tuple ::ceremony-id map?)))


(defn finish-registration
  "Completes the registration ceremony.

  responseJson is documented at:
  https://developers.yubico.com/java-webauthn-server/JavaDoc/webauthn-server-core/latest/com/yubico/webauthn/data/PublicKeyCredential.html#parseRegistrationResponseJson(java.lang.String)

  If successful, returns the user-id and credential-id of the new credential.
  "
  [{:keys [rp requests crux]} ceremony-id responseJson]
  (when-some [request (get @requests ceremony-id)]
    (try
      (let [response (PublicKeyCredential/parseRegistrationResponseJson responseJson)
            result (.finishRegistration rp (-> (FinishRegistrationOptions/builder)
                                               (.request request)
                                               (.response response)
                                               (.build)))
            user-id (-> request .getUser .getId ByteArray->uuid)
            webauthn-id (-> result .getKeyId .getId .getBase64Url)
            public-key (-> result .getPublicKeyCose .getBase64Url)]

        (run! #(log/warn %) (.getWarnings result))

        ;; Registration was successful; store the new credential and clean up.
        (db/transact! crux
                      (tx-add-webauthn-credential user-id webauthn-id public-key)
                      :sync? true)
        (swap! requests dissoc ceremony-id)

        [user-id, (users/lookup-webauthn-id crux webauthn-id)])

      (catch RegistrationFailedException e
        (log/error e)))))

(s/fdef finish-registration
  :args (s/cat :webauthn ::webauthn
               :ceremony-id ::ceremony-id
               :responseJson string?)
  :ret (s/nilable (s/tuple ::users/user-id ::users/credential-id)))


;;
;; Authentication (aka assertion)
;;

(defn- assertion-request
  ^AssertionRequest [^RelyingParty rp username]
  (let [options (cond-> (StartAssertionOptions/builder)
                        (some? username) (.username username)
                        :finally (.build))]
    (.startAssertion rp options)))


(defn- encoded-assertion-options
  "Encodes an AssertionRequest into a serializable data structure.

  This is what we pass back up to the client for the credentials API.
  "
  [^AssertionRequest request]
  (let [options (.getPublicKeyCredentialRequestOptions request)
        allowed-credentials (.getAllowCredentials options)]
    (cond-> {:rpId (.getRpId options)
             :challenge (-> options .getChallenge .getBase64Url)
             :userVerification (-> options .getUserVerification .toJsonString)}

      (.isPresent allowed-credentials)
      (assoc :allowCredentials
             (vec (for [desc (.get allowed-credentials)]
                    (let [transports (-> desc .getTransports (.orElse nil))]
                      (cond-> {:type (-> desc .getType .toJsonString)
                               :id (-> desc .getId .getBase64Url)}

                        (some? transports)
                        (assoc :transports (mapv #(.toJsonString %) transports))))))))))


(s/fdef encoded-assertion-options
  :args (s/cat :request #(instance? AssertionRequest %))
  :ret map?)


(defn start-assertion
  "Begins the assertion ceremony.

  Returns a 2-tuple: a UUID to identify the request and a map to return to the
  client for signing. The map is a PublicKeyCredentialRequestOptions structure
  with binary data base64-url-encoded.

  https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredentialRequestOptions
  "
  [{:keys [rp requests]} username]
  (when-some [request (assertion-request rp username)]
    (let [ceremony-id (new-ceremony-id)]
      (swap! requests assoc ceremony-id request)
      [ceremony-id (encoded-assertion-options request)])))

(s/fdef start-assertion
  :args (s/cat :webauthn ::webauthn
               :username (s/nilable string?))
  :ret (s/nilable (s/tuple ::ceremony-id map?)))


(defn finish-assertion
  "Completes the assertion ceremony.

  responseJson is documented at:
  https://developers.yubico.com/java-webauthn-server/JavaDoc/webauthn-server-core/latest/com/yubico/webauthn/data/PublicKeyCredential.html#parseAssertionResponseJson(java.lang.String)

  If successful, returns the credential-id used.
  "
  [{:keys [rp requests crux]} ceremony-id responseJson]
  (if-some [request (get @requests ceremony-id)]
    (try
      (let [response (PublicKeyCredential/parseAssertionResponseJson responseJson)
            result (.finishAssertion rp (-> (FinishAssertionOptions/builder)
                                            (.request request)
                                            (.response response)
                                            (.build)))
            user-id (-> result .getUserHandle ByteArray->uuid)
            webauthn-id (-> result .getCredentialId .getBase64Url)
            signature-count (.getSignatureCount result)]

        (run! #(log/warn %) (.getWarnings result))

        (when (.isSuccess result)
          (db/transact! crux (tx-set-webauthn-signature-count user-id webauthn-id signature-count))
          (swap! requests dissoc ceremony-id)

          [user-id, (users/lookup-webauthn-id crux webauthn-id)]))

      (catch AssertionFailedException e
        (log/error e)))))

(s/fdef finish-assertion
  :args (s/cat :webauthn ::webauthn
               :ceremony-id ::ceremony-id
               :responseJson string?)
  :ret (s/nilable (s/tuple ::users/user-id ::users/credential-id)))


;;
;; Misc
;;

(defn cancel-ceremony
  "Cancels an outstanding registration or assertion ceremony."
  [{:keys [requests]} ceremony-id]
  (swap! requests dissoc ceremony-id)
  nil)

(s/fdef cancel-ceremony
  :args (s/cat :webauthn ::webauthn
               :ceremony-id ::ceremony-id))


;;
;; Integrant
;;

(defn relying-party [config crux]
  (-> (RelyingParty/builder)
      (.identity (-> (RelyingPartyIdentity/builder)
                     (.id (-> config :webauthn :rpid))
                     (.name "Links")
                     (.build)))
      (.credentialRepository (->CruxCredentials (:node crux)))
      (.build)))


(defmethod ig/init-key :http/webauthn [_ {:keys [config crux]}]
  {:rp (relying-party config crux)
   :requests (atom {})
   :crux crux})


;; A spec for our Integrant component.
(s/def ::rp #(instance? RelyingParty %))
(s/def ::requests #(instance? clojure.lang.Atom %))
(s/def ::crux ::db/crux)

(s/def ::webauthn (s/keys :req-un [::rp ::requests ::crux]))
