(ns net.ignorare.links.http.auth
  (:require [better-cond.core :as b]
            [cheshire.core :as json]
            [crux.api :as crux]
            [integrant.core :as ig]
            [net.ignorare.links.db :as db]
            [ring.util.response :as res]
            [taoensso.timbre :as log])
  (:import (com.yubico.webauthn CredentialRepository FinishAssertionOptions FinishRegistrationOptions RegisteredCredential RelyingParty StartAssertionOptions StartRegistrationOptions)
           (com.yubico.webauthn.data ByteArray PublicKeyCredential PublicKeyCredentialDescriptor RelyingPartyIdentity UserIdentity UserVerificationRequirement)
           (com.yubico.webauthn.exception RegistrationFailedException)
           (java.nio ByteBuffer)
           (java.util Optional UUID)))


;;
;; WebAuthn/Crux integration
;;

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


(defn user-for-email
  "Returns the user document matching the given email, if any."
  [db email]
  (let [user-id (user-id-for-email db email)]
    (crux/entity db user-id)))


(defn tx-add-credential
  "A transactor function for adding a new WebAuthn credential to a user."
  [user-id webauthn-id public-key db]
  (when-some [user (crux/entity db user-id)]
    (let [credential-id (UUID/randomUUID)]
      [[:crux.tx/cas user (update user :links.user/credentials (fnil conj #{}) credential-id)]
       [:crux.tx/put {:crux.db/id credential-id
                      :links.credential/mechanism :webauthn
                      :links.credential.webauthn/id webauthn-id
                      :links.credential.webauthn/public-key public-key}]])))


(defn tx-set-signature-count
  [user-id webauthn-id signature-count db]
  (let [query {:find '[?credential-id]
               :where '[[user-id :links.user/credentials ?credential-id]
                        [?credential-id :links.credential.webauthn/id webauthn-id]]
               :args [{'user-id user-id
                       'webauthn-id webauthn-id}]}]
    (when-some [credential-id (ffirst (crux/q db query))]
      (let [credential (crux/entity db credential-id)]
        [[:crux.tx/cas credential (assoc credential :links.credential.webauthn/signature-count signature-count)]]))))


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
  ^RegisteredCredential [^ByteArray webauthn-id ^ByteArray user-handle ^ByteArray public-key]
  (-> (RegisteredCredential/builder)
      (.credentialId webauthn-id)
      (.userHandle user-handle)
      (.publicKeyCose public-key)
      (.build)))


(defrecord CruxCredentials [node]
  ;; https://developers.yubico.com/java-webauthn-server/JavaDoc/webauthn-server-core/latest/com/yubico/webauthn/CredentialRepository.html
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

  (^Optional lookup [this ^ByteArray webauthn-id ^ByteArray user-handle]
    (if-some [public-key (-> (crux/q (crux/db node)
                                     {:find '[?public-key]
                                      :where '[[user-id :links.user/credentials ?credential-id]
                                               [?credential-id :links.credential/mechanism :webauthn]
                                               [?credential-id :links.credential.webauthn/id webauthn-id]
                                               [?credential-id :links.credential.webauthn/public-key ?public-key]]
                                      :args [{'webauthn-id (.getBase64Url webauthn-id)
                                              'user-id (ByteArray->uuid user-handle)}]})
                             (ffirst))]
      (Optional/of (registered-credential webauthn-id
                                          user-handle
                                          (ByteArray/fromBase64Url public-key)))
      (Optional/empty)))

  (^java.util.Set lookupAll [this ^ByteArray webauthn-id]
    (->> (crux/q (crux/db node)
                 {:find '[?user-id ?public-key]
                   :where '[[?user-id :links.user/credentials ?credential-id]
                            [?credential-id :links.credential/mechanism :webauthn]
                            [?credential-id :links.credential.webauthn/id webauthn-id]
                            [?credential-id :links.credential.webauthn/public-key ?public-key]]
                   :args [{'webauthn-id (.getBase64Url webauthn-id)}]})
         (into #{}
               (map (fn [[user-id public-key]]
                      (registered-credential webauthn-id
                                             (uuid->ByteArray user-id)
                                             (ByteArray/fromBase64Url public-key))))))))


;;
;; Component
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
  {:rp (delay (relying-party config crux))
   :requests (atom {})})


;;
;; WebAuthn API
;;

(defn- creation-request
  ^com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
  [^RelyingParty rp user]
  (let [email (:links.user/email user)
        options (-> (StartRegistrationOptions/builder)
                    (.user (-> (UserIdentity/builder)
                               (.name email)
                               (.displayName (or (:links.user/name user) email))
                               (.id (uuid->ByteArray (:crux.db/id user)))
                               (.build)))
                    (.build))]

    (.startRegistration rp options)))


(defn start-registration
  [{:keys [rp requests]} user]
  (when-some [request (creation-request @rp user)]
    (swap! requests assoc (:crux.db/id user) request)

    ;; A CredentialCreationOptions object with Base64Url encoding.
    ;; https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create
    (let [rp-identity (.getIdentity @rp)]
      {:publicKey {:rp {:name (.getName rp-identity)
                        :id (.getId rp-identity)}
                   :user {:id (-> request .getUser .getId .getBase64Url)
                          :name (-> request .getUser .getName)
                          :displayName (-> request .getUser .getDisplayName)}
                   :challenge (-> request .getChallenge .getBase64Url)
                   :pubKeyCredParams (vec (for [param (.getPubKeyCredParams request)]
                                            {:type (-> param .getType .toJsonString)
                                             :alg (-> param .getAlg .toJsonNumber)}))
                   :excludeCredentials (vec (for [desc (-> request .getExcludeCredentials (.orElse #{}))]
                                              {:type (-> desc .getType .toJsonString)
                                               :id (-> desc .getId .getBase64Url)}))}})))


(defn finish-registration
  [crux {:keys [rp requests]} user credential]
  (if-some [request (get @requests (:crux.db/id user))]
    (try
      (let [response (PublicKeyCredential/parseRegistrationResponseJson (json/generate-string credential))
            result (.finishRegistration @rp (-> (FinishRegistrationOptions/builder)
                                                (.request request)
                                                (.response response)
                                                (.build)))]

        (run! #(log/warn %) (.getWarnings result))

        ;; Registration was successful; store the new credential and clean up.
        (db/transact! crux (partial tx-add-credential
                                    (:crux.db/id user)
                                    (-> result .getKeyId .getId .getBase64Url)
                                    (-> result .getPublicKeyCose .getBase64Url)))

        (swap! requests dissoc (:crux.db/id user))

        result)

      (catch RegistrationFailedException e
        (log/error e)))
    (log/warn "No request for " (:crux.db/id user) " (" (:links.user/email user) ")")))


(defn assertion-request
  ^com.yubico.webauthn.AssertionRequest
  [^RelyingParty rp user]
  (let [email (:links.user/email user)
        options (-> (StartAssertionOptions/builder)
                    (.username email)
                    (.userVerification UserVerificationRequirement/PREFERRED)
                    (.build))]

    (.startAssertion rp options)))


(defn start-assertion
  [{:keys [rp requests]} user]
  (when-some [request (assertion-request @rp user)]
    (swap! requests assoc (:crux.db/id user) request)

    (let [options (.getPublicKeyCredentialRequestOptions request)
          allowed-credentials (.getAllowCredentials options)]
      {:publicKey (cond-> {:rpId (.getRpId options)
                           :challenge (-> options .getChallenge .getBase64Url)
                           :userVerification (-> options .getUserVerification .toJsonString)}

                    (.isPresent allowed-credentials)
                    (assoc :allowCredentials
                           (vec (for [desc (.get allowed-credentials)]
                                  (let [transports (-> desc .getTransports (.orElse nil))]
                                    (cond-> {:type (-> desc .getType .toJsonString)
                                             :id (-> desc .getId .getBase64Url)}
            
                                      (some? transports)
                                      (assoc :transports (mapv #(.toJsonString %) transports))))))))})))


(defn finish-assertion
  [crux {:keys [rp requests]} user credential]
  (if-some [request (get @requests (:crux.db/id user))]
    (try
      (let [response (PublicKeyCredential/parseAssertionResponseJson (json/generate-string credential))
            result (.finishAssertion @rp (-> (FinishAssertionOptions/builder)
                                             (.request request)
                                             (.response response)
                                             (.build)))]

        (run! #(log/warn %) (.getWarnings result))

        ;; Assertion was successful; update the credential and clean up.
        (db/transact! crux (partial tx-set-signature-count
                                    (-> result .getUserHandle ByteArray->uuid)
                                    (-> result .getCredentialId .getBase64Url)
                                    (-> result .getSignatureCount)))

        (swap! requests dissoc (:crux.db/id user))

        result)

      (catch RegistrationFailedException e
        (log/error e)))
    (log/warn "No request for " (:crux.db/id user) " (" (:links.user/email user) ")")))


;;
;; HTTP handler
;;

(defn credentials-for-user
  "Returns all credential documents for the user with the given email."
  [db user]
  (->> (crux/q db {:find '[?credential-id]
                   :where '[[user-id :links.user/credentials ?credential-id]]
                   :args [{'user-id (:crux.db/id user)}]})
       (keep (comp (partial crux/entity db) first))
       (vec)))


(defmulti auth-handler
  (fn [_crux _webauthn req]
    (:request-method req)))


(defmethod auth-handler :get
  [crux webauthn req]
  (b/cond
    :let [email (-> req :params :email not-empty)]

    (nil? email)
    (res/status 400)

    :let [db (-> crux :node crux/db)
          user (user-for-email db email)]

    (nil? user)
    (res/response {:email email})

    :let [credentials (not-empty (credentials-for-user db user))
          options (if credentials
                    (start-assertion webauthn user)
                    (start-registration webauthn user))]

    (res/response {:email email
                   :action (if credentials :authenticate :register)
                   :options options})))


(defmethod auth-handler :post
  [crux webauthn req]
  (b/cond
    :let [db (-> crux :node crux/db)
          {:keys [email action credential]} (:params req)
          user (user-for-email db email)]

    (= action :register)
    (if-some [_result (finish-registration crux webauthn user credential)]
      (res/status 200)
      (res/status 403))

    (= action :authenticate)
    (if-some [_result (finish-assertion crux webauthn user credential)]
      (res/status 200)
      (res/status 403))

    :else
    (do
      (log/warn "Unhandled auth action: " action)
      (res/status 400))))
    


(defmethod auth-handler :default
  [_crux _webauthn _req]
  (res/status 405))


(defn get-auth-handler
  [crux webauthn]
  (partial auth-handler crux webauthn))
