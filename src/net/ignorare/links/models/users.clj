(ns net.ignorare.links.models.users
  (:require [clojure.spec.alpha :as s]
            [crux.api :as crux]
            [net.ignorare.links.db :as db]
            [taoensso.timbre :as log]))


(s/def ::user-id :crux.db/id)
(s/def :links.user/email string?)
(s/def :links.user/name string?)
(s/def :links.user/credentials (s/coll-of uuid?, :kind set?))
(s/def ::user (s/keys :req [:crux.db/id
                            :links.user/email]))

(s/def ::credential-id :crux.db/id)
(s/def :links.credential/description string?)

(s/def :links.credential.webauthn/id ::db/base64url)
(s/def :links.credential.webauthn/public-key ::db/base64url)
(s/def :links.credential.webauthn/signature-count int?)

(s/def :links.credential.device/key string?)

(s/def ::webauthn-credential (s/keys :req [:crux.db/id
                                           :links.credential/description
                                           :links.credential.webauthn/id
                                           :links.credential.webauthn/public-key]))

(s/def ::device-credential (s/keys :req [:crux.db/id
                                         :links.credential/description
                                         :links.credential.device/key]))


;;
;; Query wrappers
;;

(defn user-id-for-email
  "Returns the UUID (:crux.db/id) of the user with the given email, if any."
  [db email]
  (let [user-ids (->> (db/q db
                            {:find '[?user-id]
                             :where '[[?user-id :links.user/email email]]
                             :args [{'email email}]})
                      (mapv first))]

    (when (> (count user-ids) 1)
      (log/error (str "Found " (count user-ids) " for " email)))

    (first user-ids)))

(s/fdef user-id-for-email
  :args (s/cat :db ::db/datasource
               :email :links.user/email)
  :ret (s/nilable uuid?))


(defn user-for-email
  "Returns the user entity matching the given email, if any."
  [db email]
  (let [db (db/to-db db)]
    (->> (user-id-for-email db email)
         (crux/entity db))))

(s/fdef user-for-email
  :args (s/cat :db ::db/datasource
               :email :links.user/email)
  :ret (s/nilable map?))


(defn lookup-webauthn-id
  "Returns the credential-id for an existing WebAuthn credential, if any."
  [db webauthn-id]
  (let [credential-ids (->> (crux/q (db/to-db db)
                                    {:find '[?credential-id]
                                     :where '[[?credential-id :links.credential.webauthn/id webauthn-id]]
                                     :args [{'webauthn-id webauthn-id}]})
                            (into #{} (map first)))]
    (when (> (count credential-ids) 1)
      (log/error (str "Found " (count credential-ids) " for webauthn-id " webauthn-id)))

    (first credential-ids)))

(s/fdef lookup-webauthn-id
  :args (s/cat :db ::db/datasource
               :email :links.credential.webauthn/id)
  :ret (s/nilable uuid?))


(defn webauthn-credential-id-for-user
  [db user-id webauthn-id]
  (-> (db/q db {:find '[?credential-id]
                :where '[[user-id :links.user/credentials ?credential-id]
                         [?credential-id :links.credential.webauthn/id webauthn-id]]
                :args [{'webauthn-id webauthn-id
                        'user-id user-id}]})
      (ffirst)))


(defn lookup-device-key
  [db device-key]
  (-> (db/q db {:find '[?device-id]
                :where '[[?device-id :links.device/key device-key]]
                :args [{'device-key device-key}]})
      (ffirst)))


;;
;; Simple transformations
;;

(defn conj-credential-id
  [user credential-id]
  (update user :links.user/credentials (fnil conj #{}) credential-id))

(s/fdef conj-credential-id
  :args (s/cat :user ::user
               :credential-id uuid?)
  :ret ::user)


;;
;; Transactor functions
;;

(defn tx-remove-all-credentials
  [user-id]
  (fn tx-remove-all-credentials-inner [db]
    (when-some [user (crux/entity db user-id)]
      [[:crux.tx/cas user (dissoc user :links.user/credentials)]])))

(s/fdef tx-remove-all-credentials
  :args (s/cat :user-id uuid?)
  :ret ::db/tx-fn)
