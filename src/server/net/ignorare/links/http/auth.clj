(ns net.ignorare.links.http.auth
  (:require [cheshire.core :as json]
            [net.ignorare.links.db :as db]
            [net.ignorare.links.models.users :as users]
            [net.ignorare.links.webauthn :as webauthn]
            [ring.util.response :as res]))


(def conj-set (fnil conj #{}))


(defn login-session
  "Returns a new session map with the given user logged in."
  [session user-id credential-id]
  (if (= (:uid session) user-id)
    (-> session
        (assoc :uid user-id)
        (update session :net.ignorare.links.http/credentials conj-set credential-id))
    (assoc session
           :uid user-id
           :net.ignorare.links.http/credentials #{credential-id})))


;;
;; Registration
;;

(defmulti webauthn-register-handler :request-method)


(defmethod webauthn-register-handler :get
  [{:net.ignorare.links.http/keys [crux webauthn] :as req}]
  (let [email (-> req :params :email not-empty)
        user (when email (users/user-for-email crux email))]
    (if user
      (let [[ceremony-id options] (webauthn/start-registration webauthn user)]
        (res/response {:ceremony-id ceremony-id
                       :options options}))
      (res/status 400))))


(defmethod webauthn-register-handler :post
  [{:net.ignorare.links.http/keys [webauthn] :as req}]
  (let [{:keys [ceremony-id response]} (:params req)
        responseJson (json/generate-string response)]
    (if-some [[user-id credential-id] (webauthn/finish-registration webauthn ceremony-id responseJson)]
      (-> (res/status 200)
          (assoc :session (login-session (:session req) user-id credential-id)))
      (res/status 403))))


(defmethod webauthn-register-handler :delete
  [{:net.ignorare.links.http/keys [webauthn] :as req}]
  (if-some [ceremony-id (-> req :params :ceremony-id not-empty)]
    (do
      (webauthn/cancel-ceremony webauthn ceremony-id)
      (res/status 200))
    (res/status 404)))


(defmethod webauthn-register-handler :default
  [_req]
  (res/status 405))


;;
;; Authentication
;;

(defmulti webauthn-login-handler :request-method)


(defmethod webauthn-login-handler :get
  [{:net.ignorare.links.http/keys [webauthn] :as req}]
  (let [email (-> req :params :email not-empty)
        [ceremony-id options] (webauthn/start-assertion webauthn email)]
    (res/response {:ceremony-id ceremony-id
                   :options options})))


(defmethod webauthn-login-handler :post
  [{:net.ignorare.links.http/keys [webauthn] :as req}]
  (let [{:keys [ceremony-id response]} (:params req)
        responseJson (json/generate-string response)]
    (if-some [[user-id credential-id] (webauthn/finish-assertion webauthn ceremony-id responseJson)]
      (-> (res/status 200)
          (assoc :session (login-session (:session req) user-id credential-id)))
      (res/status 403))))


(defmethod webauthn-login-handler :delete
  [{:net.ignorare.links.http/keys [webauthn] :as req}]
  (if-some [ceremony-id (-> req :params :ceremony-id not-empty)]
    (do
      (webauthn/cancel-ceremony webauthn ceremony-id)
      (res/status 200))
    (res/status 404)))


(defmethod webauthn-login-handler :default
  [_req]
  (res/status 405))


;;
;; Device auth
;;

(defmulti device-handler :request-method)


(defmethod device-handler :post
  [{:net.ignorare.links.http/keys [crux] :as req}]
  (let [device-key (-> req :param :device-key)
        query {:find '[?user-id ?credential-id]
               :where '[[?user-id :links.user/credentials ?credential-id]
                        [?credential-id :links.credential.device/key device-key]]
               :args [{'device-key device-key}]}]
    (if-some [[user-id credential-id] (first (db/q crux query))]
      (-> (res/status 200)
          (assoc :session (login-session (:session req) user-id credential-id)))
      (res/status 401))))


(defmethod device-handler :default
  [_req]
  (res/status 405))


;;
;; Logout
;;

(defmulti logout-handler :request-method)


(defmethod logout-handler :post
  [_req]
  (-> (res/status 200)
      (assoc :session nil)))


(defmethod logout-handler :default
  [_req]
  (res/status 405))
