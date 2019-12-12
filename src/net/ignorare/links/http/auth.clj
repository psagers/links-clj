(ns net.ignorare.links.http.auth
  (:require [better-cond.core :as b]
            [cheshire.core :as json]
            [clojure.spec.alpha :as s]
            [net.ignorare.links.db :as db]
            [net.ignorare.links.models.users :as users]
            [net.ignorare.links.webauthn :as webauthn]
            [ring.util.response :as res]
            [taoensso.timbre :as log]))


(defn user-has-webauthn-credentials?
  "Truthy if a user has any WebAuthn credential entities."
  [db user-id]
  (let [query {:find '[?credential-id]
               :where '[[user-id :links.user/credentials ?credential-id]
                        [?credential-id :links.credential.webauthn/id _]]
               :args [{'user-id user-id}]}]
    (-> (db/q db query) seq boolean)))

(s/fdef user-has-webauthn-credentials?
  :args (s/cat :db ::db/datasource
               :user-id ::db/uuid)
  :ret boolean?)


(defmulti auth-handler
  (fn [_crux _webauthn req]
    (:request-method req)))


(defmethod auth-handler :get
  [crux webauthn req]
  (b/cond
    :let [email (-> req :params :email not-empty)]

    (nil? email)
    (res/status 400)

    :let [user (users/user-for-email crux email)]

    (nil? user)
    (res/status 404)

    :let [is-registered? (user-has-webauthn-credentials? crux (:crux.db/id user))
          options (if is-registered?
                    (webauthn/start-assertion webauthn user)
                    (webauthn/start-registration webauthn user))]

    (res/response {:email email
                   :action (if is-registered? :authenticate :register)
                   :options options})))


(defmethod auth-handler :post
  [crux webauthn req]
  (b/cond
    :let [{:keys [email action credential]} (:params req)
          user (users/user-for-email crux email)
          responseJson (json/generate-string credential)]

    (= action :register)
    (if-some [_result (webauthn/finish-registration webauthn user responseJson)]
      (do
        (log/info "Successful registration for" (:links.user/email user))
        (res/status 200))
      (res/status 403))

    (= action :authenticate)
    (if-some [_result (webauthn/finish-assertion webauthn user responseJson)]
      (do
        (log/info "Successful authentication for" (:links.user/email user))
        (res/status 200))
      (res/status 403))

    :else
    (do
      (log/warn "Unhandled auth action: " action)
      (res/status 400))))


(defmethod auth-handler :delete
  [crux webauthn req]
  (b/cond
    :let [email (-> req :params :email not-empty)]

    (nil? email)
    (res/status 400)

    :let [user (users/user-for-email crux email)]

    (nil? user)
    (res/status 404)

    :do (webauthn/cancel-ceremony webauthn (:crux.db/id user))

    (res/status 200)))


(defmethod auth-handler :default
  [_crux _webauthn _req]
  (res/status 405))


(defn get-auth-handler
  [crux webauthn]
  (partial auth-handler crux webauthn))
