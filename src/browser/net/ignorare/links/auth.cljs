(ns net.ignorare.links.auth
  (:require ["base64url" :as b64]
            [ajax.core :as ajax]
            [com.rpl.specter :refer [multi-transform multi-path terminal ALL]]
            [fork.core :as fork]
            [goog.dom.dataset :as dataset]
            [re-frame.core :as rf]
            [taoensso.encore :refer [map-keys]]
            [vlad.core :as v]))


(def auth-states
  {:connecting {::sente-connected :connected
                ::sente-unauthorized :auth-device}
   :unauthenticated {::authenticated :connecting}
   :connected {::disconnected :connecting}})



(rf/reg-event-db
 ::set-email
 (fn [db [_ email]]
   (assoc db ::email email)))


(defn create-credential-options
  "Converts server data to a CredentialCreationOptions object.

  The server returns a CLJ data structure that mimics the required JS object as
  much as possible. Some values need to be decoded from Base64Url to binary
  buffers."
  [options]
  (let [options' (multi-transform (multi-path [:user :id (terminal b64/toBuffer)]
                                              [:challenge (terminal b64/toBuffer)]
                                              [:excludeCredentials ALL :id (terminal b64/toBuffer)])
                                  options)]
    #js {:publicKey (clj->js options')}))


(defn get-credential-options
  [options]
  (let [options' (multi-transform (multi-path [:challenge (terminal b64/toBuffer)]
                                              [:allowCredentials ALL :id (terminal b64/toBuffer)])
                                  options)]
    #js {:publicKey (clj->js options')}))


(rf/reg-fx
 ::create-credential
 (fn [options]
   (-> (js/navigator.credentials.create options)
       (.then #(rf/dispatch [::new-credential-info %]))
       (.catch js/console.error))))


(rf/reg-fx
 ::get-credential
 (fn [options]
   (-> (js/navigator.credentials.get options)
       (.then #(rf/dispatch [::existing-credential-info %]))
       (.catch js/console.error))))


(rf/reg-event-fx
 ::handle-auth
 (fn [_ [_ response]]
   (case (:action response)
     :register {::create-credential (create-credential-options (:options response))}
     :authenticate {::get-credential (get-credential-options (:options response))}
     {})))


(rf/reg-event-db
 ::auth-successful
 (fn [db _]
   (assoc db ::authenticated? true)))

(rf/reg-event-db
 ::auth-failed
 (fn [db _]
   (assoc db ::authenticated? false)))


(rf/reg-event-fx
 ::new-credential-info
 (fn [{:keys [db]} [_ ^js info]]
   (let [csrf-token (dataset/get js/document.body "csrfToken")
         response (.-response info)
         params {:email (::email db)
                 :action :register
                 :credential {:type (.-type info)
                              :id (.-id info)
                              :response {:clientDataJSON (-> response .-clientDataJSON b64/encode)
                                         :attestationObject (-> response .-attestationObject b64/encode)}
                              :clientExtensionResults (.getClientExtensionResults info)}}]

     {:http-xhrio {:method :post
                   :uri "/auth"
                   :headers {:x-csrf-token csrf-token}
                   :params params
                   :format (ajax/transit-request-format)
                   :response-format (ajax/transit-response-format)
                   :on-success [::auth-successful]
                   :on-failure [::auth-failed]}})))


(rf/reg-event-fx
 ::existing-credential-info
 (fn [{:keys [db]} [_ ^js info]]
   (let [csrf-token (dataset/get js/document.body "csrfToken")
         response (.-response info)
         params {:email (::email db)
                 :action :authenticate
                 :credential {:type (.-type info)
                              :id (.-id info)
                              :response {:clientDataJSON (-> response .-clientDataJSON b64/encode)
                                         :authenticatorData (-> response .-authenticatorData b64/encode)
                                         :signature (-> response .-signature b64/encode)
                                         :userHandle (some-> response .-userHandle b64/encode)}
                              :clientExtensionResults (.getClientExtensionResults info)}}]

     {:http-xhrio {:method :post
                   :uri "/auth"
                   :headers {:x-csrf-token csrf-token}
                   :params params
                   :format (ajax/transit-request-format)
                   :response-format (ajax/transit-response-format)
                   :on-success [::auth-successful]
                   :on-failure [::auth-failed]}})))


(rf/reg-event-fx
 ::auth-api-error
 (fn [_ [_ error]]
   (js/console.error error)
   {}))


(rf/reg-event-fx
 ::submit-email
 [(fork/on-submit ::login-form)]
 (fn [{:keys [db]} _]
   {:db (dissoc db ::authenticated?)
    :http-xhrio {:method :get
                 :uri "/auth"
                 :params {:email (::email db)}
                 :response-format (ajax/transit-response-format)
                 :on-success [::handle-auth]
                 :on-failure [::auth-api-error]}}))


(rf/reg-sub
 ::email
 (fn [db _]
   (::email db)))

(rf/reg-sub
 ::authenticated?
 (fn [db _]
   (::authenticated? db)))


;;
;; Login form
;;

(def login-form-validation
  (v/join
   (v/attr ["email"] (v/present))))

(defn flatten-keys [m]
  (map-keys first m))

(defn validate-login-form
  [values]
  (-> (v/validate login-form-validation values)
      (v/guess-field-names)
      (v/translate-errors v/english-translation)
      (flatten-keys)))


(defn highlight-class
  [{:keys [touched errors]} fname]
  (when (contains? touched fname)
    (if (contains? errors fname)
      "is-danger"
      "is-success")))

(defn help-tag
  ([form fname]
   (help-tag form fname nil))

  ([{:keys [touched errors]} fname default]
   (cond
     (and (contains? touched fname) (contains? errors fname))
     (into [:div] (for [error (get errors fname)]
                    [:p.help.is-danger error]))

     default
     [:p.help default])))


(defn email-input
  [{:keys [values handle-change handle-blur disabled?] :as form}]
  (let [fname "email"]
    [:div.field
     [:label.label "Email"]
     [:div.control
      [:input.input {:name fname
                     :type "text"
                     :class [(highlight-class form fname)]
                     :disabled (get disabled? fname false)
                     :placeholder "alice@example.com"
                     :value (get values fname)
                     :on-change handle-change
                     :on-blur handle-blur}]]
     (help-tag form fname "Enter a registered email address.")]))

(defn remember-checkbox
  [{:keys [values handle-change handle-blur disabled?]}]
  (let [fname "register"]
    [:label.checkbox
     [:input {:type "checkbox"
              :name fname
              :checked (get values fname false)
              :disabled (get disabled? fname false)
              :on-change handle-change
              :on-blur handle-blur}]
     " Remember this browser"]))

(defn submit-button
  [{:keys [submitting?]}]
  [:div.level
   [:div.level-left]
   [:div.level-right
    [:div.level-item
     [:button.button {:type "submit"
                      :disabled submitting?}
      "Next"]]]])

(defn login-form
  [{:keys [form-id handle-submit] :as form}]
  [:form {:id form-id, :on-submit handle-submit}
   (email-input form)
   (remember-checkbox form)
   (submit-button form)])


(defn login-view []
  [:div.container
   [:div.columns
    [:div.column]
    [:div.column
     [fork/form {:path ::login-form
                 :form-id "login-form"
                 :validation validate-login-form
                 :prevent-default? true
                 :clean-on-unmount? true
                 :on-submit #(rf/dispatch [::submit-email %])}
      login-form]]
    [:div.column]]])
