(ns net.ignorare.links.ui.auth
  (:require ["base64url" :as b64]
            [ajax.core :as ajax]
            [com.rpl.specter :refer [multi-transform multi-path terminal ALL]]
            [goog.dom.dataset :as dataset]
            [re-frame.core :as rf]
            [reagent.core :as r]))


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
    (clj->js {:publicKey options'})))


(defn get-credential-options
  [options]
  (let [options' (multi-transform (multi-path [:challenge (terminal b64/toBuffer)]
                                              [:allowCredentials ALL :id (terminal b64/toBuffer)])
                                  options)]
    (clj->js {:publicKey options'})))


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


(defn login-view []
  (r/with-let [email (rf/subscribe [::email])
               authenticated? (rf/subscribe [::authenticated?])]
    [:div.container
     [:div.columns
      [:div.column]
      [:div.column
       [:div.field
        [:label.label "Email"]
        [:div.control
         [:input.input {:type "text"
                        :placeholder "alice@example.com"
                        :class [(case @authenticated?, true "is-success", false "is-danger", nil)]
                        :value @email
                        :on-change #(rf/dispatch [::set-email (-> % .-target .-value)])}]]
        [:p.help {:class [(case @authenticated?, true "is-success", false "is-danger", nil)]}
         (case @authenticated?
           true "Authentication successful."
           false "Authentication failed."
           "Enter a registered email address.")]]
       [:div.level
        [:div.level-left]
        [:div.level-right
         [:div.level-item
          [:button.button {:disabled (empty? @email)
                           :on-click #(rf/dispatch [::submit-email])}
           "Next"]]]]]
      [:div.column]]]))
