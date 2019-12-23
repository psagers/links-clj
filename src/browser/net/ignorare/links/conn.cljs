(ns net.ignorare.links.conn
  "Manages our sente connection to the server."
  (:require [ajax.core :as ajax]
            [clojure.core.async :as async :refer [go-loop <!]]
            [goog.dom.dataset :as dataset]
            [maximgb.re-state.core :as rs]
            [net.ignorare.links.db :as db]
            [re-frame.core :as rf]
            [reagent.core :as r]
            [taoensso.sente :as sente]))


;; Nested states that define the non-interactive connection process. Assuming a
;; connection is established, this will eventually propagate a :connected event.
;; Sente retries indefinitely on error, so there is no failure result.
(def connecting-states
  {;; Wait for the first handshake and see if we have a user ID.
   :init {:on {:handshake [{:cond ::handshake-anonymous?
                            :target :authenticating}
                           {:target :done}]}}

   ;; If we don't already have a session, see if we can start a new one with a
   ;; stored device key.
   :authenticating {:entry ::send-device-key
                    :on {;; We have no device key.
                         :auth-missing :done
                         ;; We got an HTTP error trying to authenticate.
                         :auth-error :done
                         ;; The device key was rejected.
                         :auth-fail {:actions [::reset-client]
                                     :target :done}
                         ;; Authentication successful.
                         :auth-success {:target :connect}}}

   ;; Try to connect one more time. Success or fail, the result will get kicked
   ;; up to the parent.
   :connect {:entry ::reconnect
             :on {:handshake :done}}

   ;; We may or may not be authenticated, but either way we've done all we can.
   ;; Kick it back up.
   :done {:entry {:type ::interpreter-send!
                  :event :connected}}})


;; Represents the state of our sente connection.
(rs/def-machine connection
  {:id ::connection
   :initial :connecting

   :states {;; Trying to get an authenticated connection.
            :connecting {:initial :init
                         :states connecting-states
                         :on {:connected [{:cond ::authenticated?
                                           :target :ready}
                                          {:target :unauthenticated}]}}

            ;; We have a connection, but no user ID. Someone needs to
            ;; authenticate and then reconnect.
            :unauthenticated {:on {:reconnect {:actions [::reconnect]
                                               :target :connecting}}}

            ;; We are connected and authenticated.
            :ready {:on {:reconnect {:actions [::reconnect]
                                     :target :connecting}}}}})


;;
;; Initialization
;;

(defn- -load-csrf-token []
  (dataset/get js/document.body "csrfToken"))

(rf/reg-cofx
 ::csrf-token
 (fn [cofx _]
   (assoc cofx ::csrf-token (-load-csrf-token))))

(rf/reg-fx
 ::make-channel-socket
 (fn [csrf-token]
   (let [sente (sente/make-channel-socket! "/chsk" csrf-token {:type :ws})]
     (rf/dispatch [::set-sente sente]))))

(rf/reg-fx
 ::interpreter-start
 (fn [interpreter]
   (rs/interpreter-start! interpreter)))

(db/reg-event-fx
 ::init
 [(rf/inject-cofx ::csrf-token)]
 (fn [{:keys [db] :as cofx} _]
   (let [interpreter (rs/interpreter! connection)]
     {:db (assoc db ::interpreter interpreter)
      ::interpreter-start interpreter
      ::make-channel-socket (::csrf-token cofx)})))


;;
;; re-state helpers
;;

;; For dispatching state machine events.
(db/reg-event-fx
 ::interpreter-send!
 (fn [{:keys [db]} [_ event & args]]
   (let [interp (::interpreter db)]
     {::rs/re-state [:send! (into [interp event] args)]})))

;; For sending state machine events from the state definitions.
(rs/def-action-fx
  connection
  ::interpreter-send!
  (fn [{:keys [db]} _ & {:keys [event args]}]
    (let [interp (::interpreter db)]
      {::rs/re-state [:send! (into [interp event] args)]})))


;;
;; Sente
;;

(rf/reg-fx
 ::init-sente-router
 (fn [{:keys [ch-recv]}]
   (go-loop [msg (<! ch-recv)]
     (when msg
       (rf/dispatch [::client-msg msg])
       (recur (<! ch-recv))))))

(rf/reg-fx
 ::reconnect
 (fn [{:keys [chsk] :as _sente}]
   (when (some? chsk)
     (sente/chsk-reconnect! chsk))))

(rf/reg-fx
 ::disconnect
 (fn [{:keys [chsk] :as _sente}]
   (when (some? chsk)
     (sente/chsk-disconnect! chsk))))


(db/reg-event-fx
 ::set-sente
 (fn [{:keys [db]} [_ sente]]
   (let [old-sente (::sente sente)]
     (cond-> {:db (assoc db ::sente sente)
              ::init-sente-router sente}
       (some? old-sente) (assoc ::disconnect old-sente)))))


;; Expects a :handshake event and checks to see if it has a user.
(rs/def-guard-ev
  connection
  ::handshake-anonymous?
  (fn [_event [user-id]]
    (= user-id ::sente/nil-uid)))


;;
;; Authentication
;;

(rf/reg-cofx
 ::device-key
 (fn [cofx]
   (let [device-key (js/localStorage.getItem "device-key")]
     (assoc cofx ::device-key device-key))))

(rs/def-guard-db
  connection
  ::authenticated?
  (fn [db]
    (some? (::user-id db))))

(rs/def-action-fx
  connection
  ::send-device-key
  [(rf/inject-cofx ::device-key)]
  (fn [cofx]
    (if-some [device-key (::device-key cofx)]
      {:http-xhrio {:method :post
                    :uri "/auth/device"
                    :params {:device-key device-key}
                    :format (ajax/transit-request-format)
                    :response-format (ajax/transit-response-format)
                    :on-success [::device-auth-result]
                    :on-failure [::device-auth-result]}}
      {:dispatch [::interpreter-send! :auth-missing]})))

(db/reg-event-fx
 ::device-auth-result
 (fn [_cofx [_ result]]
   (let [status (:status result)
         event (cond
                 (<= -1 status 0) :auth-error
                 (= status 200) :auth-success
                 (= status 401) :auth-fail
                 :else (do (js/console.error "Unexpected /auth/device status:" status)
                           :auth-error))]
     {:dispatch [::interpreter-send! event]})))


;;
;; Sente event dispatch
;;

(defmulti client-msg :id)

(defmethod client-msg :default
  [msg]
  (js/console.debug "Ignoring %s" (:event msg)))


(db/reg-event-fx
 ::client-msg
 (fn [_cofx [_ msg]]
   {::client-msg msg}))

(rf/reg-fx
 ::client-msg
 (fn [msg]
   (client-msg msg)))


(defmethod client-msg :chsk/handshake
  [msg]
  (rf/dispatch [::handshake (:?data msg)]))

;; We've received a :chsk/handshake event. The parameter is the event data.
(db/reg-event-fx
 ::handshake
 (fn [{:keys [db]} [_ [user-id :as data]]]
   {:db (assoc db ::user-id (when-not (= user-id ::sente/nil-uid) user-id))
    :dispatch [::interpreter-send! :handshake data]}))


;;
;; View
;;

;; The singleton connection interpreter.
(rf/reg-sub
 ::interpreter
 (fn [db _]
   (::interpreter db)))

(defn render-state
  [state]
  (cond
    (keyword? state) (str state)
    (string? state) (keyword state)
    (map? state) (let [[k v] (first state)]
                   (str (render-state k) " > " (render-state v)))
    :else state))

(defn status-view []
  (r/with-let [interpreter (rf/subscribe [::interpreter])]
    (r/with-let [state (rs/isubscribe-state @interpreter)]
      [:div.container
       [:div.columns
        [:div.column]
        [:div.column
         [:div.box
          [:div.content
           [:b "State: "] (render-state @state)]]]
        [:div.column]]])))
