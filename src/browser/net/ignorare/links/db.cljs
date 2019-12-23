(ns net.ignorare.links.db
  (:require [re-frame.core :as rf]
            [clojure.spec.alpha :as s]))


(def ^boolean debug? goog/DEBUG)


;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; re-frame
;;
;; Provider state lives under a namespaced keyword to avoid collisions with
;; other components (such as the editor). All events must be registered with the
;; wrappers below.
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defn ^:private validate
  "Validates a database value against the spec and logs the error, if any. This
  can be used on its own or with the rf/after interceptor."
  ([db]
   (validate db nil))
  ([db event]
   (when-not (s/valid? (s/keys) db)
     (js/console.error "Database failed validation after %s: %s"
                       (pr-str event)
                       (s/explain-str ::db db)))))

(def ^:private std-interceptors-db
  [(when debug? rf/debug)
   (when debug? (rf/after validate))])

(def ^:private std-interceptors-fx
  [(when debug? rf/debug)
   (when debug? (rf/after (fn [db event] (when (some? db) (validate db event)))))])


(defn reg-event-db
  "Wraps re-frame.core/reg-event-db with standard interceptors."
  ([id handler]
   (rf/reg-event-db id std-interceptors-db handler))
  ([id interceptors handler]
   (rf/reg-event-db id [std-interceptors-db interceptors] handler)))

(defn reg-event-fx
  "Wraps re-frame.core/reg-event-fx with standard interceptors."
  ([id handler]
   (rf/reg-event-fx id std-interceptors-fx handler))
  ([id interceptors handler]
   (rf/reg-event-fx id [std-interceptors-fx interceptors] handler)))
