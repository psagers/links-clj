(ns net.ignorare.links
  (:require [clojure.java.io :as io]
            [cli-matic.core :as cli]
            [integrant.core :as ig]
            [net.ignorare.links.db]
            [net.ignorare.links.http]
            [net.ignorare.links.sente]
            [net.ignorare.links.sys]
            [net.ignorare.links.webauthn])
  (:gen-class))


(defn ig-config
  [profile]
  (let [config (slurp (io/resource "links/system.edn"))]
    (-> (ig/read-string config)
        (assoc-in [:sys/config :profile] profile))))


;;
;; System
;;

(defonce system (atom nil))

(defn init-system!
  [profile keys]
  (let [sys (ig/init (ig-config profile) keys)]
    (reset! system sys)))

(defn shutdown! []
  (when @system
    (ig/halt! @system)
    (reset! system nil)))


;;
;; CLI
;;

(defn read-input
  "Reads one non-empty string from the console."
  [prompt]
  (loop []
    (if-some [value (-> (System/console)
                        (.readLine prompt (object-array 0))
                        (not-empty))]
      value
      (recur))))

(defn read-password
  "Reads one non-empty password from the console."
  [prompt]
  (loop []
    (if-some [value (-> (System/console)
                        (.readPassword prompt (object-array 0))
                        (String.)
                        (not-empty))]
      value
      (recur))))


;;
;; Server
;;

(defn- sleep-forever []
  (Thread/sleep 100000)
  (recur))

(defn run-server! [{:keys [profile]}]
  (init-system! profile #{:http/server})

  ;; Without this, cli-matic will call System/exit.
  (sleep-forever))


;;
;; User management
;;

(defn add-user!
  [{:keys [email name password]}]
  (let [email (or email (read-input "Enter the user's email address: "))
        name (or name (read-input "Enter the user's name: "))
        password1 (or password (read-password "Enter the user's password: "))
        password2 (or password (read-password "Confirm the user's password: "))]
    (if (= password1 password2)
      (println "Ready to create user" email)
      (println "Passwords don't match."))))


(defn passwd!
  [{:keys [email password]}]
  (let [password1 (or password (read-password "Enter the user's password: "))
        password2 (or password (read-password "Confirm the user's password: "))]
    (if (= password1 password2)
      (println "Ready to update user" email)
      (println "Passwords don't match."))))


;;
;; Entry
;;

(def cli-config
  {:app {:command "links"
         :description "Links page."}

   :global-opts [{:option "profile"
                  :short "p"
                  :type #{:default :dev :test}
                  :default :default}]

   :commands [{:command "serve"
               :description "Runs the HTTP service."
               :runs run-server!
               :on-shutdown shutdown!}

              {:command "add-user"
               :description "Adds a new user to the system. Will prompt for missing information."
               :opts [{:option "email", :short "e", :type :string}
                      {:option "name", :short "n", :type :string}
                      {:option "password", :short "p", :type :string}]
               :runs add-user!}

              {:command "passwd"
               :description "Resets a user's password. Will prompt for the password if it's not given."
               :opts [{:option "email", :short 0, :type :string, :default :present}
                      {:option "password", :short "p", :type :string}]
               :runs passwd!}]})


(defn -main [& args]
  (cli/run-cmd args cli-config))
