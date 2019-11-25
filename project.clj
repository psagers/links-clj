(defproject net.ignorare/links "0.1.0-SNAPSHOT"
  :url "https://links.ignorare.net/"

  :dependencies [[org.clojure/clojure "1.10.1"]
                 [com.yubico/webauthn-server-core "1.5.0"]
                 [http-kit "2.3.0"]]

  :source-paths ["src/shared", "src/server"]
  :resource-paths ["src/server/resources"]
  :target-path "build/%s/"

  :main ^:skip-aot net.ignorare.links

  :profiles {:uberjar {:aot :all}})
