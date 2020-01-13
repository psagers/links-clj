(ns net.ignorare.links.state
  "re-state utilities."
  (:require [maximgb.re-state.core :as rs]
            [maximgb.re-state.utils :refer [cofx->interpreter]]))


(defn send-action
  "Returns an re-state action that sends an event to the current interpreter.

  This is useful for embedding inline actions in machine definitions."
  [event & args]
  (rs/fx-action
    (fn [cofx]
      (let [interp (cofx->interpreter cofx)]
        {::rs/re-state [:send! (into [interp event] args)]}))))
