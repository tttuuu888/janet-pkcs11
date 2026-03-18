(use ../build/pkcs11)
(import spork/sh)

(def softhsm2-so-path "/usr/lib/softhsm/libsofthsm2.so")
(def test-so-pin  "012345")
(def test-so-pin2 "abcdef")
(def test-user-pin  "123456")
(def test-user-pin2 "bcdefg")

(defn find-slot-with-serial-number [p11 serial-number]
  (find
   (fn [s] (= ((:get-token-info p11 s) :serial-number)
              serial-number))
   (:get-slot-list p11)))

(defn init-test-token [p11]
  "Initialize a test token with user PIN set up. Returns [slot token-label]."
  (def token-label (string "janet-pkcs11-test"
                           ;(string/bytes (os/cryptorand 4))))
  (def slot (min ;(:get-slot-list p11)))
  (:init-token p11 slot test-so-pin token-label)
  (def serial-number ((:get-token-info p11 slot) :serial-number))
  (with [session (:open-session p11 slot)]
    (:login session :so test-so-pin)
    (:init-pin session test-user-pin)
    (:logout session)
    (:set-pin session test-user-pin test-user-pin2))
  [(find-slot-with-serial-number p11 serial-number) token-label])

(defn cleanup-token [token-label]
  (sh/exec "softhsm2-util" "--delete-token" "--token" token-label))
