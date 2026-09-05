(use ../build/pkcs11)
(import spork/sh)

(def hsm-so-path "/usr/lib/softhsm/libsofthsm2.so")

(def test-so-pin  "012345")
(def test-so-pin2 "abcdef")
(def test-user-pin  "123456")
(def test-user-pin2 "bcdefg")

(def CKF_TOKEN_INITIALIZED 0x400)

(defn find-uninitialized-slot
  "Return the first slot whose token is not initialized. Errors if none."
  [p11]
  (or (find (fn [s] (zero? (bit-and ((:get-token-info p11 s) :flags)
                                    CKF_TOKEN_INITIALIZED)))
            (:get-slot-list p11))
      (error "no uninitialized slot")))

(defn find-slot-with-serial-number [p11 serial-number]
  (find
   (fn [s] (= ((:get-token-info p11 s) :serial-number)
              serial-number))
   (:get-slot-list p11)))

(defn init-test-token
  "Initialize a test token labeled `token-label` with user PIN set up.
  Returns its slot."
  [p11 token-label]
  (def slot (find-uninitialized-slot p11))
  (:init-token p11 slot test-so-pin token-label)
  (def serial-number ((:get-token-info p11 slot) :serial-number))
  (with [session (:open-session p11 slot)]
    (:login session :so test-so-pin)
    (:init-pin session test-user-pin)
    (:logout session)
    (:set-pin session test-user-pin test-user-pin2))
  (find-slot-with-serial-number p11 serial-number))

(defn cleanup-token
  "Delete the test token. Returns true on success."
  [token-label]
  (zero? (sh/exec "softhsm2-util" "--delete-token" "--token" token-label)))

## Test environment for SoftHSM2 . With another PKCS#11 module these two
## may do nothing.

(defn setup-test-env
  "Create a throwaway SoftHSM store and point SOFTHSM2_CONF at it.
  Returns the store directory."
  []
  (def dir (string (or (os/getenv "TMPDIR") "/tmp") "/janet-pkcs11-test-"
                   ;(string/bytes (os/cryptorand 4))))
  (os/mkdir dir)
  (os/mkdir (string dir "/tokens"))
  (spit (string dir "/softhsm2.conf")
        (string "directories.tokendir = " dir "/tokens\n"))
  (os/setenv "SOFTHSM2_CONF" (string dir "/softhsm2.conf"))
  dir)

(defn cleanup-test-env
  "Remove the store created by setup-test-env. Returns true on success."
  [dir]
  (sh/rm dir)
  (nil? (os/stat dir)))
