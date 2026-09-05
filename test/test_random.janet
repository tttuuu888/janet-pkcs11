(use ../build/pkcs11)
(use ./helper)
(use spork/test)

(start-suite)

(def token-label (string "janet-pkcs11-test" ;(string/bytes (os/cryptorand 4))))

## Always delete the test token, even if a test raises an error.
(defer (assert (cleanup-token token-label))

  (with [p11 (assert (new hsm-so-path))]
    (def test-slot (init-test-token p11 token-label))

    ### Random number tests
    (with [session-rw (assert (:open-session p11 test-slot))]
      (assert (:login session-rw :user test-user-pin2))
      (assert (:seed-random session-rw (os/cryptorand 32)))
      (let [random1 (assert (:generate-random session-rw 32))
            random2 (assert (:generate-random session-rw 32))]
        (assert (not (= random1 random2)))))))

(end-suite)
