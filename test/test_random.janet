(use ../build/pkcs11)
(use ./helper)
(use spork/test)

(start-suite)

(def p11 (assert (new softhsm2-so-path)))
(def [test-slot token-label] (init-test-token p11))

### Random number tests
(with [session-rw (assert (:open-session p11 test-slot))]
  (assert (:login session-rw :user test-user-pin2))
  (assert (:seed-random session-rw (os/cryptorand 32)))
  (let [random1 (assert (:generate-random session-rw 32))
        random2 (assert (:generate-random session-rw 32))]
    (assert (not (= random1 random2)))))

(:close p11)
(assert (cleanup-token token-label))

(end-suite)
