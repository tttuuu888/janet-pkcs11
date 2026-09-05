(use ../build/pkcs11)
(use ./helper)
(use spork/test)

(start-suite)

(def test-env (setup-test-env))
(def token-label (string "janet-pkcs11-test" ;(string/bytes (os/cryptorand 4))))

## Always delete the test token and the test environment, even if a test
## raises an error.
(defer (do (assert (cleanup-token token-label))
           (assert (cleanup-test-env test-env)))

  (with [p11 (assert (new hsm-so-path))]
    (def test-slot (init-test-token p11 token-label))

    ### Dual-purpose cryptographic tests
    (with [session-rw (assert (:open-session p11 test-slot))]
      (assert (:login session-rw :user test-user-pin2))

      (let [priv-tpl {:CKA_CLASS    :CKO_SECRET_KEY
                      :CKA_KEY_TYPE :CKK_AES
                      :CKA_VALUE_LEN 32
                      :CKA_TOKEN     true}
            priv-key (:generate-key session-rw {:mechanism :CKM_AES_KEY_GEN} priv-tpl)]
        (assert (:digest-init session-rw {:mechanism :CKM_SHA256}))

        ## SoftHSM2 does not implement the dual-function operations.
        (assert (= :CKR_FUNCTION_NOT_SUPPORTED
                   (try (:digest-encrypt-update session-rw "abcd") ([e] e))))
        (assert (= :CKR_FUNCTION_NOT_SUPPORTED
                   (try (:decrypt-digest-update session-rw "abcd") ([e] e))))
        (assert (= :CKR_FUNCTION_NOT_SUPPORTED
                   (try (:sign-encrypt-update session-rw "abcd") ([e] e))))
        (assert (= :CKR_FUNCTION_NOT_SUPPORTED
                   (try (:decrypt-verify-update session-rw "abcd") ([e] e))))))))

(end-suite)
