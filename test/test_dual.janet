(use ../build/pkcs11)
(use ./helper)
(use spork/test)

(start-suite)

(def token-label (string "janet-pkcs11-test" ;(string/bytes (os/cryptorand 4))))

## Always delete the test token, even if a test raises an error.
(defer (assert (cleanup-token token-label))

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

        (assert-error "Softhsm2 does not support C_DigestEncryptUpdate at the moment"
                      (:digest-encrypt-update session-rw "abcd"))

        (assert-error "Softhsm2 does not support C_DecryptDigestUpdate at the moment"
                      (:decrypt-digest-update session-rw "abcd"))

        (assert-error "Softhsm2 does not support C_SignEncryptUpdate at the moment"
                      (:sign-encrypt-update session-rw "abcd"))

        (assert-error "Softhsm2 does not support C_DecryptVerifyUpdate at the moment"
                      (:decrypt-verify-update session-rw "abcd"))))))

(end-suite)
