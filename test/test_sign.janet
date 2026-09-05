(use ../build/pkcs11)
(use ./helper)
(use spork/test)

(start-suite)

(def token-label (string "janet-pkcs11-test" ;(string/bytes (os/cryptorand 4))))

## Always delete the test token, even if a test raises an error.
(defer (assert (cleanup-token token-label))

  (with [p11 (assert (new hsm-so-path))]
    (def test-slot (init-test-token p11 token-label))

    ### Sign and verify tests
    (with [session-rw (assert (:open-session p11 test-slot))]
      (assert (:login session-rw :user test-user-pin2))

      (let [pub-tpl {:CKA_VERIFY          true
                     :CKA_MODULUS_BITS    768
                     :CKA_PUBLIC_EXPONENT (buffer/from-bytes 0x01 0x00 0x01)}
            priv-tpl {:CKA_TOKEN     true
                      :CKA_PRIVATE   true
                      :CKA_SENSITIVE true
                      :CKA_SIGN      true}
            (pub-key priv-key) (:generate-key-pair session-rw
                                                   {:mechanism :CKM_RSA_PKCS_KEY_PAIR_GEN}
                                                   pub-tpl
                                                   priv-tpl)
            data  (:generate-random session-rw 16)]

        ## sign
        (assert (:sign-init session-rw {:mechanism :CKM_RSA_PKCS} priv-key))
        (def sig (assert (:sign session-rw data)))

        ## verify
        (assert (:verify-init session-rw {:mechanism :CKM_RSA_PKCS} pub-key))
        (assert (= true (:verify session-rw data sig)))

        ## NOTE: Some mechanisms (e.g., CKM_RSA_PKCS, CKM_RSA_X_509,
        ## CKM_RSA_PKCS_PSS, CKM_ECDSA, CKM_DSA) only support C_Sign after
        ## C_SignInit, not C_SignUpdate, and same for verification.

        ## sign-init, update with CKM_RSA_PKCS
        (assert (:sign-init session-rw {:mechanism :CKM_RSA_PKCS} priv-key))
        (assert-error "sign-update is not supported" (:sign-update session-rw data))

        ## verify-init, update with CKM_RSA_PKCS
        (assert (:verify-init session-rw {:mechanism :CKM_RSA_PKCS} pub-key))
        (assert-error "verify-update is not supported" (:verify-update session-rw data)))

      (let [tpl {:CKA_CLASS     :CKO_SECRET_KEY
                 :CKA_KEY_TYPE  :CKK_GENERIC_SECRET
                 :CKA_VALUE_LEN 32
                 :CKA_SIGN      true
                 :CKA_VERIFY    true}
            key (:generate-key session-rw
                               {:mechanism :CKM_GENERIC_SECRET_KEY_GEN}
                               tpl)
            data (:generate-random session-rw 16)]

        ## sign-init,update,final
        (assert (:sign-init session-rw {:mechanism :CKM_SHA256_HMAC} key))
        (assert (:sign-update session-rw data))
        (assert (:sign-update session-rw data))
        (assert (:sign-update session-rw data))
        (def sig (assert (:sign-final session-rw)))

        ## verify-init,update,final
        (assert (:verify-init session-rw {:mechanism :CKM_SHA256_HMAC} key))
        (assert (:verify-update session-rw data))
        (assert (:verify-update session-rw data))
        (assert (:verify-update session-rw data))
        (assert (= true (assert (:verify-final session-rw sig)))))

      ## sign-recover, verify-recover
      (let [pub-tpl {:CKA_ENCRYPT true
                     :CKA_VERIFY true
                     :CKA_MODULUS_BITS 2048
                     :CKA_PUBLIC_EXPONENT (buffer/from-bytes 0x01 0x00 0x01)}
            priv-tpl {:CKA_TOKEN true
                      :CKA_PRIVATE true
                      :CKA_SENSITIVE true
                      :CKA_DECRYPT true
                      :CKA_SIGN true
                      :CKA_EXTRACTABLE false}
            (pubk privk) (:generate-key-pair session-rw
                                             {:mechanism :CKM_RSA_PKCS_KEY_PAIR_GEN}
                                             pub-tpl
                                             priv-tpl)
            data (:generate-random session-rw 16)]

        (assert-error "Softhsm2 does not support C_SignRecoverInit at the moment"
                      (:sign-recover-init session-rw {:mechanism :CKM_RSA_9796} privk))

        (assert-error "Softhsm2 does not support C_SignRecover at the moment"
                      (:sign-recover session-rw data))

        (assert-error "Softhsm2 does not support C_VerifyecoverInit at the moment"
                      (:verify-recover-init session-rw {:mechanism :CKM_RSA_9796} privk))

        (assert-error "Softhsm2 does not support C_Verifyecover at the moment"
                      (:verify-recover session-rw data ""))))))

(end-suite)
