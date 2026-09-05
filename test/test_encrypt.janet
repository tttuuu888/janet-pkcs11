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

    ### Encrypt, decrypt tests
    (with [session-rw (assert (:open-session p11 test-slot))]
      (assert (:login session-rw :user test-user-pin2))

      ## encrypt-init,encrypt - decrypt-init,decrypt
      (let [key (:generate-key session-rw
                               {:mechanism     :CKM_AES_KEY_GEN}
                               {:CKA_CLASS     :CKO_SECRET_KEY
                                :CKA_KEY_TYPE  :CKK_AES
                                :CKA_VALUE_LEN 32
                                :CKA_TOKEN     true
                                :CKA_PRIVATE   true
                                :CKA_ENCRYPT   true
                                :CKA_DECRYPT   true
                                :CKA_SENSITIVE true})
            plain (hex-decode "000102030405060708090a0b0c0d0e0f")]

        ## encrypt
        (assert (:encrypt-init session-rw {:mechanism :CKM_AES_ECB} key))
        (def encrypted (assert (:encrypt session-rw plain)))

        ## decrypt
        (assert (:decrypt-init session-rw {:mechanism :CKM_AES_ECB} key))
        (def decrypted (assert (:decrypt session-rw encrypted)))

        ## check result
        (assert (= plain decrypted)))

      ## encrypt-init,update,final - decrypt-init,update,final
      (let [iv     (:generate-random session-rw 16)
            plain1 (:generate-random session-rw 16)
            plain2 (:generate-random session-rw 16)
            plain3 (:generate-random session-rw 16)
            key (:generate-key session-rw
                               {:mechanism     :CKM_AES_KEY_GEN}
                               {:CKA_CLASS     :CKO_SECRET_KEY
                                :CKA_KEY_TYPE  :CKK_AES
                                :CKA_VALUE_LEN 32
                                :CKA_TOKEN     true
                                :CKA_PRIVATE   true
                                :CKA_ENCRYPT   true
                                :CKA_DECRYPT   true
                                :CKA_SENSITIVE true})]

        ## encrypt
        (assert (:encrypt-init session-rw
                               {:mechanism :CKM_AES_CBC
                                :parameter iv}
                               key))
        (def enc1 (assert (:encrypt-update session-rw plain1)))
        (def enc2 (assert (:encrypt-update session-rw plain2)))
        (def enc3 (assert (:encrypt-update session-rw plain3)))
        (assert (:encrypt-final session-rw))

        ## decrypt
        (assert (:decrypt-init session-rw
                               {:mechanism :CKM_AES_CBC
                                :parameter iv}
                               key))
        (def dec1 (assert (:decrypt-update session-rw enc1)))
        (def dec2 (assert (:decrypt-update session-rw enc2)))
        (def dec3 (assert (:decrypt-update session-rw enc3)))
        (assert (:decrypt-final session-rw))

        ## check result
        (assert (= plain1 dec1))
        (assert (= plain2 dec2))
        (assert (= plain3 dec3))))))

(end-suite)
