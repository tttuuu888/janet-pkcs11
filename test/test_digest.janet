(use ../build/pkcs11)
(use ./helper)
(use spork/test)

(start-suite)

(def token-label (string "janet-pkcs11-test" ;(string/bytes (os/cryptorand 4))))

## Always delete the test token, even if a test raises an error.
(defer (assert (cleanup-token token-label))

  (with [p11 (assert (new hsm-so-path))]
    (def test-slot (init-test-token p11 token-label))

    ### Digest tests
    (with [session-rw (assert (:open-session p11 test-slot))]
      (assert (:login session-rw :user test-user-pin2))

      (let [priv-tpl {:CKA_CLASS    :CKO_SECRET_KEY
                      :CKA_KEY_TYPE :CKK_AES
                      :CKA_VALUE_LEN 32
                      :CKA_TOKEN     true}
            priv-key (:generate-key session-rw {:mechanism :CKM_AES_KEY_GEN} priv-tpl)]

        ## plain text digest
        (assert (:digest-init session-rw {:mechanism :CKM_SHA256}))
        (assert (= (:digest session-rw "abcd")
                   (hex-decode "88D4266FD4E6338D13B845FCF289579D209C897823B9217DA3E161936F031589")))

        ## hex text digest
        (assert (:digest-init session-rw {:mechanism :CKM_SHA256}))
        (assert (= (:digest session-rw (hex-decode "01020304"))
                   (hex-decode "9F64A747E1B97F131FABB6B447296C9B6F0201E79FB3C5356E6C77E89B6A806A")))

        ## digest-init,update,final
        (assert (:digest-init session-rw {:mechanism :CKM_SHA256}))
        (assert (:digest-update session-rw (hex-decode "01020304")))
        (assert (:digest-update session-rw (hex-decode "05060708")))
        (assert (= (:digest-final session-rw)
                   (hex-decode "66840DDA154E8A113C31DD0AD32F7F3A366A80E8136979D8F5A101D3D29D6F72")))

        ## digest-init,key,final
        (assert (:digest-init session-rw {:mechanism :CKM_SHA256}))
        (assert (:digest-key session-rw priv-key))
        (assert (:digest-final session-rw))))))

(end-suite)
