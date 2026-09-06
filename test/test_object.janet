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

    ### Objects, attribute tests
    (with [session-rw (assert (:open-session p11 test-slot))]
      (assert (:login session-rw :user test-user-pin2))

      ## The template is a struct. PKCS11 attribute defines can be used here, but
      ## only in Janet keyword format.
      (let [obj-handle1 (assert (:create-object session-rw
                                                {:CKA_CLASS       :CKO_DATA
                                                 :CKA_TOKEN       true
                                                 :CKA_APPLICATION "My Application"
                                                 :CKA_VALUE       ""}))
            obj-handle2 (assert (:copy-object session-rw
                                              obj-handle1
                                              {:CKA_LABEL "copy object"}))]
        (assert (:get-object-size session-rw obj-handle1))

        (let [attr (assert (:get-attribute-value session-rw
                                                 obj-handle1
                                                 [:CKA_TOKEN
                                                  :CKA_CLASS
                                                  :CKA_VALUE
                                                  :CKA_APPLICATION]))]
          (assert (= 0 (attr :CKA_CLASS)))
          (assert (= true (attr :CKA_TOKEN)))
          (assert (= "My Application" (attr :CKA_APPLICATION)))
          (assert (= "" (attr :CKA_VALUE))))

        ## A sensitive attribute mixed with readable ones must not fail the
        ## whole read: the readable ones come back, the sensitive one is omitted.
        (let [key (assert (:generate-key session-rw {:mechanism :CKM_AES_KEY_GEN}
                                         {:CKA_CLASS :CKO_SECRET_KEY
                                          :CKA_KEY_TYPE :CKK_AES
                                          :CKA_VALUE_LEN 32
                                          :CKA_TOKEN true
                                          :CKA_SENSITIVE true
                                          :CKA_EXTRACTABLE false}))
              attr (assert (:get-attribute-value session-rw key
                                                 [:CKA_KEY_TYPE :CKA_VALUE]))]
          ## :CKA_KEY_TYPE comes back (CKK_AES = 0x1f), :CKA_VALUE is omitted.
          (assert (= 0x1f (attr :CKA_KEY_TYPE)))
          (assert (nil? (attr :CKA_VALUE)))
          (:destroy-object session-rw key))

        ## A nested template attribute (an array of CK_ATTRIBUTE) is written
        ## from a nested struct and read back into a nested struct.
        (let [key (assert (:generate-key session-rw {:mechanism :CKM_AES_KEY_GEN}
                                         {:CKA_CLASS :CKO_SECRET_KEY
                                          :CKA_KEY_TYPE :CKK_AES
                                          :CKA_VALUE_LEN 32
                                          :CKA_WRAP true
                                          :CKA_WRAP_TEMPLATE {:CKA_ENCRYPT true
                                                              :CKA_TOKEN false
                                                              :CKA_VALUE_LEN 16}}))
              attr (assert (:get-attribute-value session-rw key [:CKA_WRAP_TEMPLATE]))
              wrap-template (attr :CKA_WRAP_TEMPLATE)]
          (assert (struct? wrap-template))
          (assert (= true (wrap-template :CKA_ENCRYPT)))
          (assert (= false (wrap-template :CKA_TOKEN)))
          (assert (= 16 (wrap-template :CKA_VALUE_LEN)))
          (:destroy-object session-rw key))

        (assert (:set-attribute-value session-rw
                                      obj-handle1
                                      {:CKA_LABEL "Label 1"}))
        (let [attr (assert (:get-attribute-value session-rw
                                                 obj-handle1
                                                 [:CKA_TOKEN
                                                  :CKA_CLASS
                                                  :CKA_VALUE
                                                  :CKA_APPLICATION
                                                  :CKA_LABEL]))]
          (assert (= "Label 1" (attr :CKA_LABEL))))

        (assert (:set-attribute-value session-rw
                                      obj-handle1
                                      {:CKA_LABEL "Label 2"}))
        (let [attr (assert (:get-attribute-value session-rw
                                                 obj-handle1
                                                 [:CKA_TOKEN
                                                  :CKA_CLASS
                                                  :CKA_VALUE
                                                  :CKA_APPLICATION
                                                  :CKA_LABEL]))]
          (assert (= "Label 2" (attr :CKA_LABEL))))

        (assert (:find-objects-init session-rw))
        (assert (= 2 (length (assert (:find-objects session-rw 10)))))
        (assert (:find-objects-final session-rw))

        ## Calling destroy-object between find-objects-init and find-objects-final
        ## cause an abnormal behavior.
        (assert (= nil (:destroy-object session-rw obj-handle2)))

        (assert (:find-objects-init session-rw))
        (assert (= 1 (length (assert (:find-objects session-rw 10)))))
        (assert (:find-objects-final session-rw))))))

(end-suite)
