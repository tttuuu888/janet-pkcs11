(use ../build/pkcs11)
(use spork/test)
(import spork/sh)

(start-suite)

(def softhsm2-so-path "/usr/lib/softhsm/libsofthsm2.so")
(def test-token-label (string "janet-pkcs11-test"
                              ;(string/bytes (os/cryptorand 4))))
(def test-so-pin  "012345")
(def test-so-pin2 "abcdef")
(def test-user-pin  "123456")
(def test-user-pin2 "bcdefg")

(var test-slot nil)

(with [p11 (assert (new softhsm2-so-path))]
  (set test-slot (min ;(:get-slot-list p11)))

  (let [info (:get-info p11)]
    (assert (= (info :cryptoki-version)) {:major 2 :minor 40})
    (assert (= (info :library-version))  {:major 2 :minor 6}))

  (assert (:get-slot-info p11 test-slot))
  (assert (:get-slot-info p11))
  (assert (:get-token-info p11 test-slot))
  (assert (= nil (:wait-for-slot-event p11)))
  (assert (:get-mechanism-info
             p11 test-slot (tuple (first (:get-mechanism-list p11 test-slot)))))
  (assert (:init-token p11 test-slot test-so-pin test-token-label))

  (with [session-rw (assert (:open-session p11 test-slot))]
    (assert (= ((:get-session-info session-rw) :flags) 6))
    (assert (= ((:get-session-info session-rw) :state) 2))
    (assert-error "softhsm2 does not support C_GetOperationState"
                  (:get-operation-state session-rw))
    (assert (:login session-rw :so test-so-pin))
    (assert (:set-pin session-rw test-so-pin test-so-pin2))
    (assert (:init-pin session-rw test-user-pin))
    (assert (:logout session-rw))
    (assert (:set-pin session-rw test-user-pin test-user-pin2))
    (assert (:login session-rw :user test-user-pin2))

    ## The template is a struct. PKCS11 attribute defines can be used here, but
    ## only in Janet keyword format.
    (let [obj-handle1 (assert (:create-object session-rw
                                              {:CKA_CLASS :CKO_DATA
                                               :CKA_TOKEN true
                                               :CKA_APPLICATION "My Application"
                                               :CKA_VALUE ""}))
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
      (assert (:find-objects-final session-rw)))

    (assert (:generate-key session-rw {:mechanism :CKM_DES_KEY_GEN}))

    (let [pubkey-template {:CKA_ENCRYPT true
                           :CKA_VERIFY true
                           :CKA_MODULUS_BITS 768
                           :CKA_PUBLIC_EXPONENT (string (buffer/from-bytes 0x01 0x00 0x01))}
          privkey-template {:CKA_TOKEN true
                            :CKA_PRIVATE true
                            :CKA_SUBJECT "subject"
                            :CKA_ID (string (buffer/from-bytes 1 2 3))
                            :CKA_SENSITIVE true
                            :CKA_DECRYPT true
                            :CKA_SIGN true
                            :CKA_UNWRAP true}]
      (assert (:generate-key-pair session-rw
                                  {:mechanism :CKM_RSA_PKCS_KEY_PAIR_GEN}
                                  pubkey-template
                                  privkey-template)))

    (let [wrap-key-template {:CKA_CLASS :CKO_SECRET_KEY
                             :CKA_KEY_TYPE :CKK_AES
                             :CKA_TOKEN true
                             :CKA_VALUE_LEN 32
                             :CKA_PRIVATE true
                             :CKA_SENSITIVE false
                             :CKA_WRAP true
                             :CKA_EXTRACTABLE true
                             :CKA_UNWRAP true
                            }
          key-template {:CKA_CLASS :CKO_SECRET_KEY
                        :CKA_KEY_TYPE :CKK_AES
                        :CKA_TOKEN true
                        :CKA_VALUE_LEN 32
                        :CKA_EXTRACTABLE true
                        :CKA_WRAP true
                        :CKA_UNWRAP true}
          unwrap-key-template {:CKA_CLASS :CKO_SECRET_KEY
                               :CKA_KEY_TYPE :CKK_AES
                               :CKA_TOKEN true
                               :CKA_EXTRACTABLE true
                               :CKA_WRAP false
                               :CKA_UNWRAP false}

          wrap-key (assert (:generate-key session-rw
                                          {:mechanism :CKM_AES_KEY_GEN}
                                          wrap-key-template))
          key (assert (:generate-key session-rw
                                     {:mechanism :CKM_AES_KEY_GEN}
                                     key-template))
          wrapped-key (assert (:wrap-key session-rw
                                         {:mechanism :CKM_AES_KEY_WRAP_PAD}
                                         wrap-key
                                         key))
          unwrapped-key (assert (:unwrap-key session-rw
                                             {:mechanism :CKM_AES_KEY_WRAP_PAD}
                                             wrap-key
                                             wrapped-key
                                             unwrap-key-template))]
      )

    ## Calling logout is not a mandatory. logout is called automatically when
    ## session-obj is out of scope.
    (assert (:logout session-rw)))

  (with [session-ro (assert (:open-session p11 test-slot :read-only))]
    (assert (= ((:get-session-info session-ro) :flags) 4))
    (assert (= ((:get-session-info session-ro) :state) 0))
    (assert (:login session-ro :user test-user-pin2))
    (assert (:logout session-ro))))

(assert (sh/exec "softhsm2-util" "--delete-token" "--token" test-token-label))

### `p11-obj` and `session-obj` should work within `let` binding as well
(let [p11 (assert (new softhsm2-so-path))]
  (let [test-slot (min ;(:get-slot-list p11))]
    (assert (:init-token p11 test-slot test-so-pin test-token-label))
    (let [session-ro (assert (:open-session p11 test-slot :read-only))]
      (assert (= ((:get-session-info session-ro) :flags) 4))
      (assert (= (:close-session session-ro) nil)))
    (assert (= (:close-all-sessions p11 test-slot) nil))))

(assert (sh/exec "softhsm2-util" "--delete-token" "--token" test-token-label))



(end-suite)
