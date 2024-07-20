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
(var test-serial-nubmer nil)

(defn find-slot-with-serial-number (p11 serial-number)
  (find
   (fn [s] (= ((:get-token-info p11 s) :serial-number)
              serial-number))
   (:get-slot-list p11)))


### Slot info, init token tests
(with [p11 (assert (new softhsm2-so-path))]

  ## Find uninitialized slot
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

  (set test-serial-nubmer ((:get-token-info p11 test-slot) :serial-number)))

### Session info, pin, login tests
(with [p11 (assert (new softhsm2-so-path))]

  ## Find the slot initialized from the above
  (set test-slot (find-slot-with-serial-number p11 test-serial-nubmer))

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

    ## Calling logout is not a mandatory. logout is called automatically when
    ## session-obj is out of scope.
    (assert (:logout session-rw)))

  (with [session-ro (assert (:open-session p11 test-slot :read-only))]
    (assert (= ((:get-session-info session-ro) :flags) 4))
    (assert (= ((:get-session-info session-ro) :state) 0))
    (assert (:login session-ro :user test-user-pin2))))

(def p11 (assert (new softhsm2-so-path)))

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
    (assert (:find-objects-final session-rw))))

### Key tests
(with [session-rw (assert (:open-session p11 test-slot))]
  (assert (:login session-rw :user test-user-pin2))

  ## generate-key
  (assert (:generate-key session-rw {:mechanism :CKM_DES_KEY_GEN}))

  ## generate-key-pair
  (let [pubkey-template {:CKA_ENCRYPT         true
                         :CKA_VERIFY          true
                         :CKA_MODULUS_BITS    768
                         :CKA_PUBLIC_EXPONENT (string (buffer/from-bytes 0x01 0x00 0x01))}
        privkey-template {:CKA_TOKEN     true
                          :CKA_PRIVATE   true
                          :CKA_SUBJECT   "subject"
                          :CKA_ID        (string (buffer/from-bytes 1 2 3))
                          :CKA_SENSITIVE true
                          :CKA_DECRYPT   true
                          :CKA_SIGN      true
                          :CKA_UNWRAP    true}]
    (assert (:generate-key-pair session-rw
                                {:mechanism :CKM_RSA_PKCS_KEY_PAIR_GEN}
                                pubkey-template
                                privkey-template)))

  ## wrap, unwrap key
  (let [wrap-key-template {:CKA_CLASS       :CKO_SECRET_KEY
                           :CKA_KEY_TYPE    :CKK_AES
                           :CKA_TOKEN       true
                           :CKA_VALUE_LEN   32
                           :CKA_PRIVATE     true
                           :CKA_SENSITIVE   false
                           :CKA_WRAP        true
                           :CKA_EXTRACTABLE true
                           :CKA_UNWRAP      true}
        key-template {:CKA_CLASS       :CKO_SECRET_KEY
                      :CKA_KEY_TYPE    :CKK_AES
                      :CKA_TOKEN       true
                      :CKA_VALUE_LEN   32
                      :CKA_EXTRACTABLE true
                      :CKA_WRAP        true
                      :CKA_UNWRAP      true}
        unwrap-key-template {:CKA_CLASS       :CKO_SECRET_KEY
                             :CKA_KEY_TYPE    :CKK_AES
                             :CKA_TOKEN       true
                             :CKA_EXTRACTABLE true
                             :CKA_WRAP        false
                             :CKA_UNWRAP      false}

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
                                           unwrap-key-template))])

  ## derive key
  (let [base (hex-decode "02")
        prime (hex-decode "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF")
        priv-tpl {:CKA_CLASS    :CKO_PRIVATE_KEY
                  :CKA_KEY_TYPE :CKK_DH
                  :CKA_PRIVATE  true
                  :CKA_TOKEN    false
                  :CKA_DERIVE   true}
        pub-tpl  {:CKA_CLASS    :CKO_PUBLIC_KEY
                  :CKA_KEY_TYPE :CKK_DH
                  :CKA_PRIVATE  true
                  :CKA_TOKEN    false
                  :CKA_DERIVE   true
                  :CKA_BASE     base
                  :CKA_PRIME    prime}
        derive-tpl {:CKA_CLASS       :CKO_SECRET_KEY
                    :CKA_KEY_TYPE    :CKK_AES
                    :CKA_VALUE_LEN   32
                    :CKA_TOKEN       true
                    :CKA_PRIVATE     true
                    :CKA_SENSITIVE   false
                    :CKA_EXTRACTABLE true}

        ## Generate 2 DH key pairs
        (pub1 priv1) (assert (:generate-key-pair session-rw
                                                 {:mechanism :CKM_DH_PKCS_KEY_PAIR_GEN}
                                                 pub-tpl
                                                 priv-tpl))
        (pub2 priv2) (assert (:generate-key-pair session-rw
                                                 {:mechanism :CKM_DH_PKCS_KEY_PAIR_GEN}
                                                 pub-tpl
                                                 priv-tpl))

        ## Retrieve public key from both
        pub1-bytes ((:get-attribute-value session-rw pub1 [:CKA_VALUE]) :CKA_VALUE)
        pub2-bytes ((:get-attribute-value session-rw pub2 [:CKA_VALUE]) :CKA_VALUE)

        ## Derive the first secret key
        sec1 (:derive-key session-rw
                          {:mechanism :CKM_DH_PKCS_DERIVE
                           :parameter pub2-bytes}
                          priv1
                          derive-tpl)

        ## Derive the second secret key
        sec2 (:derive-key session-rw
                          {:mechanism :CKM_DH_PKCS_DERIVE
                           :parameter pub1-bytes}
                          priv2
                          derive-tpl)

        ## Retrieve the derived private keys from both
        sec1-bytes ((:get-attribute-value session-rw sec1 [:CKA_VALUE]) :CKA_VALUE)
        sec2-bytes ((:get-attribute-value session-rw sec2 [:CKA_VALUE]) :CKA_VALUE)]

    ## Check if secret keys match
    (assert (= sec1-bytes sec2-bytes))))

### Encrypt, decrypt tests
(with [session-rw (assert (:open-session p11 test-slot))]
  (assert (:login session-rw :user test-user-pin2))
  (let [iv (:generate-random session-rw 8)
        key (:generate-key session-rw
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
    (assert (:encrypt-init session-rw {:mechanism :CKM_AES_ECB} key))
    (assert (:encrypt session-rw plain))))


### Random number tests
(with [session-rw (assert (:open-session p11 test-slot))]
  (assert (:login session-rw :user test-user-pin2))
  (assert (:seed-random session-rw (os/cryptorand 32)))
  (let [random1 (assert (:generate-random session-rw 32))
        random2 (assert (:generate-random session-rw 32))]
    (assert (not (= random1 random2)))))

(:close p11)

(assert (sh/exec "softhsm2-util" "--delete-token" "--token" test-token-label))


(end-suite)
