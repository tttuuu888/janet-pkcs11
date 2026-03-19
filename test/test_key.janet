(use ../build/pkcs11)
(use ./helper)
(use spork/test)

(start-suite)

(def p11 (assert (new hsm-so-path)))
(def [test-slot token-label] (init-test-token p11))

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

(:close p11)
(assert (cleanup-token token-label))

(end-suite)
