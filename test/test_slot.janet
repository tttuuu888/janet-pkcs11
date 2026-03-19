(use ../build/pkcs11)
(use ./helper)
(use spork/test)

(start-suite)

(def test-token-label (string "janet-pkcs11-test"
                              ;(string/bytes (os/cryptorand 4))))

### Slot info, init token tests
(with [p11 (assert (new hsm-so-path))]

  ## Find uninitialized slot
  (def test-slot (min ;(:get-slot-list p11)))

  (let [info (:get-info p11)]
    (assert (= (info :cryptoki-version)) {:major 2 :minor 40})
    (assert (= (info :library-version))  {:major 2 :minor 6}))

  (assert (:get-slot-info p11 test-slot))
  (assert (:get-slot-info p11))
  (assert (:get-token-info p11 test-slot))
  (assert (= nil (:wait-for-slot-event p11)))
  (assert (:get-mechanism-info
             p11 test-slot (tuple (first (:get-mechanism-list p11 test-slot)))))
  (assert (:init-token p11 test-slot test-so-pin test-token-label)))

(assert (cleanup-token test-token-label))

(end-suite)
