(use ../build/pkcs11)
(use ./helper)
(use spork/test)

(start-suite)

(def test-token-label (string "janet-pkcs11-test"
                              ;(string/bytes (os/cryptorand 4))))

(defer (assert (cleanup-token test-token-label))

  ### Slot info, init token tests
  (with [p11 (assert (new hsm-so-path))]

    ## Find uninitialized slot
    (def test-slot (min ;(:get-slot-list p11)))

    (let [info (:get-info p11)]
      # cryptoki-version follows the PKCS#11 header the HSM library was built
      # with (2.40 or 3.x), so only accept a known major version.
      (assert (has-value? [2 3] (get-in info [:cryptoki-version :major])))
      (assert (int? (get-in info [:cryptoki-version :minor])))

      # library-version depends on the installed SoftHSM, so only check the shape.
      (assert (int? (get-in info [:library-version :major])))
      (assert (int? (get-in info [:library-version :minor])))

      (assert (string? (info :manufacturer-id)))
      (assert (string? (info :library-description)))
      (assert (int? (info :flags))))

    (assert (:get-slot-info p11 test-slot))
    (assert (:get-slot-info p11))
    (assert (:get-token-info p11 test-slot))
    (assert (= nil (:wait-for-slot-event p11)))
    (assert (:get-mechanism-info
               p11 test-slot (tuple (first (:get-mechanism-list p11 test-slot)))))
    (assert (:init-token p11 test-slot test-so-pin test-token-label))))

(end-suite)
