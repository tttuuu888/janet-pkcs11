(use ../build/pkcs11)
(use spork/test)
(import spork/sh)

(start-suite)

(def test-token-label "janet-pkcs11-test")
(def test-so-pin "012345")
(def test-user-pin "123456")

(let [p11 (assert (new "/usr/lib/softhsm/libsofthsm2.so"))
      test-slot (min ;(:get-slot-list p11))]

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
  )

(assert (sh/exec "softhsm2-util" "--delete-token" "--token" test-token-label))

(end-suite)
