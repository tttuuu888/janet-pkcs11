(use ../build/pkcs11)
(use spork/test)
(import spork/sh)

(start-suite)

(def softhsm2-so-path "/usr/lib/softhsm/libsofthsm2.so")
(def test-token-label "janet-pkcs11-test")
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



    (let [obj-handle1 (assert (:create-object session-rw
                                              {CKA_CLASS CKO_DATA
                                               CKA_TOKEN true
                                               CKA_APPLICATION "My Application"
                                               CKA_VALUE ""}))
          obj-handle2 (assert (:copy-object session-rw
                                            obj-handle1
                                            {CKA_LABEL "copy object"}))]
      (assert (= nil (:destroy-object session-rw obj-handle2))))


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
