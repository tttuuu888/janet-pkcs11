(use ../build/pkcs11)
(use ./helper)
(use spork/test)

(start-suite)

(def test-env (setup-test-env))
(def test-token-label (string "janet-pkcs11-test"
                              ;(string/bytes (os/cryptorand 4))))

(var test-slot nil)
(var test-serial-nubmer nil)

## Always delete the test token and the test environment, even if a test
## raises an error.
(defer (do (assert (cleanup-token test-token-label))
           (assert (cleanup-test-env test-env)))

  ## Initialize a token for session tests
  (with [p11 (assert (new hsm-so-path))]
    (set test-slot (find-uninitialized-slot p11))
    (assert (:init-token p11 test-slot test-so-pin test-token-label))
    (set test-serial-nubmer ((:get-token-info p11 test-slot) :serial-number)))

  ### Session info, pin, login tests
  (with [p11 (assert (new hsm-so-path))]

    ## Find the slot initialized from the above
    (set test-slot (find-slot-with-serial-number p11 test-serial-nubmer))

    (with [session-rw (assert (:open-session p11 test-slot))]
      (assert (= ((:get-session-info session-rw) :flags)
                 [:CKF_SERIAL_SESSION :CKF_RW_SESSION]))
      (assert (= ((:get-session-info session-rw) :state) :CKS_RW_PUBLIC_SESSION))
      ## SoftHSM2 does not implement get-operation-state.
      (assert (= :CKR_FUNCTION_NOT_SUPPORTED
                 (try (:get-operation-state session-rw) ([e] e))))
      ## :context-specific login without an active operation is rejected.
      (assert (= :CKR_OPERATION_NOT_INITIALIZED
                 (try (:login session-rw :context-specific test-user-pin) ([e] e))))
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
      (assert (= ((:get-session-info session-ro) :flags) [:CKF_SERIAL_SESSION]))
      (assert (= ((:get-session-info session-ro) :state) :CKS_RO_PUBLIC_SESSION))
      (assert (:login session-ro :user test-user-pin2)))))

(end-suite)
