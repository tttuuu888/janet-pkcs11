(use ../build/pkcs11)
(use spork/test)

(start-suite)

(let [p11 (assert (new "/usr/lib/softhsm/libsofthsm2.so"))]
  (pp (:get-info p11))
  (pp (:get-slot-list p11))
  (pp (:get-slot-info p11 0))
  (pp (:get-slot-info p11))
  )

(end-suite)
