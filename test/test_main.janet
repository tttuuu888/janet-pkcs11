(use ../build/pkcs11)
(use spork/test)

(start-suite)

(let [p11 (assert (new "/usr/lib/softhsm/libsofthsm2.so"))]
  (pp (:get-info p11))

  )

(end-suite)
