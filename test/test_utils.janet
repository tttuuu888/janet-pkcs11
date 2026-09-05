(use ../build/pkcs11)
(use ./helper)
(use spork/test)

(start-suite)

(assert (= "abcddcba" (hex-encode (hex-decode "abcddcba"))))
(assert (= "abcddcba" (hex-encode (hex-decode "ABCDDCBA"))))
(assert (= (hex-decode "00ff") "\x00\xff"))

(assert-error "Error expected" (hex-decode "zz"))
(assert-error "Error expected" (hex-decode "abc"))

(end-suite)
