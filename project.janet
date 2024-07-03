(declare-project
 :name "pkcs11"
 :description "Janet wrapper for the PKCS #11 API"
 :author "Seungki Kim"
 :license "MIT"
 :version "0.3.0"
 :url "https://github.com/tttuuu888/janet-pkcs11"
 :repo "git+https://github.com/tttuuu888/janet-pkcs11"
 :dependencies ["spork"])

(declare-native
 :name "pkcs11"
 :cflags ["-Isrc" "-Wall" ;default-cflags]
 :source ["src/main.c"
          "src/slot_and_token.c"])
