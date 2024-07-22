/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include "main.h"
#include "error.h"
#include "attribute.h"

JANET_FN(p11_digest_encrypt_update,
         "(digest-encrypt-update session-obj data)",
         "Continues multiple-part digest and encryption operations, processing "
         "another data part. Returns an encrypted data in string, if successful.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetByteView data = janet_getbytes(argv, 1);

    CK_BYTE_PTR enc_data = NULL_PTR;
    CK_ULONG enc_data_len = 0;

    CK_RV rv;
    rv = obj->func_list->C_DigestEncryptUpdate(obj->session,
                                               (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len,
                                               enc_data, &enc_data_len);
    PKCS11_ASSERT(rv, "C_DigestEncryptUpdate");

    enc_data = janet_smalloc(enc_data_len);
    rv = obj->func_list->C_DigestEncryptUpdate(obj->session,
                                               (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len,
                                               enc_data, &enc_data_len);
    PKCS11_ASSERT(rv, "C_DigestEncryptUpdate");

    return janet_wrap_string(janet_string(enc_data, enc_data_len));
}

JANET_FN(p11_decrypt_digest_update,
         "(decrypt-digest-update session-obj data)",
         "continues a multiple-part combined decryption and digest operation, "
         "processing another data part. Returns a recovered data in string, if "
         "successful.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetByteView data = janet_getbytes(argv, 1);

    CK_BYTE_PTR dec_data = NULL_PTR;
    CK_ULONG dec_data_len = 0;

    CK_RV rv;
    rv = obj->func_list->C_DecryptDigestUpdate(obj->session,
                                               (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len,
                                               dec_data, &dec_data_len);
    PKCS11_ASSERT(rv, "C_DecryptDigestUpdate");

    dec_data = janet_smalloc(dec_data_len);
    rv = obj->func_list->C_DecryptDigestUpdate(obj->session,
                                               (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len,
                                               dec_data, &dec_data_len);
    PKCS11_ASSERT(rv, "C_DecryptDigestUpdate");

    return janet_wrap_string(janet_string(dec_data, dec_data_len));
}

JANET_FN(p11_sign_encrypt_update,
         "(sign-encrypt-update session-obj data)",
         "Continues multiple-part combined signature and encryption operations, "
         "processing another data part. Returns an encrypted data in string, "
         "if successful.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetByteView data = janet_getbytes(argv, 1);

    CK_BYTE_PTR enc_data = NULL_PTR;
    CK_ULONG enc_data_len = 0;

    CK_RV rv;
    rv = obj->func_list->C_SignEncryptUpdate(obj->session,
                                             (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len,
                                             enc_data, &enc_data_len);
    PKCS11_ASSERT(rv, "C_SignEncryptUpdate");

    enc_data = janet_smalloc(enc_data_len);
    rv = obj->func_list->C_SignEncryptUpdate(obj->session,
                                             (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len,
                                             enc_data, &enc_data_len);
    PKCS11_ASSERT(rv, "C_SignEncryptUpdate");

    return janet_wrap_string(janet_string(enc_data, enc_data_len));
}

JANET_FN(p11_decrypt_verify_update,
         "(decrypt-verify-update session-obj data)",
         "continues a multiple-part combined decryption and verification "
         "operation, processing another data part. Returns a recovered data "
         "in string, if successful.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetByteView data = janet_getbytes(argv, 1);

    CK_BYTE_PTR dec_data = NULL_PTR;
    CK_ULONG dec_data_len = 0;

    CK_RV rv;
    rv = obj->func_list->C_DecryptVerifyUpdate(obj->session,
                                               (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len,
                                               dec_data, &dec_data_len);
    PKCS11_ASSERT(rv, "C_DecryptVerifyUpdate");

    dec_data = janet_smalloc(dec_data_len);
    rv = obj->func_list->C_DecryptVerifyUpdate(obj->session,
                                               (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len,
                                               dec_data, &dec_data_len);
    PKCS11_ASSERT(rv, "C_DecryptVerifyUpdate");

    return janet_wrap_string(janet_string(dec_data, dec_data_len));
}

void submod_dual(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("digest-encrypt-update", p11_digest_encrypt_update),
        JANET_REG("decrypt-digest-update", p11_decrypt_digest_update),
        JANET_REG("sign-encrypt-update", p11_sign_encrypt_update),
        JANET_REG("decrypt-verify-update", p11_decrypt_verify_update),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "pkcs11", cfuns);
}
