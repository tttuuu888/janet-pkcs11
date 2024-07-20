/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include "main.h"
#include "error.h"
#include "attribute.h"

JANET_FN(p11_encrypt_init,
         "(encrypt-init session-obj mechanism key-handle)",
         "Initializes an encryption operation. "
         "Returns a `session-obj`, if successful.")
{
    janet_fixarity(argc, 3);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetStruct mechanism = janet_getstruct(argv, 1);
    CK_OBJECT_HANDLE key_handle = janet_getnumber(argv, 2);

    CK_MECHANISM_PTR p_mechanism = janet_struct_to_p11_mechanism(mechanism);

    CK_RV rv;
    rv = obj->func_list->C_EncryptInit(obj->session, p_mechanism, key_handle);
    PKCS11_ASSERT(rv, "C_EncryptInit");

    return janet_wrap_abstract(obj);
}

JANET_FN(p11_encrypt,
         "(encrypt session-obj data)",
         "Encrypts single-part data. Returns an encrypted data in string, "
         "if successful.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetByteView data = janet_getbytes(argv, 1);

    CK_BYTE_PTR enc_data = NULL_PTR;
    CK_ULONG enc_data_len = 0;

    CK_RV rv;
    rv = obj->func_list->C_Encrypt(obj->session,
                                   (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len,
                                   enc_data, &enc_data_len);
    PKCS11_ASSERT(rv, "C_Encrypt");

    if (enc_data_len == 0) {
        return janet_wrap_string(janet_string(NULL, 0));
    }

    enc_data = janet_smalloc(enc_data_len);
    rv = obj->func_list->C_Encrypt(obj->session, (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len,
                                   enc_data, &enc_data_len);
    PKCS11_ASSERT(rv, "C_Encrypt");

    return janet_wrap_string(janet_string(enc_data, enc_data_len));
}

void submod_encrypt(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("encrypt-init", p11_encrypt_init),
        JANET_REG("encrypt", p11_encrypt),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "", cfuns);
}
