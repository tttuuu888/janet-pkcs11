/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include "main.h"
#include "error.h"
#include "attribute.h"

JANET_FN(p11_decrypt_init,
         "(decrypt-init session-obj mechanism key-handle)",
         "Initializes an decryption operation. "
         "Returns a `session-obj`, if successful.")
{
    janet_fixarity(argc, 3);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetStruct mechanism = janet_getstruct(argv, 1);
    CK_OBJECT_HANDLE key_handle = janet_getnumber(argv, 2);

    CK_MECHANISM_PTR p_mechanism = janet_struct_to_p11_mechanism(mechanism);

    CK_RV rv;
    rv = obj->func_list->C_DecryptInit(obj->session, p_mechanism, key_handle);
    PKCS11_ASSERT(rv, "C_DecryptInit");

    return janet_wrap_abstract(obj);
}

JANET_FN(p11_decrypt,
         "(decrypt session-obj data)",
         "Decrypts encrypted data in a single part. Returns an decrypted data "
         "in string, if successful.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetByteView data = janet_getbytes(argv, 1);

    CK_BYTE_PTR dec_data = NULL_PTR;
    CK_ULONG dec_data_len = 0;

    CK_RV rv;
    rv = obj->func_list->C_Decrypt(obj->session,
                                   (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len,
                                   dec_data, &dec_data_len);
    PKCS11_ASSERT(rv, "C_Decrypt");

    dec_data = janet_smalloc(dec_data_len);
    rv = obj->func_list->C_Decrypt(obj->session, (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len,
                                   dec_data, &dec_data_len);
    PKCS11_ASSERT(rv, "C_Decrypt");

    return janet_wrap_string(janet_string(dec_data, dec_data_len));
}

JANET_FN(p11_decrypt_update,
         "(decrypt-update session-obj data)",
         "Continues a multiple-part decryption operation, processing another "
         "encrypted `data` part. Return the decrypted data part in string, "
         "if successful.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetByteView data = janet_getbytes(argv, 1);

    CK_BYTE_PTR dec_data = NULL_PTR;
    CK_ULONG dec_data_len = 0;

    CK_RV rv;
    rv = obj->func_list->C_DecryptUpdate(obj->session,
                                         (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len,
                                         dec_data, &dec_data_len);
    PKCS11_ASSERT(rv, "C_DecryptUpdate");

    dec_data = janet_smalloc(dec_data_len);
    rv = obj->func_list->C_DecryptUpdate(obj->session,
                                         (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len,
                                         dec_data, &dec_data_len);
    PKCS11_ASSERT(rv, "C_DecryptUpdate");

    return janet_wrap_string(janet_string(dec_data, dec_data_len));
}

JANET_FN(p11_decrypt_final,
         "(decrypt-final session-obj)",
         "Finishes a multiple-part decryption operation. "
         "Return the last recovered data part in string, if successful.")
{
    janet_fixarity(argc, 1);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());

    CK_BYTE_PTR dec_data = NULL_PTR;
    CK_ULONG dec_data_len = 0;

    CK_RV rv;
    rv = obj->func_list->C_DecryptFinal(obj->session, dec_data, &dec_data_len);
    PKCS11_ASSERT(rv, "C_DecryptFinal");

    dec_data = janet_smalloc(dec_data_len);
    rv = obj->func_list->C_DecryptFinal(obj->session, dec_data, &dec_data_len);
    PKCS11_ASSERT(rv, "C_DecryptFinal");

    return janet_wrap_string(janet_string(dec_data, dec_data_len));
}

void submod_decrypt(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("decrypt-init", p11_decrypt_init),
        JANET_REG("decrypt", p11_decrypt),
        JANET_REG("decrypt-update", p11_decrypt_update),
        JANET_REG("decrypt-final", p11_decrypt_final),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "pkcs11", cfuns);
}
