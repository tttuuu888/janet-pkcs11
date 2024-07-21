/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include "main.h"
#include "error.h"
#include "attribute.h"

JANET_FN(p11_digest_init,
         "(digest-init session-obj mechanism)",
         "Initializes  a message-digesting operation. "
         "Returns a `session-obj`, if successful.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetStruct mechanism = janet_getstruct(argv, 1);

    CK_MECHANISM_PTR p_mechanism = janet_struct_to_p11_mechanism(mechanism);

    CK_RV rv;
    rv = obj->func_list->C_DigestInit(obj->session, p_mechanism);
    PKCS11_ASSERT(rv, "C_DigestInit");

    return janet_wrap_abstract(obj);
}

JANET_FN(p11_digest,
         "(digest session-obj data)",
         "Digests data in a single part. Returns an message digest in string, "
         "if successful.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetByteView data = janet_getbytes(argv, 1);

    CK_BYTE_PTR digest_data = NULL_PTR;
    CK_ULONG digest_data_len = 0;

    CK_RV rv;
    rv = obj->func_list->C_Digest(obj->session,
                                  (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len,
                                  digest_data, &digest_data_len);
    PKCS11_ASSERT(rv, "C_Digest");

    digest_data = janet_smalloc(digest_data_len);
    rv = obj->func_list->C_Digest(obj->session, (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len,
                                  digest_data, &digest_data_len);
    PKCS11_ASSERT(rv, "C_Digest");

    return janet_wrap_string(janet_string(digest_data, digest_data_len));
}

JANET_FN(p11_digest_update,
         "(digest-update session-obj data)",
         "Continues a multiple-part message-digesting operation, processing "
         "another `data` part. Returns a `session-obj`, if successful.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetByteView data = janet_getbytes(argv, 1);

    CK_RV rv;
    rv = obj->func_list->C_DigestUpdate(obj->session,
                                        (CK_BYTE_PTR)data.bytes, (CK_ULONG)data.len);
    PKCS11_ASSERT(rv, "C_DigestUpdate");

    return janet_wrap_abstract(obj);
}

JANET_FN(p11_digest_key,
         "(digest-key session-obj key-handle)",
         "Continues a multiple-part message-digesting operation by digesting "
         "the value of a secret key. Returns a `session-obj`, if successful.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    CK_OBJECT_HANDLE key_handle = janet_getnumber(argv, 1);

    CK_RV rv;
    rv = obj->func_list->C_DigestKey(obj->session, key_handle);
    PKCS11_ASSERT(rv, "C_DigestKey");

    return janet_wrap_abstract(obj);
}

JANET_FN(p11_digest_final,
         "(digest-final session-obj)",
         "Finishes a multiple-part message-digesting operation. "
         "Return the message digest in string, if successful.")
{
    janet_fixarity(argc, 1);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());

    CK_BYTE_PTR digest_data = NULL_PTR;
    CK_ULONG digest_data_len = 0;

    CK_RV rv;
    rv = obj->func_list->C_DigestFinal(obj->session, digest_data, &digest_data_len);
    PKCS11_ASSERT(rv, "C_DigestFinal");

    digest_data = janet_smalloc(digest_data_len);
    rv = obj->func_list->C_DigestFinal(obj->session, digest_data, &digest_data_len);
    PKCS11_ASSERT(rv, "C_DigestFinal");

    return janet_wrap_string(janet_string(digest_data, digest_data_len));
}

void submod_digest(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("digest-init", p11_digest_init),
        JANET_REG("digest", p11_digest),
        JANET_REG("digest-update", p11_digest_update),
        JANET_REG("digest-key", p11_digest_key),
        JANET_REG("digest-final", p11_digest_final),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "", cfuns);
}
