/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include "main.h"
#include "error.h"
#include "attribute.h"
#include "types.h"

JANET_FN(p11_generate_key,
         "(generate-key session-obj mechanism &opt template)",
         "Generates a secret key or set of domain parameters, creating a new "
         "key object. Returns a `key-handle`, if successful.")
{
    janet_arity(argc, 2, 3);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetStruct mechanism = janet_getstruct(argv, 1);

    CK_MECHANISM_PTR p_mechanism = janet_struct_to_p11_mechanism(mechanism);

    CK_ULONG count = 0;
    CK_ATTRIBUTE_PTR p_template = NULL_PTR;
    CK_OBJECT_HANDLE key_handle;

    if (argc == 3) {
        JanetStruct template = janet_getstruct(argv, 2);
        count = (CK_ULONG)janet_struct_length(template);
        p_template = janet_struct_to_p11_template(template);
    }

    CK_RV rv;
    rv = obj->func_list->C_GenerateKey(obj->session, p_mechanism, p_template, count, &key_handle);
    PKCS11_ASSERT(rv, "C_GenerateKey");

    return janet_wrap_number((double)key_handle);
}

JANET_FN(p11_generate_key_pair,
         "(generate-key-pair session-obj mechanism pubkey-template privkey-template)",
         "Generates a public/private key pair, creating new key objects. "
         "Returns a list of [pubkey-handle privkey-handle], if successful.")
{
    janet_fixarity(argc, 4);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetStruct mechanism = janet_getstruct(argv, 1);
    JanetStruct pub_template = janet_getstruct(argv, 2);
    JanetStruct priv_template = janet_getstruct(argv, 3);

    CK_MECHANISM_PTR p_mechanism = janet_struct_to_p11_mechanism(mechanism);
    CK_ULONG pub_template_count = (CK_ULONG)janet_struct_length(pub_template);
    CK_ULONG priv_template_count = (CK_ULONG)janet_struct_length(priv_template);

    CK_ATTRIBUTE_PTR p_pub_template = janet_struct_to_p11_template(pub_template);
    CK_ATTRIBUTE_PTR p_priv_template = janet_struct_to_p11_template(priv_template);

    CK_OBJECT_HANDLE pub_handle;
    CK_OBJECT_HANDLE priv_handle;

    CK_RV rv;
    rv = obj->func_list->C_GenerateKeyPair(obj->session,
                                           p_mechanism,
                                           p_pub_template, pub_template_count,
                                           p_priv_template, priv_template_count,
                                           &pub_handle, &priv_handle);
    PKCS11_ASSERT(rv, "C_GenerateKeyPair");

    Janet *tup = janet_tuple_begin(2);
    tup[0] = janet_wrap_number(pub_handle);
    tup[1] = janet_wrap_number(priv_handle);

    return janet_wrap_tuple(janet_tuple_end(tup));
}

JANET_FN(p11_wrap_key,
         "(wrap-key session-obj mechanism wrapping-key-handle key-handle)",
         "Wraps (i.e., encrypts) a private or secret key."
         "Returns a wrapped key in string, if successful.")
{
    janet_fixarity(argc, 4);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetStruct mechanism = janet_getstruct(argv, 1);
    CK_OBJECT_HANDLE wrapping_key_handle = (CK_OBJECT_HANDLE)janet_getnumber(argv, 2);
    CK_OBJECT_HANDLE key_handle = (CK_OBJECT_HANDLE)janet_getnumber(argv, 3);

    CK_MECHANISM_PTR p_mechanism = janet_struct_to_p11_mechanism(mechanism);
    CK_BYTE_PTR wrapped_key = NULL_PTR;
    CK_ULONG wrapped_key_len = 0;

    CK_RV rv;
    rv = obj->func_list->C_WrapKey(obj->session, p_mechanism,
                                   wrapping_key_handle, key_handle,
                                   wrapped_key, &wrapped_key_len);
    PKCS11_ASSERT(rv, "C_WrapKey");

    wrapped_key = janet_smalloc(wrapped_key_len);

    rv = obj->func_list->C_WrapKey(obj->session, p_mechanism,
                                   wrapping_key_handle, key_handle,
                                   wrapped_key, &wrapped_key_len);
    PKCS11_ASSERT(rv, "C_WrapKey");

    return janet_wrap_string(janet_string(wrapped_key, wrapped_key_len));
}

JANET_FN(p11_unwrap_key,
         "(unwrap-key session-obj mechanism unwrapping-key-handle wrapped-key template)",
         "Unwraps (i.e. decrypts) a wrapped key, creating a new private key "
         "or secret key object. Returns a `key-handle`, if successful.")
{
    janet_fixarity(argc, 5);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetStruct mechanism = janet_getstruct(argv, 1);
    CK_OBJECT_HANDLE unwrapping_key_handle = (CK_OBJECT_HANDLE)janet_getnumber(argv, 2);
    JanetByteView wrapped_key = janet_getbytes(argv, 3);
    JanetStruct template = janet_getstruct(argv, 4);

    CK_MECHANISM_PTR p_mechanism = janet_struct_to_p11_mechanism(mechanism);
    CK_ATTRIBUTE_PTR p_template = janet_struct_to_p11_template(template);
    CK_ULONG count = (CK_ULONG)janet_struct_length(template);
    CK_OBJECT_HANDLE key_handle = 0;

    CK_RV rv;
    rv = obj->func_list->C_UnwrapKey(obj->session, p_mechanism,
                                     unwrapping_key_handle,
                                     (CK_BYTE_PTR)wrapped_key.bytes,
                                     (CK_ULONG)wrapped_key.len,
                                     p_template, count,
                                     &key_handle);
    PKCS11_ASSERT(rv, "C_UnwrapKey");

    return janet_wrap_number((double)key_handle);
}

JANET_FN(p11_derive_key,
         "(derive-key session-obj mechanism base-key-handle template)",
         "Derives a key from a base key, creating a new key object. "
         "Returns a `key-handle`, if successful.")
{
    janet_fixarity(argc, 4);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetStruct mechanism = janet_getstruct(argv, 1);
    CK_OBJECT_HANDLE base_key_handle = (CK_OBJECT_HANDLE)janet_getnumber(argv, 2);
    JanetStruct template = janet_getstruct(argv, 3);

    CK_MECHANISM_PTR p_mechanism = janet_struct_to_p11_mechanism(mechanism);
    CK_ATTRIBUTE_PTR p_template = janet_struct_to_p11_template(template);
    CK_ULONG count = (CK_ULONG)janet_struct_length(template);
    CK_OBJECT_HANDLE key_handle = 0;

    CK_RV rv;
    rv = obj->func_list->C_DeriveKey(obj->session, p_mechanism,
                                     base_key_handle,
                                     p_template, count,
                                     &key_handle);
    PKCS11_ASSERT(rv, "C_DeriveKey");

    return janet_wrap_number((double)key_handle);
}

void submod_key(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("generate-key", p11_generate_key),
        JANET_REG("generate-key-pair", p11_generate_key_pair),
        JANET_REG("wrap-key", p11_wrap_key),
        JANET_REG("unwrap-key", p11_unwrap_key),
        JANET_REG("derive-key", p11_derive_key),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "pkcs11", cfuns);
}
