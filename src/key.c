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
         "object. Returns an `obj-handle`, if successful.")
{
    janet_arity(argc, 2, 3);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetStruct mechanism = janet_getstruct(argv, 1);

    CK_MECHANISM_PTR p_mechanism = janet_struct_to_p11_mechanism(mechanism);

    CK_ULONG count = 0;
    CK_ATTRIBUTE_PTR p_template = NULL_PTR;
    CK_OBJECT_HANDLE obj_handle;

    if (argc == 3) {
        JanetStruct template = janet_getstruct(argv, 2);
        count = (CK_ULONG)janet_struct_length(template);
        p_template = janet_struct_to_p11_template(template);
    }

    CK_RV rv;
    rv = obj->func_list->C_GenerateKey(obj->session, p_mechanism, p_template, count, &obj_handle);
    PKCS11_ASSERT(rv, "C_GenerateKey");

    return janet_wrap_number((double)obj_handle);
}

JANET_FN(p11_generate_key_pair,
         "(generate-key-pair session-obj mechanism pubkey-template privkey-template)",
         "Generates a public/private key pair, creating new key objects. "
         "Returns a list of [pubkey-obj-handle privkey-obj-handle], if successful.")
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

    CK_OBJECT_HANDLE pub_obj_handle;
    CK_OBJECT_HANDLE priv_obj_handle;

    CK_RV rv;
    rv = obj->func_list->C_GenerateKeyPair(obj->session,
                                           p_mechanism,
                                           p_pub_template, pub_template_count,
                                           p_priv_template, priv_template_count,
                                           &pub_obj_handle, &priv_obj_handle);
    PKCS11_ASSERT(rv, "C_GenerateKeyPair");

    Janet *tup = janet_tuple_begin(2);
    tup[0] = janet_wrap_number(pub_obj_handle);
    tup[1] = janet_wrap_number(priv_obj_handle);

    return janet_wrap_tuple(janet_tuple_end(tup));
}

void submod_key(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("generate-key", p11_generate_key),
        JANET_REG("generate-key-pair", p11_generate_key_pair),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "", cfuns);
}
