/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include "main.h"
#include "error.h"

JANET_FN(p11_seed_random,
         "(seed-random session-obj seed)",
         "Mixes additional seed material into the token’s random number generator."
         "Returns a `session-obj`, if successful.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    JanetByteView seed = janet_getbytes(argv, 1);

    CK_RV rv;
    rv = obj->func_list->C_SeedRandom(obj->session, (CK_BYTE_PTR)seed.bytes, (CK_ULONG)seed.len);
    PKCS11_ASSERT(rv, "C_SeedRandom");

    return janet_wrap_abstract(obj);
}

JANET_FN(p11_generate_random,
         "(generate-random session-obj length)",
         "Generates random or pseudo-random data. Returns the `length` "
         "bytes of random data in string format, if successful.")
{
    janet_fixarity(argc, 2);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    CK_ULONG length = (CK_ULONG)janet_getnumber(argv, 1);
    CK_BYTE_PTR random_data = (CK_BYTE_PTR)janet_smalloc(length);

    CK_RV rv;
    rv = obj->func_list->C_GenerateRandom(obj->session, random_data, length);
    PKCS11_ASSERT(rv, "C_GenerateRandom");

    return janet_wrap_string(janet_string(random_data, length));
}

void submod_random(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("seed-random", p11_seed_random),
        JANET_REG("generate-random", p11_generate_random),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "", cfuns);
}
