/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include "main.h"
#include "pkcs11_utils.h"


JANET_FN(cfun_bit_and,
         "(bit-and & xs)",
         "Returns the bit-wise and of 64 bit integer xs.")
{
    if (argc == 0)
        return janet_wrap_s64(0);

    int64_t ret = janet_getinteger64(argv, 0);
    for (int i = 1; i < argc; i++) {
        ret &= janet_getinteger64(argv, i);
    }

    return janet_wrap_number(ret);
}

JANET_FN(cfun_bit_or,
         "(bit-or & xs)",
         "Returns the bit-wise or of 64 bit integer xs.")
{
    if (argc == 0)
        return janet_wrap_s64(0);

    int64_t ret = janet_getinteger64(argv, 0);
    for (int i = 1; i < argc; i++) {
        ret |= janet_getinteger64(argv, i);
    }

    return janet_wrap_number(ret);
}

JANET_FN(cfun_bit_lshift,
         "(bit-lshift x shift)",
         "Returns the value of `x` bit shifted left by `shift`. "
         "Each elements are 64 bit integers.")
{
    janet_fixarity(argc, 2);

    int64_t x = janet_getinteger64(argv, 0);
    int64_t shift = janet_getinteger64(argv, 1);

    return janet_wrap_number(x << shift);
}

JANET_FN(cfun_bit_rshift,
         "(bit-rshift x shift)",
         "Returns the value of `x` bit shifted right by `shift`. "
         "Each elements are 64 bit integers.")
{
    janet_fixarity(argc, 2);

    int64_t x = janet_getinteger64(argv, 0);
    int64_t shift = janet_getinteger64(argv, 1);

    return janet_wrap_number(x >> shift);
}

void submod_utils(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("bit-and", cfun_bit_and),
        JANET_REG("bit-or", cfun_bit_or),
        JANET_REG("bit-lshift", cfun_bit_lshift),
        JANET_REG("bit-rshift", cfun_bit_rshift),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "", cfuns);
}
