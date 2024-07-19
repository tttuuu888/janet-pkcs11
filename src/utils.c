/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include "main.h"
#include "utils.h"


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

JANET_FN(cfun_hex_encode,
         "(hex-encode bin)",
         "Performs hex encoding of binary data in `bin`. Returns the string.")
{
    const char hex_chars[] = "0123456789abcdef";

    janet_fixarity(argc, 1);

    JanetByteView bin = janet_getbytes(argv, 0);
    int str_len = bin.len * 2;
    unsigned char *str = janet_smalloc(str_len);

    for (int i = 0; i < bin.len; i++) {
        str[i*2] = hex_chars[bin.bytes[i] >> 4];
        str[i*2 + 1] = hex_chars[bin.bytes[i] & 0x0F];
    }

    return janet_wrap_string(janet_string(str, str_len));
}

JANET_FN(cfun_hex_decode,
         "(hex-decode str)",
         "Performs hex decoding of string data in `str`. Returns the string.")
{
    janet_fixarity(argc, 1);

    JanetByteView str = janet_getbytes(argv, 0);

    if (str.len & 0x01) {
        janet_panicf("Bad parameter length %d.", str.len);
    }

    int bin_len = str.len / 2;
    unsigned char *bin = janet_smalloc(bin_len);

    for (int i = 0; i < bin_len; i++) {
        char high_n = str.bytes[i*2];
        char low_n = str.bytes[i*2 + 1];

        int high = (high_n >= 'a') ? (high_n - 'a' + 10) :
                   (high_n >= 'A') ? (high_n - 'A' + 10) :
                   (high_n - '0');
        int low = (low_n >= 'a') ? (low_n - 'a' + 10) :
                  (low_n >= 'A') ? (low_n - 'A' + 10) :
                  (low_n - '0');

        bin[i] = (high << 4) | low;
    }

    return janet_wrap_string(janet_string(bin, bin_len));
}

void submod_utils(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("bit-and", cfun_bit_and),
        JANET_REG("bit-or", cfun_bit_or),
        JANET_REG("bit-lshift", cfun_bit_lshift),
        JANET_REG("bit-rshift", cfun_bit_rshift),
        JANET_REG("hex-encode", cfun_hex_encode),
        JANET_REG("hex-decode", cfun_hex_decode),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "", cfuns);
}
