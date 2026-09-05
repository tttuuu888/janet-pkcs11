/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include "main.h"
#include "utils.h"

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

static int hex_digit_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
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
        int high = hex_digit_value(str.bytes[i*2]);
        int low = hex_digit_value(str.bytes[i*2 + 1]);

        if (high < 0 || low < 0) {
            janet_panicf("invalid hex string %v", argv[0]);
        }

        bin[i] = (high << 4) | low;
    }

    return janet_wrap_string(janet_string(bin, bin_len));
}

void submod_utils(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("hex-encode", cfun_hex_encode),
        JANET_REG("hex-decode", cfun_hex_decode),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "pkcs11", cfuns);
}
