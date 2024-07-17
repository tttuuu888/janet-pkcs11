/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include "main.h"
#include "types.h"

p11_attr_type_t get_attribute_type(CK_ATTRIBUTE_TYPE type) {
    switch (type) {
        /* Boolean attributes */
        case CKA_TOKEN:
        case CKA_PRIVATE:
        case CKA_TRUSTED:
        case CKA_SENSITIVE:
        case CKA_ENCRYPT:
        case CKA_DECRYPT:
        case CKA_WRAP:
        case CKA_UNWRAP:
        case CKA_SIGN:
        case CKA_SIGN_RECOVER:
        case CKA_VERIFY:
        case CKA_VERIFY_RECOVER:
        case CKA_DERIVE:
        case CKA_EXTRACTABLE:
        case CKA_LOCAL:
        case CKA_NEVER_EXTRACTABLE:
        case CKA_ALWAYS_SENSITIVE:
        case CKA_MODIFIABLE:
        case CKA_COPYABLE:
        case CKA_DESTROYABLE:
        case CKA_ALWAYS_AUTHENTICATE:
            return P11_ATTR_BOOL;

        /* CK_ULONG attributes */
        case CKA_CERTIFICATE_TYPE:
        case CKA_CERTIFICATE_CATEGORY:
        case CKA_MECHANISM_TYPE:
        case CKA_KEY_TYPE:
        case CKA_KEY_GEN_MECHANISM:
        case CKA_CLASS:
        case CKA_VALUE_BITS:
        case CKA_VALUE_LEN:
            return P11_ATTR_ULONG;

        /* Date attributes */
        case CKA_START_DATE:
        case CKA_END_DATE:
            return P11_ATTR_DATE;

        /* Byte array attributes */
        case CKA_VALUE:
        case CKA_OBJECT_ID:
        case CKA_SUBJECT:
        case CKA_ID:
        case CKA_ISSUER:
        case CKA_SERIAL_NUMBER:
        case CKA_WRAP_TEMPLATE:
        case CKA_UNWRAP_TEMPLATE:
        case CKA_DERIVE_TEMPLATE:
        case CKA_MODULUS:
        case CKA_MODULUS_BITS:
        case CKA_PUBLIC_EXPONENT:
        case CKA_PRIVATE_EXPONENT:
        case CKA_PRIME_1:
        case CKA_PRIME_2:
        case CKA_EXPONENT_1:
        case CKA_EXPONENT_2:
        case CKA_COEFFICIENT:
        case CKA_PRIME:
        case CKA_SUBPRIME:
        case CKA_BASE:
        case CKA_PRIME_BITS:
        case CKA_SUB_PRIME_BITS:
        case CKA_EC_PARAMS:
        case CKA_EC_POINT:
        case CKA_SECONDARY_AUTH:
        case CKA_AUTH_PIN_FLAGS:
        case CKA_WRAP_WITH_TRUSTED:
        case CKA_HW_FEATURE_TYPE:
        case CKA_RESET_ON_INIT:
        case CKA_HAS_RESET:
        case CKA_PIXEL_X:
        case CKA_PIXEL_Y:
        case CKA_RESOLUTION:
        case CKA_CHAR_ROWS:
        case CKA_CHAR_COLUMNS:
        case CKA_COLOR:
        case CKA_BITS_PER_PIXEL:
        case CKA_CHAR_SETS:
        case CKA_ENCODING_METHODS:
        case CKA_MIME_TYPES:
        case CKA_REQUIRED_CMS_ATTRIBUTES:
        case CKA_DEFAULT_CMS_ATTRIBUTES:
        case CKA_SUPPORTED_CMS_ATTRIBUTES:
        case CKA_ALLOWED_MECHANISMS:
            return P11_ATTR_BYTES;

        /* String attributes (null-terminated) */
        case CKA_LABEL:
        case CKA_APPLICATION:
            return P11_ATTR_STRING;

        default:
            janet_panicf("0x%0x type is not found", type);
    }

    return P11_ATTR_STRING;
}

const char *p11_attr_type_to_string(CK_ATTRIBUTE_TYPE type) {
    switch(type) {
        case CKA_CLASS: return "CKA_CLASS";
        case CKA_TOKEN: return "CKA_TOKEN";
        case CKA_PRIVATE: return "CKA_PRIVATE";
        case CKA_LABEL: return "CKA_LABEL";
        case CKA_APPLICATION: return "CKA_APPLICATION";
        case CKA_VALUE: return "CKA_VALUE";
        case CKA_OBJECT_ID: return "CKA_OBJECT_ID";
        case CKA_CERTIFICATE_TYPE: return "CKA_CERTIFICATE_TYPE";
        case CKA_ISSUER: return "CKA_ISSUER";
        case CKA_SERIAL_NUMBER: return "CKA_SERIAL_NUMBER";
        case CKA_AC_ISSUER: return "CKA_AC_ISSUER";
        case CKA_OWNER: return "CKA_OWNER";
        case CKA_ATTR_TYPES: return "CKA_ATTR_TYPES";
        case CKA_TRUSTED: return "CKA_TRUSTED";
        case CKA_CERTIFICATE_CATEGORY: return "CKA_CERTIFICATE_CATEGORY";
        case CKA_JAVA_MIDP_SECURITY_DOMAIN: return "CKA_JAVA_MIDP_SECURITY_DOMAIN";
        case CKA_URL: return "CKA_URL";
        case CKA_HASH_OF_SUBJECT_PUBLIC_KEY: return "CKA_HASH_OF_SUBJECT_PUBLIC_KEY";
        case CKA_HASH_OF_ISSUER_PUBLIC_KEY: return "CKA_HASH_OF_ISSUER_PUBLIC_KEY";
        case CKA_NAME_HASH_ALGORITHM: return "CKA_NAME_HASH_ALGORITHM";
        case CKA_CHECK_VALUE: return "CKA_CHECK_VALUE";
        case CKA_KEY_TYPE: return "CKA_KEY_TYPE";
        case CKA_SUBJECT: return "CKA_SUBJECT";
        case CKA_ID: return "CKA_ID";
        case CKA_SENSITIVE: return "CKA_SENSITIVE";
        case CKA_ENCRYPT: return "CKA_ENCRYPT";
        case CKA_DECRYPT: return "CKA_DECRYPT";
        case CKA_WRAP: return "CKA_WRAP";
        case CKA_UNWRAP: return "CKA_UNWRAP";
        case CKA_SIGN: return "CKA_SIGN";
        case CKA_SIGN_RECOVER: return "CKA_SIGN_RECOVER";
        case CKA_VERIFY: return "CKA_VERIFY";
        case CKA_VERIFY_RECOVER: return "CKA_VERIFY_RECOVER";
        case CKA_DERIVE: return "CKA_DERIVE";
        case CKA_START_DATE: return "CKA_START_DATE";
        case CKA_END_DATE: return "CKA_END_DATE";
        case CKA_MODULUS: return "CKA_MODULUS";
        case CKA_MODULUS_BITS: return "CKA_MODULUS_BITS";
        case CKA_PUBLIC_EXPONENT: return "CKA_PUBLIC_EXPONENT";
        case CKA_PRIVATE_EXPONENT: return "CKA_PRIVATE_EXPONENT";
        case CKA_PRIME_2: return "CKA_PRIME_2";
        case CKA_EXPONENT_2: return "CKA_EXPONENT_2";
        case CKA_COEFFICIENT: return "CKA_COEFFICIENT";
        case CKA_PRIME: return "CKA_PRIME";
        case CKA_SUBPRIME: return "CKA_SUBPRIME";
        case CKA_BASE: return "CKA_BASE";
        case CKA_PRIME_BITS: return "CKA_PRIME_BITS";
        case CKA_VALUE_BITS: return "CKA_VALUE_BITS";
        case CKA_VALUE_LEN: return "CKA_VALUE_LEN";
        case CKA_EXTRACTABLE: return "CKA_EXTRACTABLE";
        case CKA_LOCAL: return "CKA_LOCAL";
        case CKA_NEVER_EXTRACTABLE: return "CKA_NEVER_EXTRACTABLE";
        case CKA_ALWAYS_SENSITIVE: return "CKA_ALWAYS_SENSITIVE";
        case CKA_KEY_GEN_MECHANISM: return "CKA_KEY_GEN_MECHANISM";
        case CKA_MODIFIABLE: return "CKA_MODIFIABLE";
        case CKA_COPYABLE: return "CKA_COPYABLE";
        case CKA_DESTROYABLE: return "CKA_DESTROYABLE";
        case CKA_EC_PARAMS: return "CKA_EC_PARAMS";
        case CKA_EC_POINT: return "CKA_EC_POINT";
        case CKA_ALWAYS_AUTHENTICATE: return "CKA_ALWAYS_AUTHENTICATE";
        case CKA_WRAP_WITH_TRUSTED: return "CKA_WRAP_WITH_TRUSTED";
        case CKA_WRAP_TEMPLATE: return "CKA_WRAP_TEMPLATE";
        case CKA_UNWRAP_TEMPLATE: return "CKA_UNWRAP_TEMPLATE";
        case CKA_HW_FEATURE_TYPE: return "CKA_HW_FEATURE_TYPE";
        case CKA_RESET_ON_INIT: return "CKA_RESET_ON_INIT";
        case CKA_HAS_RESET: return "CKA_HAS_RESET";
        case CKA_PIXEL_X: return "CKA_PIXEL_X";
        case CKA_PIXEL_Y: return "CKA_PIXEL_Y";
        case CKA_RESOLUTION: return "CKA_RESOLUTION";
        case CKA_CHAR_ROWS: return "CKA_CHAR_ROWS";
        case CKA_CHAR_COLUMNS: return "CKA_CHAR_COLUMNS";
        case CKA_COLOR: return "CKA_COLOR";
        case CKA_BITS_PER_PIXEL: return "CKA_BITS_PER_PIXEL";
        case CKA_CHAR_SETS: return "CKA_CHAR_SETS";
        case CKA_ENCODING_METHODS: return "CKA_ENCODING_METHODS";
        case CKA_MIME_TYPES: return "CKA_MIME_TYPES";
        case CKA_MECHANISM_TYPE: return "CKA_MECHANISM_TYPE";
        case CKA_REQUIRED_CMS_ATTRIBUTES: return "CKA_REQUIRED_CMS_ATTRIBUTES";
        case CKA_DEFAULT_CMS_ATTRIBUTES: return "CKA_DEFAULT_CMS_ATTRIBUTES";
        case CKA_SUPPORTED_CMS_ATTRIBUTES: return "CKA_SUPPORTED_CMS_ATTRIBUTES";
        case CKA_ALLOWED_MECHANISMS: return "CKA_ALLOWED_MECHANISMS";
        case CKA_VENDOR_DEFINED: return "CKA_VENDOR_DEFINED";
        default:
            janet_panicf("0x%lx type is not found.", type);
    }
}

void submod_types(JanetTable *env) {
    JANET_DEF(env, "CK_INVALID_HANDLE", janet_wrap_number((double)CK_INVALID_HANDLE), "PKCS11 define");

    JANET_DEF(env, "CKN_SURRENDER", janet_wrap_number((double)CKN_SURRENDER), "PKCS11 define");

    JANET_DEF(env, "CK_UNAVAILABLE_INFORMATION", janet_wrap_number((double)CK_UNAVAILABLE_INFORMATION), "PKCS11 define");
    JANET_DEF(env, "CK_EFFECTIVELY_INFINITE", janet_wrap_number((double)CK_EFFECTIVELY_INFINITE), "PKCS11 define");

    JANET_DEF(env, "CKF_DONT_BLOCK", janet_wrap_number((double)CKF_DONT_BLOCK), "PKCS11 define");

    JANET_DEF(env, "CKF_ARRAY_ATTRIBUTE", janet_wrap_number((double)CKF_ARRAY_ATTRIBUTE), "PKCS11 define");

    JANET_DEF(env, "CKU_SO", janet_wrap_number((double)CKU_SO), "PKCS11 define");
    JANET_DEF(env, "CKU_USER", janet_wrap_number((double)CKU_USER), "PKCS11 define");
    JANET_DEF(env, "CKU_CONTEXT_SPECIFIC", janet_wrap_number((double)CKU_CONTEXT_SPECIFIC), "PKCS11 define");

    JANET_DEF(env, "CKS_RO_PUBLIC_SESSION", janet_wrap_number((double)CKS_RO_PUBLIC_SESSION), "PKCS11 define");
    JANET_DEF(env, "CKS_RO_USER_FUNCTIONS", janet_wrap_number((double)CKS_RO_USER_FUNCTIONS), "PKCS11 define");
    JANET_DEF(env, "CKS_RW_PUBLIC_SESSION", janet_wrap_number((double)CKS_RW_PUBLIC_SESSION), "PKCS11 define");
    JANET_DEF(env, "CKS_RW_USER_FUNCTIONS", janet_wrap_number((double)CKS_RW_USER_FUNCTIONS), "PKCS11 define");
    JANET_DEF(env, "CKS_RW_SO_FUNCTIONS", janet_wrap_number((double)CKS_RW_SO_FUNCTIONS), "PKCS11 define");

    JANET_DEF(env, "CKO_DATA", janet_wrap_number((double)CKO_DATA), "PKCS11 define");
    JANET_DEF(env, "CKO_CERTIFICATE", janet_wrap_number((double)CKO_CERTIFICATE), "PKCS11 define");
    JANET_DEF(env, "CKO_PUBLIC_KEY", janet_wrap_number((double)CKO_PUBLIC_KEY), "PKCS11 define");
    JANET_DEF(env, "CKO_PRIVATE_KEY", janet_wrap_number((double)CKO_PRIVATE_KEY), "PKCS11 define");
    JANET_DEF(env, "CKO_SECRET_KEY", janet_wrap_number((double)CKO_SECRET_KEY), "PKCS11 define");
    JANET_DEF(env, "CKO_HW_FEATURE", janet_wrap_number((double)CKO_HW_FEATURE), "PKCS11 define");
    JANET_DEF(env, "CKO_DOMAIN_PARAMETERS", janet_wrap_number((double)CKO_DOMAIN_PARAMETERS), "PKCS11 define");
    JANET_DEF(env, "CKO_MECHANISM", janet_wrap_number((double)CKO_MECHANISM), "PKCS11 define");
    JANET_DEF(env, "CKO_VENDOR_DEFINED", janet_wrap_number((double)CKO_VENDOR_DEFINED), "PKCS11 define");

    JANET_DEF(env, "CKH_MONOTONIC_COUNTER", janet_wrap_number((double)CKH_MONOTONIC_COUNTER), "PKCS11 define");
    JANET_DEF(env, "CKH_CLOCK", janet_wrap_number((double)CKH_CLOCK), "PKCS11 define");
    JANET_DEF(env, "CKH_USER_INTERFACE", janet_wrap_number((double)CKH_USER_INTERFACE), "PKCS11 define");
    JANET_DEF(env, "CKH_VENDOR_DEFINED", janet_wrap_number((double)CKH_VENDOR_DEFINED), "PKCS11 define");

    JANET_DEF(env, "CKA_CLASS", janet_wrap_number((double)CKA_CLASS), "PKCS11 define");
    JANET_DEF(env, "CKA_TOKEN", janet_wrap_number((double)CKA_TOKEN), "PKCS11 define");
    JANET_DEF(env, "CKA_PRIVATE", janet_wrap_number((double)CKA_PRIVATE), "PKCS11 define");
    JANET_DEF(env, "CKA_LABEL", janet_wrap_number((double)CKA_LABEL), "PKCS11 define");
    JANET_DEF(env, "CKA_APPLICATION", janet_wrap_number((double)CKA_APPLICATION), "PKCS11 define");
    JANET_DEF(env, "CKA_VALUE", janet_wrap_number((double)CKA_VALUE), "PKCS11 define");
    JANET_DEF(env, "CKA_OBJECT_ID", janet_wrap_number((double)CKA_OBJECT_ID), "PKCS11 define");
    JANET_DEF(env, "CKA_CERTIFICATE_TYPE", janet_wrap_number((double)CKA_CERTIFICATE_TYPE), "PKCS11 define");
    JANET_DEF(env, "CKA_ISSUER", janet_wrap_number((double)CKA_ISSUER), "PKCS11 define");
    JANET_DEF(env, "CKA_SERIAL_NUMBER", janet_wrap_number((double)CKA_SERIAL_NUMBER), "PKCS11 define");
    JANET_DEF(env, "CKA_AC_ISSUER", janet_wrap_number((double)CKA_AC_ISSUER), "PKCS11 define");
    JANET_DEF(env, "CKA_OWNER", janet_wrap_number((double)CKA_OWNER), "PKCS11 define");
    JANET_DEF(env, "CKA_ATTR_TYPES", janet_wrap_number((double)CKA_ATTR_TYPES), "PKCS11 define");
    JANET_DEF(env, "CKA_TRUSTED", janet_wrap_number((double)CKA_TRUSTED), "PKCS11 define");
    JANET_DEF(env, "CKA_CERTIFICATE_CATEGORY", janet_wrap_number((double)CKA_CERTIFICATE_CATEGORY), "PKCS11 define");
    JANET_DEF(env, "CKA_JAVA_MIDP_SECURITY_DOMAIN", janet_wrap_number((double)CKA_JAVA_MIDP_SECURITY_DOMAIN), "PKCS11 define");
    JANET_DEF(env, "CKA_URL", janet_wrap_number((double)CKA_URL), "PKCS11 define");
    JANET_DEF(env, "CKA_HASH_OF_SUBJECT_PUBLIC_KEY", janet_wrap_number((double)CKA_HASH_OF_SUBJECT_PUBLIC_KEY), "PKCS11 define");
    JANET_DEF(env, "CKA_HASH_OF_ISSUER_PUBLIC_KEY", janet_wrap_number((double)CKA_HASH_OF_ISSUER_PUBLIC_KEY), "PKCS11 define");
    JANET_DEF(env, "CKA_NAME_HASH_ALGORITHM", janet_wrap_number((double)CKA_NAME_HASH_ALGORITHM), "PKCS11 define");
    JANET_DEF(env, "CKA_CHECK_VALUE", janet_wrap_number((double)CKA_CHECK_VALUE), "PKCS11 define");
    JANET_DEF(env, "CKA_KEY_TYPE", janet_wrap_number((double)CKA_KEY_TYPE), "PKCS11 define");
    JANET_DEF(env, "CKA_SUBJECT", janet_wrap_number((double)CKA_SUBJECT), "PKCS11 define");
    JANET_DEF(env, "CKA_ID", janet_wrap_number((double)CKA_ID), "PKCS11 define");
    JANET_DEF(env, "CKA_SENSITIVE", janet_wrap_number((double)CKA_SENSITIVE), "PKCS11 define");
    JANET_DEF(env, "CKA_ENCRYPT", janet_wrap_number((double)CKA_ENCRYPT), "PKCS11 define");
    JANET_DEF(env, "CKA_DECRYPT", janet_wrap_number((double)CKA_DECRYPT), "PKCS11 define");
    JANET_DEF(env, "CKA_WRAP", janet_wrap_number((double)CKA_WRAP), "PKCS11 define");
    JANET_DEF(env, "CKA_UNWRAP", janet_wrap_number((double)CKA_UNWRAP), "PKCS11 define");
    JANET_DEF(env, "CKA_SIGN", janet_wrap_number((double)CKA_SIGN), "PKCS11 define");
    JANET_DEF(env, "CKA_SIGN_RECOVER", janet_wrap_number((double)CKA_SIGN_RECOVER), "PKCS11 define");
    JANET_DEF(env, "CKA_VERIFY", janet_wrap_number((double)CKA_VERIFY), "PKCS11 define");
    JANET_DEF(env, "CKA_VERIFY_RECOVER", janet_wrap_number((double)CKA_VERIFY_RECOVER), "PKCS11 define");
    JANET_DEF(env, "CKA_DERIVE", janet_wrap_number((double)CKA_DERIVE), "PKCS11 define");
    JANET_DEF(env, "CKA_START_DATE", janet_wrap_number((double)CKA_START_DATE), "PKCS11 define");
    JANET_DEF(env, "CKA_END_DATE", janet_wrap_number((double)CKA_END_DATE), "PKCS11 define");
    JANET_DEF(env, "CKA_MODULUS", janet_wrap_number((double)CKA_MODULUS), "PKCS11 define");
    JANET_DEF(env, "CKA_MODULUS_BITS", janet_wrap_number((double)CKA_MODULUS_BITS), "PKCS11 define");
    JANET_DEF(env, "CKA_PUBLIC_EXPONENT", janet_wrap_number((double)CKA_PUBLIC_EXPONENT), "PKCS11 define");
    JANET_DEF(env, "CKA_PRIVATE_EXPONENT", janet_wrap_number((double)CKA_PRIVATE_EXPONENT), "PKCS11 define");
    JANET_DEF(env, "CKA_PRIME_CKA_PRIME_1", janet_wrap_number((double)1), "PKCS11 define");
    JANET_DEF(env, "CKA_PRIME_2", janet_wrap_number((double)CKA_PRIME_2), "PKCS11 define");
    JANET_DEF(env, "CKA_EXPONENT_CKA_EXPONENT_1", janet_wrap_number((double)1), "PKCS11 define");
    JANET_DEF(env, "CKA_EXPONENT_2", janet_wrap_number((double)CKA_EXPONENT_2), "PKCS11 define");
    JANET_DEF(env, "CKA_COEFFICIENT", janet_wrap_number((double)CKA_COEFFICIENT), "PKCS11 define");
    JANET_DEF(env, "CKA_PRIME", janet_wrap_number((double)CKA_PRIME), "PKCS11 define");
    JANET_DEF(env, "CKA_SUBPRIME", janet_wrap_number((double)CKA_SUBPRIME), "PKCS11 define");
    JANET_DEF(env, "CKA_BASE", janet_wrap_number((double)CKA_BASE), "PKCS11 define");
    JANET_DEF(env, "CKA_PRIME_BITS", janet_wrap_number((double)CKA_PRIME_BITS), "PKCS11 define");
    JANET_DEF(env, "CKA_VALUE_BITS", janet_wrap_number((double)CKA_VALUE_BITS), "PKCS11 define");
    JANET_DEF(env, "CKA_VALUE_LEN", janet_wrap_number((double)CKA_VALUE_LEN), "PKCS11 define");
    JANET_DEF(env, "CKA_EXTRACTABLE", janet_wrap_number((double)CKA_EXTRACTABLE), "PKCS11 define");
    JANET_DEF(env, "CKA_LOCAL", janet_wrap_number((double)CKA_LOCAL), "PKCS11 define");
    JANET_DEF(env, "CKA_NEVER_EXTRACTABLE", janet_wrap_number((double)CKA_NEVER_EXTRACTABLE), "PKCS11 define");
    JANET_DEF(env, "CKA_ALWAYS_SENSITIVE", janet_wrap_number((double)CKA_ALWAYS_SENSITIVE), "PKCS11 define");
    JANET_DEF(env, "CKA_KEY_GEN_MECHANISM", janet_wrap_number((double)CKA_KEY_GEN_MECHANISM), "PKCS11 define");
    JANET_DEF(env, "CKA_MODIFIABLE", janet_wrap_number((double)CKA_MODIFIABLE), "PKCS11 define");
    JANET_DEF(env, "CKA_COPYABLE", janet_wrap_number((double)CKA_COPYABLE), "PKCS11 define");
    JANET_DEF(env, "CKA_DESTROYABLE", janet_wrap_number((double)CKA_DESTROYABLE), "PKCS11 define");
    JANET_DEF(env, "CKA_EC_PARAMS", janet_wrap_number((double)CKA_EC_PARAMS), "PKCS11 define");
    JANET_DEF(env, "CKA_EC_POINT", janet_wrap_number((double)CKA_EC_POINT), "PKCS11 define");
    JANET_DEF(env, "CKA_ALWAYS_AUTHENTICATE", janet_wrap_number((double)CKA_ALWAYS_AUTHENTICATE), "PKCS11 define");

    JANET_DEF(env, "CKA_WRAP_WITH_TRUSTED", janet_wrap_number((double)CKA_WRAP_WITH_TRUSTED), "PKCS11 define");
    JANET_DEF(env, "CKA_WRAP_TEMPLATE", janet_wrap_number((double)CKA_WRAP_TEMPLATE), "PKCS11 define");
    JANET_DEF(env, "CKA_UNWRAP_TEMPLATE", janet_wrap_number((double)CKA_UNWRAP_TEMPLATE), "PKCS11 define");
    JANET_DEF(env, "CKA_HW_FEATURE_TYPE", janet_wrap_number((double)CKA_HW_FEATURE_TYPE), "PKCS11 define");
    JANET_DEF(env, "CKA_RESET_ON_INIT", janet_wrap_number((double)CKA_RESET_ON_INIT), "PKCS11 define");
    JANET_DEF(env, "CKA_HAS_RESET", janet_wrap_number((double)CKA_HAS_RESET), "PKCS11 define");
    JANET_DEF(env, "CKA_PIXEL_X", janet_wrap_number((double)CKA_PIXEL_X), "PKCS11 define");
    JANET_DEF(env, "CKA_PIXEL_Y", janet_wrap_number((double)CKA_PIXEL_Y), "PKCS11 define");
    JANET_DEF(env, "CKA_RESOLUTION", janet_wrap_number((double)CKA_RESOLUTION), "PKCS11 define");
    JANET_DEF(env, "CKA_CHAR_ROWS", janet_wrap_number((double)CKA_CHAR_ROWS), "PKCS11 define");
    JANET_DEF(env, "CKA_CHAR_COLUMNS", janet_wrap_number((double)CKA_CHAR_COLUMNS), "PKCS11 define");
    JANET_DEF(env, "CKA_COLOR", janet_wrap_number((double)CKA_COLOR), "PKCS11 define");
    JANET_DEF(env, "CKA_BITS_PER_PIXEL", janet_wrap_number((double)CKA_BITS_PER_PIXEL), "PKCS11 define");
    JANET_DEF(env, "CKA_CHAR_SETS", janet_wrap_number((double)CKA_CHAR_SETS), "PKCS11 define");
    JANET_DEF(env, "CKA_ENCODING_METHODS", janet_wrap_number((double)CKA_ENCODING_METHODS), "PKCS11 define");
    JANET_DEF(env, "CKA_MIME_TYPES", janet_wrap_number((double)CKA_MIME_TYPES), "PKCS11 define");
    JANET_DEF(env, "CKA_MECHANISM_TYPE", janet_wrap_number((double)CKA_MECHANISM_TYPE), "PKCS11 define");
    JANET_DEF(env, "CKA_REQUIRED_CMS_ATTRIBUTES", janet_wrap_number((double)CKA_REQUIRED_CMS_ATTRIBUTES), "PKCS11 define");
    JANET_DEF(env, "CKA_DEFAULT_CMS_ATTRIBUTES", janet_wrap_number((double)CKA_DEFAULT_CMS_ATTRIBUTES), "PKCS11 define");
    JANET_DEF(env, "CKA_SUPPORTED_CMS_ATTRIBUTES", janet_wrap_number((double)CKA_SUPPORTED_CMS_ATTRIBUTES), "PKCS11 define");
    JANET_DEF(env, "CKA_ALLOWED_MECHANISMS", janet_wrap_number((double)CKA_ALLOWED_MECHANISMS), "PKCS11 define");
    JANET_DEF(env, "CKA_VENDOR_DEFINED", janet_wrap_number((double)CKA_VENDOR_DEFINED), "PKCS11 define");

    JANET_DEF(env, "CKR_OK", janet_wrap_number((double)CKR_OK), "PKCS11 define");
    JANET_DEF(env, "CKR_CANCEL", janet_wrap_number((double)CKR_CANCEL), "PKCS11 define");
    JANET_DEF(env, "CKR_HOST_MEMORY", janet_wrap_number((double)CKR_HOST_MEMORY), "PKCS11 define");
    JANET_DEF(env, "CKR_SLOT_ID_INVALID", janet_wrap_number((double)CKR_SLOT_ID_INVALID), "PKCS11 define");
    JANET_DEF(env, "CKR_GENERAL_ERROR", janet_wrap_number((double)CKR_GENERAL_ERROR), "PKCS11 define");
    JANET_DEF(env, "CKR_FUNCTION_FAILED", janet_wrap_number((double)CKR_FUNCTION_FAILED), "PKCS11 define");
    JANET_DEF(env, "CKR_ARGUMENTS_BAD", janet_wrap_number((double)CKR_ARGUMENTS_BAD), "PKCS11 define");
    JANET_DEF(env, "CKR_NO_EVENT", janet_wrap_number((double)CKR_NO_EVENT), "PKCS11 define");
    JANET_DEF(env, "CKR_NEED_TO_CREATE_THREADS", janet_wrap_number((double)CKR_NEED_TO_CREATE_THREADS), "PKCS11 define");
    JANET_DEF(env, "CKR_CANT_LOCK", janet_wrap_number((double)CKR_CANT_LOCK), "PKCS11 define");
    JANET_DEF(env, "CKR_ATTRIBUTE_READ_ONLY", janet_wrap_number((double)CKR_ATTRIBUTE_READ_ONLY), "PKCS11 define");
    JANET_DEF(env, "CKR_ATTRIBUTE_SENSITIVE", janet_wrap_number((double)CKR_ATTRIBUTE_SENSITIVE), "PKCS11 define");
    JANET_DEF(env, "CKR_ATTRIBUTE_TYPE_INVALID", janet_wrap_number((double)CKR_ATTRIBUTE_TYPE_INVALID), "PKCS11 define");
    JANET_DEF(env, "CKR_ATTRIBUTE_VALUE_INVALID", janet_wrap_number((double)CKR_ATTRIBUTE_VALUE_INVALID), "PKCS11 define");
    JANET_DEF(env, "CKR_ACTION_PROHIBITED", janet_wrap_number((double)CKR_ACTION_PROHIBITED), "PKCS11 define");
    JANET_DEF(env, "CKR_DATA_INVALID", janet_wrap_number((double)CKR_DATA_INVALID), "PKCS11 define");
    JANET_DEF(env, "CKR_DATA_LEN_RANGE", janet_wrap_number((double)CKR_DATA_LEN_RANGE), "PKCS11 define");
    JANET_DEF(env, "CKR_DEVICE_ERROR", janet_wrap_number((double)CKR_DEVICE_ERROR), "PKCS11 define");
    JANET_DEF(env, "CKR_DEVICE_MEMORY", janet_wrap_number((double)CKR_DEVICE_MEMORY), "PKCS11 define");
    JANET_DEF(env, "CKR_DEVICE_REMOVED", janet_wrap_number((double)CKR_DEVICE_REMOVED), "PKCS11 define");
    JANET_DEF(env, "CKR_ENCRYPTED_DATA_INVALID", janet_wrap_number((double)CKR_ENCRYPTED_DATA_INVALID), "PKCS11 define");
    JANET_DEF(env, "CKR_ENCRYPTED_DATA_LEN_RANGE", janet_wrap_number((double)CKR_ENCRYPTED_DATA_LEN_RANGE), "PKCS11 define");
    JANET_DEF(env, "CKR_FUNCTION_CANCELED", janet_wrap_number((double)CKR_FUNCTION_CANCELED), "PKCS11 define");
    JANET_DEF(env, "CKR_FUNCTION_NOT_PARALLEL", janet_wrap_number((double)CKR_FUNCTION_NOT_PARALLEL), "PKCS11 define");
    JANET_DEF(env, "CKR_FUNCTION_NOT_SUPPORTED", janet_wrap_number((double)CKR_FUNCTION_NOT_SUPPORTED), "PKCS11 define");
    JANET_DEF(env, "CKR_KEY_HANDLE_INVALID", janet_wrap_number((double)CKR_KEY_HANDLE_INVALID), "PKCS11 define");
    JANET_DEF(env, "CKR_KEY_SIZE_RANGE", janet_wrap_number((double)CKR_KEY_SIZE_RANGE), "PKCS11 define");
    JANET_DEF(env, "CKR_KEY_TYPE_INCONSISTENT", janet_wrap_number((double)CKR_KEY_TYPE_INCONSISTENT), "PKCS11 define");
    JANET_DEF(env, "CKR_KEY_NOT_NEEDED", janet_wrap_number((double)CKR_KEY_NOT_NEEDED), "PKCS11 define");
    JANET_DEF(env, "CKR_KEY_CHANGED", janet_wrap_number((double)CKR_KEY_CHANGED), "PKCS11 define");
    JANET_DEF(env, "CKR_KEY_NEEDED", janet_wrap_number((double)CKR_KEY_NEEDED), "PKCS11 define");
    JANET_DEF(env, "CKR_KEY_INDIGESTIBLE", janet_wrap_number((double)CKR_KEY_INDIGESTIBLE), "PKCS11 define");
    JANET_DEF(env, "CKR_KEY_FUNCTION_NOT_PERMITTED", janet_wrap_number((double)CKR_KEY_FUNCTION_NOT_PERMITTED), "PKCS11 define");
    JANET_DEF(env, "CKR_KEY_NOT_WRAPPABLE", janet_wrap_number((double)CKR_KEY_NOT_WRAPPABLE), "PKCS11 define");
    JANET_DEF(env, "CKR_KEY_UNEXTRACTABLE", janet_wrap_number((double)CKR_KEY_UNEXTRACTABLE), "PKCS11 define");
    JANET_DEF(env, "CKR_MECHANISM_INVALID", janet_wrap_number((double)CKR_MECHANISM_INVALID), "PKCS11 define");
    JANET_DEF(env, "CKR_MECHANISM_PARAM_INVALID", janet_wrap_number((double)CKR_MECHANISM_PARAM_INVALID), "PKCS11 define");
    JANET_DEF(env, "CKR_OBJECT_HANDLE_INVALID", janet_wrap_number((double)CKR_OBJECT_HANDLE_INVALID), "PKCS11 define");
    JANET_DEF(env, "CKR_OPERATION_ACTIVE", janet_wrap_number((double)CKR_OPERATION_ACTIVE), "PKCS11 define");
    JANET_DEF(env, "CKR_OPERATION_NOT_INITIALIZED", janet_wrap_number((double)CKR_OPERATION_NOT_INITIALIZED), "PKCS11 define");
    JANET_DEF(env, "CKR_PIN_INCORRECT", janet_wrap_number((double)CKR_PIN_INCORRECT), "PKCS11 define");
    JANET_DEF(env, "CKR_PIN_INVALID", janet_wrap_number((double)CKR_PIN_INVALID), "PKCS11 define");
    JANET_DEF(env, "CKR_PIN_LEN_RANGE", janet_wrap_number((double)CKR_PIN_LEN_RANGE), "PKCS11 define");
    JANET_DEF(env, "CKR_PIN_EXPIRED", janet_wrap_number((double)CKR_PIN_EXPIRED), "PKCS11 define");
    JANET_DEF(env, "CKR_PIN_LOCKED", janet_wrap_number((double)CKR_PIN_LOCKED), "PKCS11 define");
    JANET_DEF(env, "CKR_SESSION_CLOSED", janet_wrap_number((double)CKR_SESSION_CLOSED), "PKCS11 define");
    JANET_DEF(env, "CKR_SESSION_COUNT", janet_wrap_number((double)CKR_SESSION_COUNT), "PKCS11 define");
    JANET_DEF(env, "CKR_SESSION_HANDLE_INVALID", janet_wrap_number((double)CKR_SESSION_HANDLE_INVALID), "PKCS11 define");
    JANET_DEF(env, "CKR_SESSION_PARALLEL_NOT_SUPPORTED", janet_wrap_number((double)CKR_SESSION_PARALLEL_NOT_SUPPORTED), "PKCS11 define");
    JANET_DEF(env, "CKR_SESSION_READ_ONLY", janet_wrap_number((double)CKR_SESSION_READ_ONLY), "PKCS11 define");
    JANET_DEF(env, "CKR_SESSION_EXISTS", janet_wrap_number((double)CKR_SESSION_EXISTS), "PKCS11 define");
    JANET_DEF(env, "CKR_SESSION_READ_ONLY_EXISTS", janet_wrap_number((double)CKR_SESSION_READ_ONLY_EXISTS), "PKCS11 define");
    JANET_DEF(env, "CKR_SESSION_READ_WRITE_SO_EXISTS", janet_wrap_number((double)CKR_SESSION_READ_WRITE_SO_EXISTS), "PKCS11 define");
    JANET_DEF(env, "CKR_SIGNATURE_INVALID", janet_wrap_number((double)CKR_SIGNATURE_INVALID), "PKCS11 define");
    JANET_DEF(env, "CKR_SIGNATURE_LEN_RANGE", janet_wrap_number((double)CKR_SIGNATURE_LEN_RANGE), "PKCS11 define");
    JANET_DEF(env, "CKR_TEMPLATE_INCOMPLETE", janet_wrap_number((double)CKR_TEMPLATE_INCOMPLETE), "PKCS11 define");
    JANET_DEF(env, "CKR_TEMPLATE_INCONSISTENT", janet_wrap_number((double)CKR_TEMPLATE_INCONSISTENT), "PKCS11 define");
    JANET_DEF(env, "CKR_TOKEN_NOT_PRESENT", janet_wrap_number((double)CKR_TOKEN_NOT_PRESENT), "PKCS11 define");
    JANET_DEF(env, "CKR_TOKEN_NOT_RECOGNIZED", janet_wrap_number((double)CKR_TOKEN_NOT_RECOGNIZED), "PKCS11 define");
    JANET_DEF(env, "CKR_TOKEN_WRITE_PROTECTED", janet_wrap_number((double)CKR_TOKEN_WRITE_PROTECTED), "PKCS11 define");
    JANET_DEF(env, "CKR_UNWRAPPING_KEY_HANDLE_INVALID", janet_wrap_number((double)CKR_UNWRAPPING_KEY_HANDLE_INVALID), "PKCS11 define");
    JANET_DEF(env, "CKR_UNWRAPPING_KEY_SIZE_RANGE", janet_wrap_number((double)CKR_UNWRAPPING_KEY_SIZE_RANGE), "PKCS11 define");
    JANET_DEF(env, "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT", janet_wrap_number((double)CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT), "PKCS11 define");
    JANET_DEF(env, "CKR_USER_ALREADY_LOGGED_IN", janet_wrap_number((double)CKR_USER_ALREADY_LOGGED_IN), "PKCS11 define");
    JANET_DEF(env, "CKR_USER_NOT_LOGGED_IN", janet_wrap_number((double)CKR_USER_NOT_LOGGED_IN), "PKCS11 define");
    JANET_DEF(env, "CKR_USER_PIN_NOT_INITIALIZED", janet_wrap_number((double)CKR_USER_PIN_NOT_INITIALIZED), "PKCS11 define");
    JANET_DEF(env, "CKR_USER_TYPE_INVALID", janet_wrap_number((double)CKR_USER_TYPE_INVALID), "PKCS11 define");
    JANET_DEF(env, "CKR_USER_ANOTHER_ALREADY_LOGGED_IN", janet_wrap_number((double)CKR_USER_ANOTHER_ALREADY_LOGGED_IN), "PKCS11 define");
    JANET_DEF(env, "CKR_USER_TOO_MANY_TYPES", janet_wrap_number((double)CKR_USER_TOO_MANY_TYPES), "PKCS11 define");
    JANET_DEF(env, "CKR_WRAPPED_KEY_INVALID", janet_wrap_number((double)CKR_WRAPPED_KEY_INVALID), "PKCS11 define");
    JANET_DEF(env, "CKR_WRAPPED_KEY_LEN_RANGE", janet_wrap_number((double)CKR_WRAPPED_KEY_LEN_RANGE), "PKCS11 define");
    JANET_DEF(env, "CKR_WRAPPING_KEY_HANDLE_INVALID", janet_wrap_number((double)CKR_WRAPPING_KEY_HANDLE_INVALID), "PKCS11 define");
    JANET_DEF(env, "CKR_WRAPPING_KEY_SIZE_RANGE", janet_wrap_number((double)CKR_WRAPPING_KEY_SIZE_RANGE), "PKCS11 define");
    JANET_DEF(env, "CKR_WRAPPING_KEY_TYPE_INCONSISTENT", janet_wrap_number((double)CKR_WRAPPING_KEY_TYPE_INCONSISTENT), "PKCS11 define");
    JANET_DEF(env, "CKR_RANDOM_SEED_NOT_SUPPORTED", janet_wrap_number((double)CKR_RANDOM_SEED_NOT_SUPPORTED), "PKCS11 define");
    JANET_DEF(env, "CKR_RANDOM_NO_RNG", janet_wrap_number((double)CKR_RANDOM_NO_RNG), "PKCS11 define");
    JANET_DEF(env, "CKR_DOMAIN_PARAMS_INVALID", janet_wrap_number((double)CKR_DOMAIN_PARAMS_INVALID), "PKCS11 define");
    JANET_DEF(env, "CKR_CURVE_NOT_SUPPORTED", janet_wrap_number((double)CKR_CURVE_NOT_SUPPORTED), "PKCS11 define");
    JANET_DEF(env, "CKR_BUFFER_TOO_SMALL", janet_wrap_number((double)CKR_BUFFER_TOO_SMALL), "PKCS11 define");
    JANET_DEF(env, "CKR_SAVED_STATE_INVALID", janet_wrap_number((double)CKR_SAVED_STATE_INVALID), "PKCS11 define");
    JANET_DEF(env, "CKR_INFORMATION_SENSITIVE", janet_wrap_number((double)CKR_INFORMATION_SENSITIVE), "PKCS11 define");
    JANET_DEF(env, "CKR_STATE_UNSAVEABLE", janet_wrap_number((double)CKR_STATE_UNSAVEABLE), "PKCS11 define");
    JANET_DEF(env, "CKR_CRYPTOKI_NOT_INITIALIZED", janet_wrap_number((double)CKR_CRYPTOKI_NOT_INITIALIZED), "PKCS11 define");
    JANET_DEF(env, "CKR_CRYPTOKI_ALREADY_INITIALIZED", janet_wrap_number((double)CKR_CRYPTOKI_ALREADY_INITIALIZED), "PKCS11 define");
    JANET_DEF(env, "CKR_MUTEX_BAD", janet_wrap_number((double)CKR_MUTEX_BAD), "PKCS11 define");
    JANET_DEF(env, "CKR_MUTEX_NOT_LOCKED", janet_wrap_number((double)CKR_MUTEX_NOT_LOCKED), "PKCS11 define");
    JANET_DEF(env, "CKR_FUNCTION_REJECTED", janet_wrap_number((double)CKR_FUNCTION_REJECTED), "PKCS11 define");
    JANET_DEF(env, "CKR_VENDOR_DEFINED", janet_wrap_number((double)CKR_VENDOR_DEFINED), "PKCS11 define");
}
