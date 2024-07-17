/*
 * Copyright (c) 2024, Janet-botan Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "main.h"
#include "types.h"

#define MAX_TYPES 200
#define HASH_SIZE 2000

typedef struct {
    const char *name;
    int value;
} TypeEntry;

TypeEntry type_table[MAX_TYPES] = {
    {"CK_INVALID_HANDLE",                    CK_INVALID_HANDLE},
    {"CKN_SURRENDER",                        CKN_SURRENDER},
    {"CK_EFFECTIVELY_INFINITE",              CK_EFFECTIVELY_INFINITE},
    {"CKF_DONT_BLOCK",                       CKF_DONT_BLOCK},
    {"CKF_ARRAY_ATTRIBUTE",                  CKF_ARRAY_ATTRIBUTE},
    {"CKU_SO",                               CKU_SO},
    {"CKU_USER",                             CKU_USER},
    {"CKU_CONTEXT_SPECIFIC",                 CKU_CONTEXT_SPECIFIC},
    {"CKS_RO_PUBLIC_SESSION",                CKS_RO_PUBLIC_SESSION},
    {"CKS_RO_USER_FUNCTIONS",                CKS_RO_USER_FUNCTIONS},
    {"CKS_RW_PUBLIC_SESSION",                CKS_RW_PUBLIC_SESSION},
    {"CKS_RW_USER_FUNCTIONS",                CKS_RW_USER_FUNCTIONS},
    {"CKS_RW_SO_FUNCTIONS",                  CKS_RW_SO_FUNCTIONS},
    {"CKO_DATA",                             CKO_DATA},
    {"CKO_CERTIFICATE",                      CKO_CERTIFICATE},
    {"CKO_PUBLIC_KEY",                       CKO_PUBLIC_KEY},
    {"CKO_PRIVATE_KEY",                      CKO_PRIVATE_KEY},
    {"CKO_SECRET_KEY",                       CKO_SECRET_KEY},
    {"CKO_HW_FEATURE",                       CKO_HW_FEATURE},
    {"CKO_DOMAIN_PARAMETERS",                CKO_DOMAIN_PARAMETERS},
    {"CKO_MECHANISM",                        CKO_MECHANISM},
    {"CKO_VENDOR_DEFINED",                   CKO_VENDOR_DEFINED},
    {"CKH_MONOTONIC_COUNTER",                CKH_MONOTONIC_COUNTER},
    {"CKH_CLOCK",                            CKH_CLOCK},
    {"CKH_USER_INTERFACE",                   CKH_USER_INTERFACE},
    {"CKH_VENDOR_DEFINED",                   CKH_VENDOR_DEFINED},
    {"CKA_CLASS",                            CKA_CLASS},
    {"CKA_TOKEN",                            CKA_TOKEN},
    {"CKA_PRIVATE",                          CKA_PRIVATE},
    {"CKA_LABEL",                            CKA_LABEL},
    {"CKA_APPLICATION",                      CKA_APPLICATION},
    {"CKA_VALUE",                            CKA_VALUE},
    {"CKA_OBJECT_ID",                        CKA_OBJECT_ID},
    {"CKA_CERTIFICATE_TYPE",                 CKA_CERTIFICATE_TYPE},
    {"CKA_ISSUER",                           CKA_ISSUER},
    {"CKA_SERIAL_NUMBER",                    CKA_SERIAL_NUMBER},
    {"CKA_AC_ISSUER",                        CKA_AC_ISSUER},
    {"CKA_OWNER",                            CKA_OWNER},
    {"CKA_ATTR_TYPES",                       CKA_ATTR_TYPES},
    {"CKA_TRUSTED",                          CKA_TRUSTED},
    {"CKA_CERTIFICATE_CATEGORY",             CKA_CERTIFICATE_CATEGORY},
    {"CKA_JAVA_MIDP_SECURITY_DOMAIN",        CKA_JAVA_MIDP_SECURITY_DOMAIN},
    {"CKA_URL",                              CKA_URL},
    {"CKA_HASH_OF_SUBJECT_PUBLIC_KEY",       CKA_HASH_OF_SUBJECT_PUBLIC_KEY},
    {"CKA_HASH_OF_ISSUER_PUBLIC_KEY",        CKA_HASH_OF_ISSUER_PUBLIC_KEY},
    {"CKA_NAME_HASH_ALGORITHM",              CKA_NAME_HASH_ALGORITHM},
    {"CKA_CHECK_VALUE",                      CKA_CHECK_VALUE},
    {"CKA_KEY_TYPE",                         CKA_KEY_TYPE},
    {"CKA_SUBJECT",                          CKA_SUBJECT},
    {"CKA_ID",                               CKA_ID},
    {"CKA_SENSITIVE",                        CKA_SENSITIVE},
    {"CKA_ENCRYPT",                          CKA_ENCRYPT},
    {"CKA_DECRYPT",                          CKA_DECRYPT},
    {"CKA_WRAP",                             CKA_WRAP},
    {"CKA_UNWRAP",                           CKA_UNWRAP},
    {"CKA_SIGN",                             CKA_SIGN},
    {"CKA_SIGN_RECOVER",                     CKA_SIGN_RECOVER},
    {"CKA_VERIFY",                           CKA_VERIFY},
    {"CKA_VERIFY_RECOVER",                   CKA_VERIFY_RECOVER},
    {"CKA_DERIVE",                           CKA_DERIVE},
    {"CKA_START_DATE",                       CKA_START_DATE},
    {"CKA_END_DATE",                         CKA_END_DATE},
    {"CKA_MODULUS",                          CKA_MODULUS},
    {"CKA_MODULUS_BITS",                     CKA_MODULUS_BITS},
    {"CKA_PUBLIC_EXPONENT",                  CKA_PUBLIC_EXPONENT},
    {"CKA_PRIVATE_EXPONENT",                 CKA_PRIVATE_EXPONENT},
    {"CKA_PRIME_2",                          CKA_PRIME_2},
    {"CKA_COEFFICIENT",                      CKA_COEFFICIENT},
    {"CKA_PRIME",                            CKA_PRIME},
    {"CKA_SUBPRIME",                         CKA_SUBPRIME},
    {"CKA_BASE",                             CKA_BASE},
    {"CKA_PRIME_BITS",                       CKA_PRIME_BITS},
    {"CKA_VALUE_BITS",                       CKA_VALUE_BITS},
    {"CKA_VALUE_LEN",                        CKA_VALUE_LEN},
    {"CKA_EXTRACTABLE",                      CKA_EXTRACTABLE},
    {"CKA_LOCAL",                            CKA_LOCAL},
    {"CKA_NEVER_EXTRACTABLE",                CKA_NEVER_EXTRACTABLE},
    {"CKA_ALWAYS_SENSITIVE",                 CKA_ALWAYS_SENSITIVE},
    {"CKA_KEY_GEN_MECHANISM",                CKA_KEY_GEN_MECHANISM},
    {"CKA_MODIFIABLE",                       CKA_MODIFIABLE},
    {"CKA_COPYABLE",                         CKA_COPYABLE},
    {"CKA_DESTROYABLE",                      CKA_DESTROYABLE},
    {"CKA_EC_PARAMS",                        CKA_EC_PARAMS},
    {"CKA_EC_POINT",                         CKA_EC_POINT},
    {"CKA_ALWAYS_AUTHENTICATE",              CKA_ALWAYS_AUTHENTICATE},
    {"CKA_WRAP_WITH_TRUSTED",                CKA_WRAP_WITH_TRUSTED},
    {"CKA_WRAP_TEMPLATE",                    CKA_WRAP_TEMPLATE},
    {"CKA_UNWRAP_TEMPLATE",                  CKA_UNWRAP_TEMPLATE},
    {"CKA_HW_FEATURE_TYPE",                  CKA_HW_FEATURE_TYPE},
    {"CKA_RESET_ON_INIT",                    CKA_RESET_ON_INIT},
    {"CKA_HAS_RESET",                        CKA_HAS_RESET},
    {"CKA_PIXEL_X",                          CKA_PIXEL_X},
    {"CKA_PIXEL_Y",                          CKA_PIXEL_Y},
    {"CKA_RESOLUTION",                       CKA_RESOLUTION},
    {"CKA_CHAR_ROWS",                        CKA_CHAR_ROWS},
    {"CKA_CHAR_COLUMNS",                     CKA_CHAR_COLUMNS},
    {"CKA_COLOR",                            CKA_COLOR},
    {"CKA_BITS_PER_PIXEL",                   CKA_BITS_PER_PIXEL},
    {"CKA_CHAR_SETS",                        CKA_CHAR_SETS},
    {"CKA_ENCODING_METHODS",                 CKA_ENCODING_METHODS},
    {"CKA_MIME_TYPES",                       CKA_MIME_TYPES},
    {"CKA_MECHANISM_TYPE",                   CKA_MECHANISM_TYPE},
    {"CKA_REQUIRED_CMS_ATTRIBUTES",          CKA_REQUIRED_CMS_ATTRIBUTES},
    {"CKA_DEFAULT_CMS_ATTRIBUTES",           CKA_DEFAULT_CMS_ATTRIBUTES},
    {"CKA_SUPPORTED_CMS_ATTRIBUTES",         CKA_SUPPORTED_CMS_ATTRIBUTES},
    {"CKA_ALLOWED_MECHANISMS",               CKA_ALLOWED_MECHANISMS},
    {"CKA_VENDOR_DEFINED",                   CKA_VENDOR_DEFINED},
    {"CKR_OK",                               CKR_OK},
    {"CKR_CANCEL",                           CKR_CANCEL},
    {"CKR_HOST_MEMORY",                      CKR_HOST_MEMORY},
    {"CKR_SLOT_ID_INVALID",                  CKR_SLOT_ID_INVALID},
    {"CKR_GENERAL_ERROR",                    CKR_GENERAL_ERROR},
    {"CKR_FUNCTION_FAILED",                  CKR_FUNCTION_FAILED},
    {"CKR_ARGUMENTS_BAD",                    CKR_ARGUMENTS_BAD},
    {"CKR_NO_EVENT",                         CKR_NO_EVENT},
    {"CKR_NEED_TO_CREATE_THREADS",           CKR_NEED_TO_CREATE_THREADS},
    {"CKR_CANT_LOCK",                        CKR_CANT_LOCK},
    {"CKR_ATTRIBUTE_READ_ONLY",              CKR_ATTRIBUTE_READ_ONLY},
    {"CKR_ATTRIBUTE_SENSITIVE",              CKR_ATTRIBUTE_SENSITIVE},
    {"CKR_ATTRIBUTE_TYPE_INVALID",           CKR_ATTRIBUTE_TYPE_INVALID},
    {"CKR_ATTRIBUTE_VALUE_INVALID",          CKR_ATTRIBUTE_VALUE_INVALID},
    {"CKR_ACTION_PROHIBITED",                CKR_ACTION_PROHIBITED},
    {"CKR_DATA_INVALID",                     CKR_DATA_INVALID},
    {"CKR_DATA_LEN_RANGE",                   CKR_DATA_LEN_RANGE},
    {"CKR_DEVICE_ERROR",                     CKR_DEVICE_ERROR},
    {"CKR_DEVICE_MEMORY",                    CKR_DEVICE_MEMORY},
    {"CKR_DEVICE_REMOVED",                   CKR_DEVICE_REMOVED},
    {"CKR_ENCRYPTED_DATA_INVALID",           CKR_ENCRYPTED_DATA_INVALID},
    {"CKR_ENCRYPTED_DATA_LEN_RANGE",         CKR_ENCRYPTED_DATA_LEN_RANGE},
    {"CKR_FUNCTION_CANCELED",                CKR_FUNCTION_CANCELED},
    {"CKR_FUNCTION_NOT_PARALLEL",            CKR_FUNCTION_NOT_PARALLEL},
    {"CKR_FUNCTION_NOT_SUPPORTED",           CKR_FUNCTION_NOT_SUPPORTED},
    {"CKR_KEY_HANDLE_INVALID",               CKR_KEY_HANDLE_INVALID},
    {"CKR_KEY_SIZE_RANGE",                   CKR_KEY_SIZE_RANGE},
    {"CKR_KEY_TYPE_INCONSISTENT",            CKR_KEY_TYPE_INCONSISTENT},
    {"CKR_KEY_NOT_NEEDED",                   CKR_KEY_NOT_NEEDED},
    {"CKR_KEY_CHANGED",                      CKR_KEY_CHANGED},
    {"CKR_KEY_NEEDED",                       CKR_KEY_NEEDED},
    {"CKR_KEY_INDIGESTIBLE",                 CKR_KEY_INDIGESTIBLE},
    {"CKR_KEY_FUNCTION_NOT_PERMITTED",       CKR_KEY_FUNCTION_NOT_PERMITTED},
    {"CKR_KEY_NOT_WRAPPABLE",                CKR_KEY_NOT_WRAPPABLE},
    {"CKR_KEY_UNEXTRACTABLE",                CKR_KEY_UNEXTRACTABLE},
    {"CKR_MECHANISM_INVALID",                CKR_MECHANISM_INVALID},
    {"CKR_MECHANISM_PARAM_INVALID",          CKR_MECHANISM_PARAM_INVALID},
    {"CKR_OBJECT_HANDLE_INVALID",            CKR_OBJECT_HANDLE_INVALID},
    {"CKR_OPERATION_ACTIVE",                 CKR_OPERATION_ACTIVE},
    {"CKR_OPERATION_NOT_INITIALIZED",        CKR_OPERATION_NOT_INITIALIZED},
    {"CKR_PIN_INCORRECT",                    CKR_PIN_INCORRECT},
    {"CKR_PIN_INVALID",                      CKR_PIN_INVALID},
    {"CKR_PIN_LEN_RANGE",                    CKR_PIN_LEN_RANGE},
    {"CKR_PIN_EXPIRED",                      CKR_PIN_EXPIRED},
    {"CKR_PIN_LOCKED",                       CKR_PIN_LOCKED},
    {"CKR_SESSION_CLOSED",                   CKR_SESSION_CLOSED},
    {"CKR_SESSION_COUNT",                    CKR_SESSION_COUNT},
    {"CKR_SESSION_HANDLE_INVALID",           CKR_SESSION_HANDLE_INVALID},
    {"CKR_SESSION_PARALLEL_NOT_SUPPORTED",   CKR_SESSION_PARALLEL_NOT_SUPPORTED},
    {"CKR_SESSION_READ_ONLY",                CKR_SESSION_READ_ONLY},
    {"CKR_SESSION_EXISTS",                   CKR_SESSION_EXISTS},
    {"CKR_SESSION_READ_ONLY_EXISTS",         CKR_SESSION_READ_ONLY_EXISTS},
    {"CKR_SESSION_READ_WRITE_SO_EXISTS",     CKR_SESSION_READ_WRITE_SO_EXISTS},
    {"CKR_SIGNATURE_INVALID",                CKR_SIGNATURE_INVALID},
    {"CKR_SIGNATURE_LEN_RANGE",              CKR_SIGNATURE_LEN_RANGE},
    {"CKR_TEMPLATE_INCOMPLETE",              CKR_TEMPLATE_INCOMPLETE},
    {"CKR_TEMPLATE_INCONSISTENT",            CKR_TEMPLATE_INCONSISTENT},
    {"CKR_TOKEN_NOT_PRESENT",                CKR_TOKEN_NOT_PRESENT},
    {"CKR_TOKEN_NOT_RECOGNIZED",             CKR_TOKEN_NOT_RECOGNIZED},
    {"CKR_TOKEN_WRITE_PROTECTED",            CKR_TOKEN_WRITE_PROTECTED},
    {"CKR_UNWRAPPING_KEY_HANDLE_INVALID",    CKR_UNWRAPPING_KEY_HANDLE_INVALID},
    {"CKR_UNWRAPPING_KEY_SIZE_RANGE",        CKR_UNWRAPPING_KEY_SIZE_RANGE},
    {"CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT", CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT},
    {"CKR_USER_ALREADY_LOGGED_IN",           CKR_USER_ALREADY_LOGGED_IN},
    {"CKR_USER_NOT_LOGGED_IN",               CKR_USER_NOT_LOGGED_IN},
    {"CKR_USER_PIN_NOT_INITIALIZED",         CKR_USER_PIN_NOT_INITIALIZED},
    {"CKR_USER_TYPE_INVALID",                CKR_USER_TYPE_INVALID},
    {"CKR_USER_ANOTHER_ALREADY_LOGGED_IN",   CKR_USER_ANOTHER_ALREADY_LOGGED_IN},
    {"CKR_USER_TOO_MANY_TYPES",              CKR_USER_TOO_MANY_TYPES},
    {"CKR_WRAPPED_KEY_INVALID",              CKR_WRAPPED_KEY_INVALID},
    {"CKR_WRAPPED_KEY_LEN_RANGE",            CKR_WRAPPED_KEY_LEN_RANGE},
    {"CKR_WRAPPING_KEY_HANDLE_INVALID",      CKR_WRAPPING_KEY_HANDLE_INVALID},
    {"CKR_WRAPPING_KEY_SIZE_RANGE",          CKR_WRAPPING_KEY_SIZE_RANGE},
    {"CKR_WRAPPING_KEY_TYPE_INCONSISTENT",   CKR_WRAPPING_KEY_TYPE_INCONSISTENT},
    {"CKR_RANDOM_SEED_NOT_SUPPORTED",        CKR_RANDOM_SEED_NOT_SUPPORTED},
    {"CKR_RANDOM_NO_RNG",                    CKR_RANDOM_NO_RNG},
    {"CKR_DOMAIN_PARAMS_INVALID",            CKR_DOMAIN_PARAMS_INVALID},
    {"CKR_CURVE_NOT_SUPPORTED",              CKR_CURVE_NOT_SUPPORTED},
    {"CKR_BUFFER_TOO_SMALL",                 CKR_BUFFER_TOO_SMALL},
    {"CKR_SAVED_STATE_INVALID",              CKR_SAVED_STATE_INVALID},
    {"CKR_INFORMATION_SENSITIVE",            CKR_INFORMATION_SENSITIVE},
    {"CKR_STATE_UNSAVEABLE",                 CKR_STATE_UNSAVEABLE},
    {"CKR_CRYPTOKI_NOT_INITIALIZED",         CKR_CRYPTOKI_NOT_INITIALIZED},
    {"CKR_CRYPTOKI_ALREADY_INITIALIZED",     CKR_CRYPTOKI_ALREADY_INITIALIZED},
    {"CKR_MUTEX_BAD",                        CKR_MUTEX_BAD},
    {"CKR_MUTEX_NOT_LOCKED",                 CKR_MUTEX_NOT_LOCKED},
    {"CKR_FUNCTION_REJECTED",                CKR_FUNCTION_REJECTED},
    {"CKR_VENDOR_DEFINED",                   CKR_VENDOR_DEFINED},
    {NULL, 0}
};

typedef struct {
    const char *key;
    unsigned long value;
} HashEntry;

static HashEntry hash_table[HASH_SIZE] = {{NULL, 0}};

static unsigned int djb2_hash(const char *str) {
    unsigned int hash = 5381;
    int c;

    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;

    return hash % HASH_SIZE;
}

static void init_hash_table() {
    static char init = 0;
    if (init)
        return;

    for (int i = 0; type_table[i].name != NULL; i++) {
        unsigned int index = djb2_hash(type_table[i].name);
        while (hash_table[index].key != NULL)
            index = (index + 1) % HASH_SIZE;
        hash_table[index].key = type_table[i].name;
        hash_table[index].value = type_table[i].value;
    }

    init = 1;
}

unsigned long get_type_value(const unsigned char *type_name) {
    init_hash_table();

    unsigned int index = djb2_hash((const char *)type_name);
    while (hash_table[index].key != NULL) {
        if (strcmp(hash_table[index].key, (const char *)type_name) == 0) {
            return hash_table[index].value;
        }
        index = (index + 1) % HASH_SIZE;
    }

    janet_panicf("%s type is not found", type_name);
    return -1;
}


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
