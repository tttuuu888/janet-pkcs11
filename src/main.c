/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include <janet.h>
#include <dlfcn.h>

#include "cryptoki_compat/pkcs11.h"


typedef struct pkcs11_obj {
    void *lib_handle;
    CK_C_GetFunctionList *func_list;
} pkcs11_obj_t;

/* Abstract Object functions */
static int pkcs11_gc_fn(void *data, size_t len);
static int pkcs11_get_fn(void *data, Janet key, Janet *out);

/* Janet functions */
Janet cfun_new(int32_t argc, Janet *argv);
Janet cfun_test(int32_t argc, Janet *argv);

static JanetAbstractType pkcs11_obj_type = {
    "pkcs11",
    pkcs11_gc_fn,
    NULL,
    pkcs11_get_fn,
    JANET_ATEND_GET
};

static JanetMethod pkcs11_methods[] = {
    {"test", cfun_test},
    {NULL, NULL},
};

static JanetAbstractType *get_obj_type() {
    return &pkcs11_obj_type;
}

/* Abstract Object functions */
static int pkcs11_gc_fn(void *data, size_t len) {
    pkcs11_obj_t *obj = (pkcs11_obj_t *)data;

    if (obj->lib_handle) {
        dlclose(obj->lib_handle);
    }

    return 0;
}

static int pkcs11_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), pkcs11_methods, out);
}

/* Janet functions */
JANET_FN(cfun_new,
         "(new &opt lib-path)",
         "Get the instance holding a handle to the opened PKCS#11 library. "
         "If `lib-path` is not provided, try to open a libirary in environment "
         "variable, `PKCS11_MODULE`")
{
    janet_arity(argc, 0, 1);

    pkcs11_obj_t *obj = janet_abstract(&pkcs11_obj_type, sizeof(pkcs11_obj_t));
    memset(obj, 0, sizeof(pkcs11_obj_t));

    return janet_wrap_abstract(obj);
}


JANET_FN(cfun_test,
         "(test)",
         "test function")
{
    janet_arity(argc, 0, 1);

    pkcs11_obj_t *obj = janet_getabstract(argv, 0, get_obj_type());

    printf("test function\n");

    return janet_wrap_abstract(obj);
}

JANET_MODULE_ENTRY(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("new", cfun_new),
        JANET_REG("test", cfun_test),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "", cfuns);
}
