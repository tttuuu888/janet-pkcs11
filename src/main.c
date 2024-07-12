/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include <dlfcn.h>
#include "main.h"
#include "pkcs11_utils.h"

/* Abstract Object functions */
static int pkcs11_gc_fn(void *data, size_t len);
static int pkcs11_get_fn(void *data, Janet key, Janet *out);

static JanetAbstractType p11_obj_type = {
    "pkcs11",
    pkcs11_gc_fn,
    NULL,
    pkcs11_get_fn,
    JANET_ATEND_GET
};

static JanetMethod pkcs11_methods[] = {
    {"get-info", get_info},
    {"get-slot-list", get_slot_list},
    {"get-slot-info", get_slot_info},
    {"get-token-info", get_token_info},
    {"wait-for-slot-event", wait_for_slot_event},
    {"get-mechanism-list", get_mechanism_list},
    {"get-mechanism-info", get_mechanism_info},
    {"init-token", init_token},
    {"open-session", open_session},
    {NULL, NULL},
};

/* Abstract Object functions */
static int pkcs11_gc_fn(void *data, size_t len) {
    p11_obj_t *obj = (p11_obj_t *)data;

    obj->func_list->C_Finalize(NULL_PTR);
    dlclose(obj->lib_handle);

    return 0;
}

static int pkcs11_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), pkcs11_methods, out);
}

JanetAbstractType *get_p11_obj_type(void) {
    return &p11_obj_type;
}

JANET_FN(new,
         "(new &opt lib-path)",
         "Get the `p11-obj`(an instance holding a handle to the opened PKCS#11 "
         "library). If `lib-path` is not provided, try to open a libirary in "
         "environment variable, `PKCS11_MODULE`")
{
    janet_arity(argc, 0, 1);

    p11_obj_t *obj = janet_abstract(get_p11_obj_type(), sizeof(p11_obj_t));
    memset(obj, 0, sizeof(p11_obj_t));

    const char *lib_path = janet_getcstring(argv, 0);
	obj->lib_handle = dlopen(lib_path, RTLD_NOW | RTLD_LOCAL);
    if (!obj->lib_handle) {
        janet_panicf("Load library %s failed", lib_path);
    }

    CK_C_GetFunctionList get_func_list;
    get_func_list = (CK_C_GetFunctionList)dlsym(obj->lib_handle, "C_GetFunctionList");
    if (!get_func_list) {
        janet_panic("Cannot find C_GetFunctionList");
    }

    CK_RV rv;
    rv = (*get_func_list)(&obj->func_list);
    PKCS11_ASSERT(rv, "C_GetFunctionList");

    rv = obj->func_list->C_Initialize(NULL_PTR);
    PKCS11_ASSERT(rv, "C_Initialize");

    return janet_wrap_abstract(obj);
}

JANET_FN(get_info,
         "(get-info p11-obj)",
         "Returns general information about Cryptoki.")
{
    janet_fixarity(argc, 1);

    p11_obj_t *obj = janet_getabstract(argv, 0, get_p11_obj_type());

    CK_INFO info;
    memset(&info, 0, sizeof(info));

    CK_RV rv;
    rv = obj->func_list->C_GetInfo(&info);
    PKCS11_ASSERT(rv, "C_GetInfo");

    JanetTable *ret = janet_table(5);
    JanetTable *ck_ver = janet_table(2);
    JanetTable *lib_ver = janet_table(2);

    janet_table_put(ck_ver, janet_ckeywordv("major"), janet_wrap_number(info.cryptokiVersion.major));
    janet_table_put(ck_ver, janet_ckeywordv("minor"), janet_wrap_number(info.cryptokiVersion.minor));

    janet_table_put(lib_ver, janet_ckeywordv("major"), janet_wrap_number(info.libraryVersion.major));
    janet_table_put(lib_ver, janet_ckeywordv("minor"), janet_wrap_number(info.libraryVersion.minor));

    janet_table_put(ret, janet_ckeywordv("cryptoki-version"), janet_wrap_struct(janet_table_to_struct(ck_ver)));
    janet_table_put(ret, janet_ckeywordv("manufacturer-id"), janet_stringv(info.manufacturerID, 32));
    janet_table_put(ret, janet_ckeywordv("flags"), janet_wrap_number(info.flags));
    janet_table_put(ret, janet_ckeywordv("library-description"), janet_stringv(info.libraryDescription, 32));
    janet_table_put(ret, janet_ckeywordv("library-version"), janet_wrap_struct(janet_table_to_struct(lib_ver)));

    return janet_wrap_struct(janet_table_to_struct(ret));
}

static void submod_general_purpose(JanetTable *env)
{
    JanetRegExt cfuns[] = {
        JANET_REG("new", new),
        JANET_REG("get-info", get_info),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "", cfuns);
}

JANET_MODULE_ENTRY(JanetTable *env) {
    janet_register_abstract_type(get_p11_obj_type());
    submod_general_purpose(env);
    submod_slot_and_token(env);
    submod_session(env);
}
