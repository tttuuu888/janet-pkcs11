/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include "main.h"
#include "pkcs11_utils.h"

/* Abstract Object functions */
static Janet cfun_session_close(int32_t argc, Janet *argv);
static int session_gc_fn(void *data, size_t len);
static int session_get_fn(void *data, Janet key, Janet *out);

static JanetAbstractType session_obj_type = {
    "session",
    session_gc_fn,
    NULL,
    session_get_fn,
    JANET_ATEND_GET
};

static JanetMethod session_methods[] = {
    {"close", cfun_session_close},
    {"get-session-info", get_session_info},
    {NULL, NULL},
};

static void session_close(session_obj_t *obj) {
    if (obj->is_session_open) {
        CK_RV rv;
        rv = obj->func_list->C_CloseSession(obj->session);
        PKCS11_ASSERT(rv, "C_CloseSession");
        obj->is_session_open = false;
    }
}

/* Abstract Object functions */
static int session_gc_fn(void *data, size_t len) {
    session_obj_t *obj = (session_obj_t *)data;
    session_close(obj);

    return 0;
}

static int session_get_fn(void *data, Janet key, Janet *out) {
    (void)data;
    if (!janet_checktype(key, JANET_KEYWORD)) {
        return 0;
    }

    return janet_getmethod(janet_unwrap_keyword(key), session_methods, out);
}

static Janet cfun_session_close(int32_t argc, Janet *argv) {
    janet_fixarity(argc, 1);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    session_close(obj);

    return janet_wrap_nil();
}

JanetAbstractType *get_session_obj_type(void) {
    return &session_obj_type;
}

JANET_FN(open_session,
         "(open-session p11-obj slot-id &opt :read-only)",
         "Opens a session between an application and a token in a particular "
         "slot. Returns `session-obj`, if successful."
         "Open R/W session unless `:read-only` is passed.")
{
    janet_arity(argc, 2, 3);

    p11_obj_t *obj = janet_getabstract(argv, 0, get_p11_obj_type());
    CK_SLOT_ID slot_id = janet_getinteger64(argv, 1);

    CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    CK_SESSION_HANDLE session;

    if (IS_ARG_KEYWORD(2, "read-only")) {
        flags = CKF_SERIAL_SESSION;
    }

    CK_RV rv;
    rv = obj->func_list->C_OpenSession(slot_id, flags, NULL_PTR, NULL_PTR, &session);
    PKCS11_ASSERT(rv, "C_OpenSession");

    session_obj_t *session_obj = janet_abstract(get_session_obj_type(), sizeof(session_obj_t));
    memset(session_obj, 0, sizeof(session_obj_t));
    session_obj->session = session;
    session_obj->func_list = obj->func_list;
    session_obj->is_session_open = true;

    return janet_wrap_abstract(session_obj);
}

JANET_FN(get_session_info,
         "(get-session-info session-obj)",
         "Returns an information about a session.")
{
    janet_fixarity(argc, 1);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());

    CK_SESSION_INFO info;
    CK_RV rv;
    rv = obj->func_list->C_GetSessionInfo(obj->session, &info);
    PKCS11_ASSERT(rv, "C_GetSessionInfo");

    JanetTable *ret = janet_table(4);
    janet_table_put(ret, janet_ckeywordv("slot-id"), janet_wrap_number(info.slotID));
    janet_table_put(ret, janet_ckeywordv("state"), janet_wrap_number(info.state));
    janet_table_put(ret, janet_ckeywordv("flags"), janet_wrap_number(info.flags));
    janet_table_put(ret, janet_ckeywordv("device-error"), janet_wrap_number(info.ulDeviceError));

    return janet_wrap_struct(janet_table_to_struct(ret));
}

void submod_session(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("open-session", open_session),
        JANET_REG("get-session-info", get_session_info),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "", cfuns);
}
