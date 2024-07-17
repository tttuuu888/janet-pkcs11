/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include "main.h"
#include "error.h"
#include "utils.h"

/* Abstract Object functions */
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
    {"close", p11_close_session},
    {"close-session", p11_close_session},
    {"get-session-info", p11_get_session_info},
    {"get-operation-state", p11_get_operation_state},
    {"login", p11_login},
    {"logout", p11_logout},
    {"init-pin", p11_init_pin},
    {"set-pin", p11_set_pin},
    {"create-object", p11_create_object},
    {"copy-object", p11_copy_object},
    {"destroy-object", p11_destroy_object},
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

JanetAbstractType *get_session_obj_type(void) {
    return &session_obj_type;
}

JANET_FN(p11_open_session,
         "(open-session p11-obj slot-id &opt :read-only)",
         "Opens a session between an application and a token in a particular "
         "slot. Opens R/W session unless `:read-only` is passed. "
         "Returns `session-obj`, if successful.")
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

JANET_FN(p11_close_session,
         "(close-session session-obj)",
         "Closes a session between an application and a token.")
{
    janet_fixarity(argc, 1);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    session_close(obj);

    return janet_wrap_nil();
}

JANET_FN(p11_close_all_sessions,
         "(close-all-sessions p11-obj slot-id)",
         "Closes all sessions an application has with a token.")
{
    janet_fixarity(argc, 2);

    p11_obj_t *obj = janet_getabstract(argv, 0, get_p11_obj_type());
    CK_SLOT_ID slot_id = janet_getinteger64(argv, 1);

    CK_RV rv;
    rv = obj->func_list->C_CloseAllSessions(slot_id);
    PKCS11_ASSERT(rv, "C_CloseAllSessions");

    return janet_wrap_nil();
}

JANET_FN(p11_get_session_info,
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

JANET_FN(p11_get_operation_state,
         "(get-operation-state session-obj)",
         "Returns the cryptographic operations state of a session in string.")
{
    janet_fixarity(argc, 1);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());

    CK_ULONG state_len;
    CK_RV rv;
    rv = obj->func_list->C_GetOperationState(obj->session, NULL_PTR, &state_len);
    PKCS11_ASSERT(rv, "C_GetOperationState");

    if (state_len == 0) {
        return janet_wrap_nil();
    }

    JanetBuffer *state = janet_buffer(state_len);
    rv = obj->func_list->C_GetOperationState(obj->session, (CK_BYTE_PTR)state->data, &state_len);
    PKCS11_ASSERT(rv, "C_GetOperationState");

    return janet_wrap_string(janet_string(state->data, state_len));
}

JANET_FN(p11_login,
         "(login session-obj user-type pin)",
         "Logs a user into a token. `user-type` must be one of the following: "
         ":so, :user, or :context-specific. Returns `session-obj`, if "
         "successful.")
{
    janet_fixarity(argc, 3);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    const uint8_t *user_type_kw = janet_getkeyword(argv, 1);
    const char *pin = (const char *)janet_getstring(argv, 2);

    CK_USER_TYPE user_type;
    if (!janet_cstrcmp(user_type_kw, "so")) {
        user_type = CKU_SO;
    } else if (!janet_cstrcmp(user_type_kw, "user")) {
        user_type = CKU_USER;
    } else if (!janet_cstrcmp(user_type_kw, "context-speicifc")) {
        user_type = CKU_CONTEXT_SPECIFIC;
    } else {
        janet_panicf("expected one of :so, :user, :context-speicifc, got %v", argv[1]);
    }

    CK_RV rv;
    rv = obj->func_list->C_Login(obj->session, user_type, (CK_UTF8CHAR_PTR)pin, (CK_ULONG)strlen(pin));
    PKCS11_ASSERT(rv, "C_Login");

    return janet_wrap_abstract(obj);
}

JANET_FN(p11_logout,
         "(logout session-obj)",
         "Logs a user out from a token. Returns `session-obj`, if successful.")
{
    janet_fixarity(argc, 1);

    session_obj_t *obj = janet_getabstract(argv, 0, get_session_obj_type());
    CK_RV rv;
    rv = obj->func_list->C_Logout(obj->session);
    PKCS11_ASSERT(rv, "C_Logout");

    return janet_wrap_abstract(obj);
}

void submod_session(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("open-session", p11_open_session),
        JANET_REG("close-session", p11_close_session),
        JANET_REG("close-all-sessions", p11_close_all_sessions),
        JANET_REG("get-session-info", p11_get_session_info),
        JANET_REG("get-operation-state", p11_get_operation_state),
        JANET_REG("login", p11_login),
        JANET_REG("logout", p11_logout),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "", cfuns);
    janet_register_abstract_type(get_session_obj_type());
}
