/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include <janet.h>
#include <stdbool.h>
#include "main.h"

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
    {NULL, NULL},
};

/* Abstract Object functions */
static int session_gc_fn(void *data, size_t len) {
    session_obj_t *obj = (session_obj_t *)data;
    (void)obj;

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
    CK_SESSION_HANDLE_PTR p_session = janet_smalloc(sizeof(CK_SESSION_HANDLE));

    if (IS_ARG_KEYWORD(2, "read-only")) {
        flags = CKF_SERIAL_SESSION;
    }

    CK_RV rv;
    rv = obj->func_list->C_OpenSession(slot_id, flags, NULL_PTR, NULL_PTR, p_session);
    PKCS11_ASSERT(rv, "C_OpenSession");

    return janet_wrap_nil();
}

void submod_session(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("open-session", open_session),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "", cfuns);
}
