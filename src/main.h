/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#ifndef MAIN_H
#define MAIN_H

#include "cryptoki_compat/pkcs11.h"
#include "pkcs11_utils.h"

typedef struct p11_obj {
    void *lib_handle;
    CK_FUNCTION_LIST_PTR func_list;
} p11_obj_t;

typedef struct session_obj {
    CK_SESSION_HANDLE_PTR session;
} session_obj_t;

JanetAbstractType *get_p11_obj_type(void);
JanetAbstractType *get_session_obj_type(void);

/* General purpose functions */
Janet new(int32_t argc, Janet *argv);
Janet get_info(int32_t argc, Janet *argv);

/* Slot and token management functions */
Janet get_slot_list(int32_t argc, Janet *argv);
Janet get_slot_info(int32_t argc, Janet *argv);
Janet get_token_info(int32_t argc, Janet *argv);
Janet wait_for_slot_event(int32_t argc, Janet *argv);
Janet get_mechanism_list(int32_t argc, Janet *argv);
Janet get_mechanism_info(int32_t argc, Janet *argv);
Janet init_token(int32_t argc, Janet *argv);

/* Session management functions */
Janet open_session(int32_t argc, Janet *argv);

/* Sub modules */
void submod_slot_and_token(JanetTable *env);
void submod_session(JanetTable *env);

#endif /* MAIN_H */
