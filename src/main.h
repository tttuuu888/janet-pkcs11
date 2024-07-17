/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#ifndef MAIN_H
#define MAIN_H

#include <stdbool.h>
#include "janet.h"
#include "cryptoki_compat/pkcs11.h"

typedef struct p11_obj {
    void *lib_handle;
    CK_FUNCTION_LIST_PTR func_list;
    bool is_p11_open;
} p11_obj_t;

typedef struct session_obj {
    CK_SESSION_HANDLE session;
    CK_FUNCTION_LIST_PTR func_list;
    bool is_session_open;
} session_obj_t;

JanetAbstractType *get_p11_obj_type(void);
JanetAbstractType *get_session_obj_type(void);

/* General purpose functions */
Janet p11_new(int32_t argc, Janet *argv);
Janet p11_get_info(int32_t argc, Janet *argv);

/* Slot and token management functions */
Janet p11_get_slot_list(int32_t argc, Janet *argv);
Janet p11_get_slot_info(int32_t argc, Janet *argv);
Janet p11_get_token_info(int32_t argc, Janet *argv);
Janet p11_wait_for_slot_event(int32_t argc, Janet *argv);
Janet p11_get_mechanism_list(int32_t argc, Janet *argv);
Janet p11_get_mechanism_info(int32_t argc, Janet *argv);
Janet p11_init_token(int32_t argc, Janet *argv);
Janet p11_init_pin(int32_t argc, Janet *argv);
Janet p11_set_pin(int32_t argc, Janet *argv);

/* Session management functions */
Janet p11_open_session(int32_t argc, Janet *argv);
Janet p11_close_session(int32_t argc, Janet *argv);
Janet p11_close_all_sessions(int32_t argc, Janet *argv);
Janet p11_get_session_info(int32_t argc, Janet *argv);
Janet p11_get_operation_state(int32_t argc, Janet *argv);
Janet p11_login(int32_t argc, Janet *argv);
Janet p11_logout(int32_t argc, Janet *argv);

/* Object management functions */
Janet p11_create_object(int32_t argc, Janet *argv);
Janet p11_copy_object(int32_t argc, Janet *argv);

/* Sub modules */
void submod_utils(JanetTable *env);
void submod_types(JanetTable *env);
void submod_slot_and_token(JanetTable *env);
void submod_session(JanetTable *env);
void submod_utils(JanetTable *env);

#endif /* MAIN_H */
