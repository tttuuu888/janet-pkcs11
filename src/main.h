/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#ifndef MAIN_H
#define MAIN_H

#include "cryptoki_compat/pkcs11.h"
#include "pkcs11_errors.h"

typedef struct pkcs11_obj {
    void *lib_handle;
    CK_FUNCTION_LIST_PTR func_list;
} pkcs11_obj_t;

JanetAbstractType *get_obj_type(void);

/* General purpose functions */
Janet new(int32_t argc, Janet *argv);
Janet get_info(int32_t argc, Janet *argv);

/* Slot and token management functions */
Janet get_slot_list(int32_t argc, Janet *argv);
Janet get_slot_info(int32_t argc, Janet *argv);
Janet get_token_info(int32_t argc, Janet *argv);
Janet wait_for_slot_event(int32_t argc, Janet *argv);

void submod_slot_and_token(JanetTable *env);

#endif /* MAIN_H */
