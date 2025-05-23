/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#ifndef MAIN_H
#define MAIN_H

#include <stdbool.h>
#include "janet.h"
#include "pkcs11_header/pkcs11.h"

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
Janet p11_destroy_object(int32_t argc, Janet *argv);
Janet p11_get_object_size(int32_t argc, Janet *argv);
Janet p11_get_attribute_value(int32_t argc, Janet *argv);
Janet p11_set_attribute_value(int32_t argc, Janet *argv);
Janet p11_find_objects_init(int32_t argc, Janet *argv);
Janet p11_find_objects(int32_t argc, Janet *argv);
Janet p11_find_objects_final(int32_t argc, Janet *argv);

/* Encrypt functions */
Janet p11_encrypt_init(int32_t argc, Janet *argv);
Janet p11_encrypt(int32_t argc, Janet *argv);
Janet p11_encrypt_update(int32_t argc, Janet *argv);
Janet p11_encrypt_final(int32_t argc, Janet *argv);

/* Decrypt functions */
Janet p11_decrypt_init(int32_t argc, Janet *argv);
Janet p11_decrypt(int32_t argc, Janet *argv);
Janet p11_decrypt_update(int32_t argc, Janet *argv);
Janet p11_decrypt_final(int32_t argc, Janet *argv);

/* Digest functions */
Janet p11_digest_init(int32_t argc, Janet *argv);
Janet p11_digest(int32_t argc, Janet *argv);
Janet p11_digest_update(int32_t argc, Janet *argv);
Janet p11_digest_key(int32_t argc, Janet *argv);
Janet p11_digest_final(int32_t argc, Janet *argv);

/* Signing and MACing functions */
Janet p11_sign_init(int32_t argc, Janet *argv);
Janet p11_sign(int32_t argc, Janet *argv);
Janet p11_sign_update(int32_t argc, Janet *argv);
Janet p11_sign_final(int32_t argc, Janet *argv);
Janet p11_sign_recover_init(int32_t argc, Janet *argv);
Janet p11_sign_recover(int32_t argc, Janet *argv);

/* Verify signature and MAC functions */
Janet p11_verify_init(int32_t argc, Janet *argv);
Janet p11_verify(int32_t argc, Janet *argv);
Janet p11_verify_update(int32_t argc, Janet *argv);
Janet p11_verify_final(int32_t argc, Janet *argv);
Janet p11_verify_recover_init(int32_t argc, Janet *argv);
Janet p11_verify_recover(int32_t argc, Janet *argv);

/* Dual-purpose cryptographic functions */
Janet p11_digest_encrypt_update(int32_t argc, Janet *argv);
Janet p11_decrypt_digest_update(int32_t argc, Janet *argv);
Janet p11_sign_encrypt_update(int32_t argc, Janet *argv);
Janet p11_decrypt_verify_update(int32_t argc, Janet *argv);

/* Key management functions */
Janet p11_generate_key(int32_t argc, Janet *argv);
Janet p11_generate_key_pair(int32_t argc, Janet *argv);
Janet p11_wrap_key(int32_t argc, Janet *argv);
Janet p11_unwrap_key(int32_t argc, Janet *argv);
Janet p11_derive_key(int32_t argc, Janet *argv);

/* Random number generation functions */
Janet p11_seed_random(int32_t argc, Janet *argv);
Janet p11_generate_random(int32_t argc, Janet *argv);

/* Sub modules */
void submod_utils(JanetTable *env);
void submod_slot_and_token(JanetTable *env);
void submod_session(JanetTable *env);
void submod_object(JanetTable *env);
void submod_encrypt(JanetTable *env);
void submod_decrypt(JanetTable *env);
void submod_digest(JanetTable *env);
void submod_sign(JanetTable *env);
void submod_verify(JanetTable *env);
void submod_dual(JanetTable *env);
void submod_key(JanetTable *env);
void submod_random(JanetTable *env);

#endif /* MAIN_H */
