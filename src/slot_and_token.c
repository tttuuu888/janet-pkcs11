/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include <janet.h>
#include <stdbool.h>
#include "main.h"

/* `:slot-id` will be added to original CK_SLOT_INFO */
static JanetStruct slot_info_to_struct(CK_SLOT_INFO_PTR info, CK_SLOT_ID slot_id)
{
    JanetTable *ret = janet_table(5);
    JanetTable *hw_ver = janet_table(2);
    JanetTable *fw_ver = janet_table(2);

    janet_table_put(hw_ver, janet_ckeywordv("major"), janet_wrap_number(info->hardwareVersion.major));
    janet_table_put(hw_ver, janet_ckeywordv("minor"), janet_wrap_number(info->hardwareVersion.minor));
    janet_table_put(fw_ver, janet_ckeywordv("major"), janet_wrap_number(info->firmwareVersion.major));
    janet_table_put(fw_ver, janet_ckeywordv("minor"), janet_wrap_number(info->firmwareVersion.minor));

    janet_table_put(ret, janet_ckeywordv("slot-id"), janet_wrap_number(slot_id));
    janet_table_put(ret, janet_ckeywordv("slot-description"), janet_wrap_string(janet_string(info->slotDescription, 64)));
    janet_table_put(ret, janet_ckeywordv("manufacturer-id"), janet_wrap_string(janet_string(info->manufacturerID, 32)));
    janet_table_put(ret, janet_ckeywordv("flags"), janet_wrap_number(info->flags));
    janet_table_put(ret, janet_ckeywordv("hardware-version"), janet_wrap_struct(janet_table_to_struct(hw_ver)));
    janet_table_put(ret, janet_ckeywordv("firmware-version"), janet_wrap_struct(janet_table_to_struct(fw_ver)));

    return janet_table_to_struct(ret);
}

JANET_FN(get_slot_list,
         "(get-slot-list p11-obj)",
         "Returns a list of slots in the system")
{
    janet_fixarity(argc, 1);

    pkcs11_obj_t *obj = janet_getabstract(argv, 0, get_obj_type());

    CK_BBOOL token_present = TRUE;
    CK_SLOT_ID_PTR p_slot_list = NULL_PTR;
    CK_ULONG count = 0;
    CK_RV rv;
    rv = obj->func_list->C_GetSlotList(token_present, p_slot_list, &count);
    PKCS11_ASSERT(rv, "C_GetSlotList");

    if (count == 0) {
        return janet_wrap_nil();
    }

    p_slot_list = janet_smalloc(count * sizeof(CK_SLOT_ID));

    rv = obj->func_list->C_GetSlotList(token_present, p_slot_list, &count);
    PKCS11_ASSERT(rv, "C_GetSlotList");

    Janet *tup = janet_tuple_begin(count);
    for (int i=0; i<count; i++) {
        tup[i] = janet_wrap_number(p_slot_list[i]);
    }

    return janet_wrap_tuple(janet_tuple_end(tup));
}

JANET_FN(get_slot_info,
         "(get-slot-info p11-obj &opt slot-id)",
         "Returns information about a particular slot in the system. If "
         "`slot-id` is not provided, information about all slots is returned "
         "as a list. If there is no slot corresponding to `slot-id` or no "
         "slot exists in system, `nil` is returned."
    )
{
    janet_arity(argc, 1, 2);

    pkcs11_obj_t *obj = janet_getabstract(argv, 0, get_obj_type());

    CK_BBOOL token_present = TRUE;
    CK_SLOT_ID_PTR p_slot_list = NULL_PTR;
    CK_ULONG count = 0;
    CK_RV rv;
    rv = obj->func_list->C_GetSlotList(token_present, p_slot_list, &count);
    PKCS11_ASSERT(rv, "C_GetSlotList");

    if (count == 0) {
        return janet_wrap_nil();
    }

    p_slot_list = janet_smalloc(count * sizeof(CK_SLOT_ID));
    rv = obj->func_list->C_GetSlotList(token_present, p_slot_list, &count);
    PKCS11_ASSERT(rv, "C_GetSlotList");

    if (argc == 2) {
        /* Return slot info corresponding to `slot-id` */
        CK_SLOT_ID slot_id = janet_getinteger64(argv, 1);
        bool slot_id_found = false;
        for (int i=0; i<count; i++) {
            if (p_slot_list[i] == slot_id) {
                slot_id_found = true;
                break;
            }
        }

        if (!slot_id_found) {
            return janet_wrap_nil();
        }

        CK_SLOT_INFO info;
        memset(&info, 0, sizeof(info));
        rv = obj->func_list->C_GetSlotInfo(slot_id, &info);
        PKCS11_ASSERT(rv, "C_GetSlotInfo");

        JanetStruct slot_info = slot_info_to_struct(&info, slot_id);
        return janet_wrap_struct(slot_info);
    }

    /* Return slot info of all slots */
    Janet *tup = janet_tuple_begin(count);
    for (int i=0; i<count; i++) {
        CK_SLOT_INFO info;
        memset(&info, 0, sizeof(info));
        rv = obj->func_list->C_GetSlotInfo(p_slot_list[i], &info);
        PKCS11_ASSERT(rv, "C_GetSlotInfo");

        JanetStruct slot_info = slot_info_to_struct(&info, p_slot_list[i]);
        tup[i] = janet_wrap_struct(slot_info);
    }

    return janet_wrap_tuple(janet_tuple_end(tup));
}

JANET_FN(get_token_info,
         "(get-token-info p11-obj slot-id)",
         "Returns information about a particular token in the system. "
         "`slot-id` is the ID of the token’s slot.")
{
    janet_fixarity(argc, 2);

    pkcs11_obj_t *obj = janet_getabstract(argv, 0, get_obj_type());
    CK_SLOT_ID slot_id = janet_getinteger64(argv, 1);
    CK_TOKEN_INFO info;
    CK_RV rv;
    memset(&info, 0, sizeof(info));
    rv = obj->func_list->C_GetTokenInfo(slot_id, &info);
    PKCS11_ASSERT(rv, "C_GetTokenInfo");

    JanetTable *ret = janet_table(18);
    JanetTable *hw_ver = janet_table(2);
    JanetTable *fw_ver = janet_table(2);

    janet_table_put(hw_ver, janet_ckeywordv("major"), janet_wrap_number(info.hardwareVersion.major));
    janet_table_put(hw_ver, janet_ckeywordv("minor"), janet_wrap_number(info.hardwareVersion.minor));
    janet_table_put(fw_ver, janet_ckeywordv("major"), janet_wrap_number(info.firmwareVersion.major));
    janet_table_put(fw_ver, janet_ckeywordv("minor"), janet_wrap_number(info.firmwareVersion.minor));

    janet_table_put(ret, janet_ckeywordv("label"), janet_stringv(info.label, 32));
    janet_table_put(ret, janet_ckeywordv("manufacturer-id"), janet_stringv(info.manufacturerID, 32));
    janet_table_put(ret, janet_ckeywordv("model"), janet_stringv(info.model, 16));
    janet_table_put(ret, janet_ckeywordv("serial-number"), janet_stringv(info.serialNumber, 16));
    janet_table_put(ret, janet_ckeywordv("flags"), janet_wrap_number(info.flags));
    janet_table_put(ret, janet_ckeywordv("max-session-count"), janet_wrap_number(info.ulMaxSessionCount));
    janet_table_put(ret, janet_ckeywordv("session-count"), janet_wrap_number(info.ulSessionCount));
    janet_table_put(ret, janet_ckeywordv("max-rw-session-count"), janet_wrap_number(info.ulMaxRwSessionCount));
    janet_table_put(ret, janet_ckeywordv("rw-session-count"), janet_wrap_number(info.ulRwSessionCount));
    janet_table_put(ret, janet_ckeywordv("max-pin-len"), janet_wrap_number(info.ulMaxPinLen));
    janet_table_put(ret, janet_ckeywordv("min-pin-len"), janet_wrap_number(info.ulMinPinLen));
    janet_table_put(ret, janet_ckeywordv("total-public-memory"), janet_wrap_number(info.ulTotalPublicMemory));
    janet_table_put(ret, janet_ckeywordv("free-public-memory"), janet_wrap_number(info.ulFreePublicMemory));
    janet_table_put(ret, janet_ckeywordv("total-private-memory"), janet_wrap_number(info.ulTotalPrivateMemory));
    janet_table_put(ret, janet_ckeywordv("hardware-version"), janet_wrap_struct(janet_table_to_struct(hw_ver)));
    janet_table_put(ret, janet_ckeywordv("firmware-version"), janet_wrap_struct(janet_table_to_struct(fw_ver)));
    janet_table_put(ret, janet_ckeywordv("utc-time"), janet_stringv(info.utcTime, 16));

    return janet_wrap_struct(janet_table_to_struct(ret));
}

JANET_FN(wait_for_slot_event,
         "(wait-for-slot-event p11-obj)",
         "Returns a list of slot-id of slots where events occurred. "
         "Returns `nil` if there are no event in any slots.")
{
    janet_fixarity(argc, 1);

    pkcs11_obj_t *obj = janet_getabstract(argv, 0, get_obj_type());
    int event_slots = 0;
    CK_SLOT_ID slot_ids[32] = {0,};
    CK_SLOT_ID slot_id;
    CK_RV rv;
    for (int i=0; i<32; i++) {
        rv = obj->func_list->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot_id, NULL_PTR);
        if (rv == CKR_NO_EVENT) {
            break;
        }

        PKCS11_ASSERT(rv, "C_WaitForSlotEvent");
        slot_ids[i] = slot_id;
        event_slots += 1;
    }

    if (event_slots == 0) {
        return janet_wrap_nil();
    }

    Janet *tup = janet_tuple_begin(event_slots);
    for (int i=0; i<event_slots; i++) {
        tup[i] = janet_wrap_number(slot_ids[i]);
    }

    return janet_wrap_tuple(janet_tuple_end(tup));
}

JANET_FN(get_mechanism_list,
         "(get-mechanism-list p11-obj slot-id)",
         "Returns a list of mechanisms supported by a token."
         "`slot-id` is the ID of the token’s slot.")
{
    janet_fixarity(argc, 2);

    pkcs11_obj_t *obj = janet_getabstract(argv, 0, get_obj_type());
    CK_SLOT_ID slot_id = janet_getinteger64(argv, 1);
    CK_MECHANISM_TYPE_PTR p_mechanism_list = NULL_PTR;
    CK_ULONG count = 0;
    CK_RV rv;
    rv = obj->func_list->C_GetMechanismList(slot_id, p_mechanism_list, &count);
    PKCS11_ASSERT(rv, "C_GetMechanismList");

    if (count == 0) {
        return janet_wrap_nil();
    }

    p_mechanism_list = janet_smalloc(count * sizeof(CK_MECHANISM_TYPE));
    rv = obj->func_list->C_GetMechanismList(slot_id, p_mechanism_list, &count);
    PKCS11_ASSERT(rv, "C_GetMechanismList");

    Janet *tup = janet_tuple_begin(count);
    for (int i=0; i<count; i++) {
        tup[i] = janet_wrap_number(p_mechanism_list[i]);
    }

    return janet_wrap_tuple(janet_tuple_end(tup));
}

JANET_FN(get_mechanism_info,
         "(get-mechanism-info p11-obj slot-id &opt mechanism-list)",
         "Returns a list of mechanisms information of `mechanism-list` list."
         "`slot-id` is the ID of the token’s slot. If `mechanism-list` is not "
         "provided, return list of all avaiable mechanism information.")
{
    janet_arity(argc, 2, 3);

    pkcs11_obj_t *obj = janet_getabstract(argv, 0, get_obj_type());
    CK_SLOT_ID slot_id = janet_getinteger64(argv, 1);
    CK_MECHANISM_TYPE_PTR p_mechanism_list = NULL_PTR;
    CK_ULONG count = 0;
    CK_RV rv;

    if (argc == 2) {
        rv = obj->func_list->C_GetMechanismList(slot_id, p_mechanism_list, &count);
        PKCS11_ASSERT(rv, "C_GetMechanismList");

        if (count == 0) {
            return janet_wrap_nil();
        }

        p_mechanism_list = janet_smalloc(count * sizeof(CK_MECHANISM_TYPE));
        rv = obj->func_list->C_GetMechanismList(slot_id, p_mechanism_list, &count);
        PKCS11_ASSERT(rv, "C_GetMechanismList");
    } else {
        JanetTuple tup = janet_gettuple(argv, 2);
        count = (CK_ULONG)janet_tuple_length(tup);
        p_mechanism_list = janet_smalloc(count * sizeof(CK_MECHANISM_TYPE));
        for (int i=0; i<count; i++) {
            p_mechanism_list[i] = janet_getinteger64(tup, i);
        }
    }

    Janet *ret = janet_tuple_begin(count);
    for (int i=0; i<count; i++) {
        CK_MECHANISM_INFO info;
        rv = obj->func_list->C_GetMechanismInfo(slot_id, p_mechanism_list[i], &info);
        PKCS11_ASSERT(rv, "C_GetMechanismInfo");

        JanetTable *jinfo = janet_table(4);
        janet_table_put(jinfo, janet_ckeywordv("type"), janet_wrap_number(p_mechanism_list[i]));
        janet_table_put(jinfo, janet_ckeywordv("min-key-size"), janet_wrap_number(info.ulMinKeySize));
        janet_table_put(jinfo, janet_ckeywordv("max-key-size"), janet_wrap_number(info.ulMaxKeySize));
        janet_table_put(jinfo, janet_ckeywordv("flags"), janet_wrap_number(info.flags));

        ret[i] = janet_wrap_struct(janet_table_to_struct(jinfo));
    }

    return janet_wrap_tuple(janet_tuple_end(ret));
}

JANET_FN(init_token,
         "(init-token p11-obj slot-id so-pin label)",
         "Initializes a token. Return `p11-obj`, if successful.")
{
    janet_fixarity(argc, 4);

    pkcs11_obj_t *obj = janet_getabstract(argv, 0, get_obj_type());
    CK_SLOT_ID slot_id = janet_getinteger64(argv, 1);
    CK_UTF8CHAR_PTR pin = (CK_UTF8CHAR_PTR)janet_getcstring(argv, 2);
    const char *jlabel = janet_getcstring(argv, 3);
    CK_UTF8CHAR label[32];
    CK_RV rv;

    memset(label, ' ', sizeof(label));
    memcpy(label, jlabel, strlen(jlabel));

    rv = obj->func_list->C_InitToken(slot_id, pin, strlen(pin), label);
    PKCS11_ASSERT(rv, "C_InitToken");

    return janet_wrap_abstract(obj);
}

void submod_slot_and_token(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("get-slot-list", get_slot_list),
        JANET_REG("get-slot-info", get_slot_info),
        JANET_REG("get-token-info", get_token_info),
        JANET_REG("wait-for-slot-event", wait_for_slot_event),
        JANET_REG("get-mechanism-list", get_mechanism_list),
        JANET_REG("get-mechanism-info", get_mechanism_info),
        JANET_REG("init-token", init_token),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "", cfuns);
}
