/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include <janet.h>
#include <stdbool.h>
#include "main.h"

static JanetStruct slot_info_to_struct(CK_SLOT_INFO_PTR info)
{
    JanetTable *ret = janet_table(5);
    JanetTable *hw_ver = janet_table(2);
    JanetTable *fw_ver = janet_table(2);

    janet_table_put(hw_ver, janet_ckeywordv("major"), janet_wrap_number(info->hardwareVersion.major));
    janet_table_put(hw_ver, janet_ckeywordv("minor"), janet_wrap_number(info->hardwareVersion.minor));
    janet_table_put(fw_ver, janet_ckeywordv("major"), janet_wrap_number(info->firmwareVersion.major));
    janet_table_put(fw_ver, janet_ckeywordv("minor"), janet_wrap_number(info->firmwareVersion.minor));

    janet_table_put(ret, janet_ckeywordv("slot-description"), janet_wrap_string(janet_string(info->slotDescription, 64)));
    janet_table_put(ret, janet_ckeywordv("manufacturer-id"), janet_wrap_string(janet_string(info->manufacturerID, 32)));
    janet_table_put(ret, janet_ckeywordv("flags"), janet_wrap_number(info->flags));
    janet_table_put(ret, janet_ckeywordv("hardware-version"), janet_wrap_struct(janet_table_to_struct(hw_ver)));
    janet_table_put(ret, janet_ckeywordv("firmware-version"), janet_wrap_struct(janet_table_to_struct(fw_ver)));

    return janet_table_to_struct(ret);
}

JANET_FN(get_slot_list,
         "(get-slot-list p11-obj)",
         "Obtains a list of slots in the system")
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
         "Obtains information about a particular slot in the system. If "
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

        JanetStruct slot_info = slot_info_to_struct(&info);
        return janet_wrap_struct(slot_info);
    }

    /* Return slot info of all slots */
    Janet *tup = janet_tuple_begin(count);
    for (int i=0; i<count; i++) {
        CK_SLOT_INFO info;
        memset(&info, 0, sizeof(info));
        rv = obj->func_list->C_GetSlotInfo((CK_SLOT_ID)p_slot_list[i], &info);
        PKCS11_ASSERT(rv, "C_GetSlotInfo");

        JanetStruct slot_info = slot_info_to_struct(&info);

        tup[i] = janet_wrap_struct(slot_info);
    }

    return janet_wrap_tuple(janet_tuple_end(tup));
}

void submod_slot_and_token(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("get-slot-list", get_slot_list),
        JANET_REG("get-slot-info", get_slot_info),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "", cfuns);
}
