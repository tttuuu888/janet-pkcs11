/*
 * Copyright (c) 2024, Janet-pkcs11 Seungki Kim
 *
 * Janet-pkcs11 is released under the MIT License, see the LICENSE file.
 */

#include <janet.h>
#include "main.h"

JANET_FN(get_slot_list,
         "(get-slot-list p11-obj)",
         "Obtains a list of slots in the system")
{
    janet_fixarity(argc, 1);

    pkcs11_obj_t *obj = janet_getabstract(argv, 0, get_obj_type());

    CK_BBOOL tokenPresent = TRUE;
    CK_SLOT_ID_PTR pSlotList = NULL_PTR;
    CK_ULONG pulCount = 0;
    CK_RV rv;
    rv = obj->func_list->C_GetSlotList(tokenPresent, pSlotList, &pulCount);
    PKCS11_ASSERT(rv, "C_GetSlotList");

    if (pulCount == 0) {
        return janet_wrap_nil();
    }

    pSlotList = janet_smalloc(pulCount * sizeof(CK_SLOT_ID));

    rv = obj->func_list->C_GetSlotList(tokenPresent, pSlotList, &pulCount);
    PKCS11_ASSERT(rv, "C_GetSlotList");

    Janet *tup = janet_tuple_begin(pulCount);
    for (int i=0; i<pulCount; i++) {
        tup[i] = janet_wrap_number(pSlotList[i]);
    }

    return janet_wrap_tuple(janet_tuple_end(tup));
}

void submod_slot_and_token(JanetTable *env) {
    JanetRegExt cfuns[] = {
        JANET_REG("get-slot-list", get_slot_list),
        JANET_REG_END
    };
    janet_cfuns_ext(env, "", cfuns);
}
