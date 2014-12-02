#include <virgil/service/data/VirgilAccountId.h>
using virgil::service::data::VirgilAccountId;

GEN_CONSTRUCTOR(VirgilAccountId, com.virgilsecurity.wrapper)
GEN_DESTRUCTOR(VirgilAccountId, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilAccountId_accountId(asSelf):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilAccountId_accountId() {

    VirgilAccountId *cSelf = (VirgilAccountId *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cAccountId = cSelf->accountId();
    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cAccountId, asAccountId);

    AS3_ReturnAS3Var(asAccountId);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilAccountId_setAccountId(asSelf, asAccountId:ByteArray):void"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilAccountId_setAccountId() {
    VirgilAccountId *cSelf = (VirgilAccountId *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cAccountId;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asAccountId, cAccountId);

    cSelf->setAccountId(cAccountId);

    AS3_ReturnAS3Var(undefined);
}
