#include <virgil/service/data/VirgilUserIdTicket.h>
using virgil::service::data::VirgilUserIdTicket;

#include <virgil/service/data/VirgilUserIdType.h>
using virgil::service::data::VirgilUserIdType;

GEN_DESTRUCTOR(VirgilUserIdTicket, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_new_VirgilUserIdTicket(asUserId:ByteArray, asUserIdType:int):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_new_VirgilUserIdTicket() {
    VirgilByteArray cUserId;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asUserId, cUserId);

    VirgilUserIdType *cUserIdType = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cUserIdType, asUserIdType);

    VirgilUserIdTicket *cSelf = new VirgilUserIdTicket(cUserId, *cUserIdType);
    AS3_DeclareVar(asSelf, int);
    AS3_CopyScalarToVar(asSelf, cSelf);
    AS3_ReturnAS3Var(asSelf);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilUserIdTicket_userId(asSelf):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdTicket_userId() {
    VirgilUserIdTicket *cSelf = (VirgilUserIdTicket *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cUserId = cSelf->userId();
    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cUserId, asUserId);

    AS3_ReturnAS3Var(asUserId);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilUserIdTicket_userIdType(asSelf):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdTicket_userIdType() {
    VirgilUserIdTicket *cSelf = (VirgilUserIdTicket *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    const VirgilUserIdType& cUserIdType = cSelf->userIdType();

    AS3_DeclareVar(asUserIdType, int);
    AS3_CopyScalarToVar(asUserIdType, &cUserIdType);
    AS3_ReturnAS3Var(asUserIdType);
}
