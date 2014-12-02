#include <virgil/service/data/VirgilTicketId.h>
using virgil::service::data::VirgilTicketId;

GEN_CONSTRUCTOR(VirgilTicketId, com.virgilsecurity.wrapper)
GEN_DESTRUCTOR(VirgilTicketId, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilTicketId_ticketId(asSelf):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilTicketId_ticketId() {

    VirgilTicketId *cSelf = (VirgilTicketId *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cTicketId = cSelf->ticketId();
    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cTicketId, asTicketId);

    AS3_ReturnAS3Var(asTicketId);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilTicketId_setTicketId(asSelf, asTicketId:ByteArray):void"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilTicketId_setTicketId() {
    VirgilTicketId *cSelf = (VirgilTicketId *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cTicketId;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asTicketId, cTicketId);

    cSelf->setTicketId(cTicketId);

    AS3_ReturnAS3Var(undefined);
}
