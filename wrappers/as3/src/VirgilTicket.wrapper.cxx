#include <virgil/service/data/VirgilTicket.h>
using virgil::service::data::VirgilTicket;

GEN_CONSTRUCTOR(VirgilTicket, com.virgilsecurity.wrapper)
GEN_DESTRUCTOR(VirgilTicket, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilTicket_id(asSelf):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilTicket_id() {

    VirgilTicket *cSelf = (VirgilTicket *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    const VirgilTicketId& cTicketId = cSelf->id();

    AS3_DeclareVar(asTicketId, int);
    AS3_CopyScalarToVar(asTicketId, &cTicketId);
    AS3_ReturnAS3Var(asTicketId);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilTicket_setId(asSelf, asTicketId:int):void"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilTicket_setId() {
    VirgilTicket *cSelf = (VirgilTicket *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilTicketId *cTicketId = (VirgilTicketId *)0;
    AS3_GetScalarFromVar(cTicketId, asTicketId);

    cSelf->setId(*cTicketId);

    AS3_ReturnAS3Var(undefined);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilTicket_isUserIdTicket(asSelf):Boolean"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilTicket_isUserIdTicket() {

    VirgilTicket *cSelf = (VirgilTicket *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    bool cIsUserIdTicket = cSelf->isUserIdTicket();

    AS3_Return(cIsUserIdTicket);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilTicket_asUserIdTicket(asSelf):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilTicket_asUserIdTicket() {
WRAPPER_THROWABLE_SECTION_START
    VirgilTicket *cSelf = (VirgilTicket *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    const virgil::service::data::VirgilUserIdTicket& cUserIdTicket = cSelf->asUserIdTicket();

    AS3_DeclareVar(asUserIdTicket, int);
    AS3_CopyScalarToVar(asUserIdTicket, &cUserIdTicket);
    AS3_ReturnAS3Var(asUserIdTicket);
WRAPPER_THROWABLE_SECTION_END
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilTicket_isUserInfoTicket(asSelf):Boolean"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilTicket_isUserInfoTicket() {

    VirgilTicket *cSelf = (VirgilTicket *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    bool cIsUserInfoTicket = cSelf->isUserInfoTicket();

    AS3_Return(cIsUserInfoTicket);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilTicket_asUserInfoTicket(asSelf):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilTicket_asUserInfoTicket() {
WRAPPER_THROWABLE_SECTION_START
    VirgilTicket *cSelf = (VirgilTicket *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    const virgil::service::data::VirgilUserInfoTicket& cUserInfoTicket = cSelf->asUserInfoTicket();

    AS3_DeclareVar(asUserInfoTicket, int);
    AS3_CopyScalarToVar(asUserInfoTicket, &cUserInfoTicket);
    AS3_ReturnAS3Var(asUserInfoTicket);
WRAPPER_THROWABLE_SECTION_END
}
