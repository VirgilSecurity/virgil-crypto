#include <virgil/service/data/VirgilUserInfoTicket.h>
using virgil::service::data::VirgilUserInfoTicket;

GEN_DESTRUCTOR(VirgilUserInfoTicket, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_new_VirgilUserInfoTicket"
            "(asUserFirstName:ByteArray, asUserLastName:ByteArray, asUserAge:uint):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_new_VirgilUserInfoTicket() {
    VirgilByteArray cUserFirstName;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asUserFirstName, cUserFirstName);

    VirgilByteArray cUserLastName;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asUserLastName, cUserLastName);

    size_t cUserAge = 0;
    AS3_GetScalarFromVar(cUserAge, asUserAge);

    VirgilUserInfoTicket *cSelf = new VirgilUserInfoTicket(cUserFirstName, cUserLastName, cUserAge);
    AS3_DeclareVar(asSelf, int);
    AS3_CopyScalarToVar(asSelf, cSelf);
    AS3_ReturnAS3Var(asSelf);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilUserInfoTicket_userFirstName(asSelf):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserInfoTicket_userFirstName() {
    VirgilUserInfoTicket *cSelf = (VirgilUserInfoTicket *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cUserFirstName = cSelf->userFirstName();
    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cUserFirstName, asUserFirstName);

    AS3_ReturnAS3Var(asUserFirstName);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilUserInfoTicket_userLastName(asSelf):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserInfoTicket_userLastName() {
    VirgilUserInfoTicket *cSelf = (VirgilUserInfoTicket *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cUserLastName = cSelf->userLastName();
    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cUserLastName, asUserLastName);

    AS3_ReturnAS3Var(asUserLastName);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilUserInfoTicket_userAge(asSelf):uint"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserInfoTicket_userAge() {
    VirgilUserInfoTicket *cSelf = (VirgilUserInfoTicket *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    uint cUserAge = cSelf->userAge();

    AS3_DeclareVar(asUserAge, uint);
    AS3_CopyScalarToVar(asUserAge, cUserAge);
    AS3_ReturnAS3Var(asUserAge);
}
