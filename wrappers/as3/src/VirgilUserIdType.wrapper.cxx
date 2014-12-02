#include <virgil/service/data/VirgilUserIdType.h>
using virgil::service::data::VirgilUserIdType;

GEN_DESTRUCTOR(VirgilUserIdType, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_email():int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_email() {
    const VirgilUserIdType& cSelf = VirgilUserIdType::email;
    AS3_DeclareVar(asSelf, int);
    AS3_CopyScalarToVar(asSelf, &cSelf);
    AS3_ReturnAS3Var(asSelf);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_phone():int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_phone() {
    const VirgilUserIdType& cSelf = VirgilUserIdType::phone;
    AS3_DeclareVar(asSelf, int);
    AS3_CopyScalarToVar(asSelf, &cSelf);
    AS3_ReturnAS3Var(asSelf);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_fax():int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_fax() {
    const VirgilUserIdType& cSelf = VirgilUserIdType::fax;
    AS3_DeclareVar(asSelf, int);
    AS3_CopyScalarToVar(asSelf, &cSelf);
    AS3_ReturnAS3Var(asSelf);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_domain():int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_domain() {
    const VirgilUserIdType& cSelf = VirgilUserIdType::domain;
    AS3_DeclareVar(asSelf, int);
    AS3_CopyScalarToVar(asSelf, &cSelf);
    AS3_ReturnAS3Var(asSelf);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_macAddress():int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_macAddress() {
    const VirgilUserIdType& cSelf = VirgilUserIdType::macAddress;
    AS3_DeclareVar(asSelf, int);
    AS3_CopyScalarToVar(asSelf, &cSelf);
    AS3_ReturnAS3Var(asSelf);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_application():int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_application() {
    const VirgilUserIdType& cSelf = VirgilUserIdType::application;
    AS3_DeclareVar(asSelf, int);
    AS3_CopyScalarToVar(asSelf, &cSelf);
    AS3_ReturnAS3Var(asSelf);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_isEmail(asSelf):Boolean"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_isEmail() {
    VirgilUserIdType *cSelf = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    bool cResult = (int)(cSelf->isEmail());

    AS3_DeclareVar(asResult, Boolean);
    AS3_CopyScalarToVar(asResult, cResult);
    AS3_ReturnAS3Var(asResult);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_isPhone(asSelf):Boolean"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_isPhone() {
    VirgilUserIdType *cSelf = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    bool cResult = (int)(cSelf->isPhone());

    AS3_DeclareVar(asResult, Boolean);
    AS3_CopyScalarToVar(asResult, cResult);
    AS3_ReturnAS3Var(asResult);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_isFax(asSelf):Boolean"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_isFax() {
    VirgilUserIdType *cSelf = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    bool cResult = (int)(cSelf->isFax());

    AS3_DeclareVar(asResult, Boolean);
    AS3_CopyScalarToVar(asResult, cResult);
    AS3_ReturnAS3Var(asResult);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_isDomain(asSelf):Boolean"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_isDomain() {
    VirgilUserIdType *cSelf = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    bool cResult = (int)(cSelf->isDomain());

    AS3_DeclareVar(asResult, Boolean);
    AS3_CopyScalarToVar(asResult, cResult);
    AS3_ReturnAS3Var(asResult);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_isMacAddress(asSelf):Boolean"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_isMacAddress() {
    VirgilUserIdType *cSelf = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    bool cResult = (int)(cSelf->isMacAddress());

    AS3_DeclareVar(asResult, Boolean);
    AS3_CopyScalarToVar(asResult, cResult);
    AS3_ReturnAS3Var(asResult);
}


__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_isApplication(asSelf):Boolean"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_isApplication() {
    VirgilUserIdType *cSelf = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    bool cResult = (int)(cSelf->isApplication());

    AS3_DeclareVar(asResult, Boolean);
    AS3_CopyScalarToVar(asResult, cResult);
    AS3_ReturnAS3Var(asResult);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_name(asSelf):String"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_name() {
    VirgilUserIdType *cSelf = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    std::string cName = cSelf->name();
    STD_STRING_TO_AS3_STRING(cName, asName);

    AS3_ReturnAS3Var(asName);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_code(asSelf):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_code() {
    VirgilUserIdType *cSelf = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    int cCode = (int)(cSelf->code());

    AS3_DeclareVar(asCode, int);
    AS3_CopyScalarToVar(asCode, cCode);
    AS3_ReturnAS3Var(asCode);
}

__attribute__((
    annotate("as3sig:public function _wrap_VirgilUserIdType_equals(asLeft:int, asRight:int):Boolean"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilUserIdType_equals() {
    VirgilUserIdType *cLeft = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cLeft, asLeft);

    VirgilUserIdType *cRight = (VirgilUserIdType *)0;
    AS3_GetScalarFromVar(cRight, asRight);

    bool cEqual = operator==(*cLeft, *cRight);

    AS3_DeclareVar(asCode, Boolean);
    AS3_CopyScalarToVar(asCode, cEqual);
    AS3_ReturnAS3Var(asCode);
}
