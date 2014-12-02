#include <virgil/service/data/VirgilAccount.h>
using virgil::service::data::VirgilAccount;

GEN_CONSTRUCTOR(VirgilAccount, com.virgilsecurity.wrapper)
GEN_DESTRUCTOR(VirgilAccount, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilAccount_id(asSelf):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilAccount_id() {

    VirgilAccount *cSelf = (VirgilAccount *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    const VirgilAccountId& cAccountId = cSelf->id();

    AS3_DeclareVar(asAccountId, int);
    AS3_CopyScalarToVar(asAccountId, &cAccountId);

    AS3_ReturnAS3Var(asAccountId);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilAccount_setId(asSelf, asAccountId:int):void"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilAccount_setId() {
    VirgilAccount *cSelf = (VirgilAccount *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilAccountId *cAccountId = (VirgilAccountId *)0;
    AS3_GetScalarFromVar(cAccountId, asAccountId);

    cSelf->setId(*cAccountId);

    AS3_ReturnAS3Var(undefined);
}
