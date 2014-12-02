#include <virgil/service/data/VirgilSignId.h>
using virgil::service::data::VirgilSignId;

GEN_CONSTRUCTOR(VirgilSignId, com.virgilsecurity.wrapper)
GEN_DESTRUCTOR(VirgilSignId, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilSignId_signId(asSelf):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilSignId_signId() {

    VirgilSignId *cSelf = (VirgilSignId *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cSignId = cSelf->signId();
    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cSignId, asSignId);

    AS3_ReturnAS3Var(asSignId);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilSignId_setSignId(asSelf, asSignId:ByteArray):void"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilSignId_setSignId() {
    VirgilSignId *cSelf = (VirgilSignId *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cSignId;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asSignId, cSignId);

    cSelf->setSignId(cSignId);

    AS3_ReturnAS3Var(undefined);
}
