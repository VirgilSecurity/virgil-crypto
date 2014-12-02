#include <virgil/crypto/VirgilRandom.h>
using virgil::crypto::VirgilRandom;

GEN_DESTRUCTOR(VirgilRandom, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_new_VirgilRandom(asPersonalInfo:ByteArray):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_new_VirgilRandom() {
    VirgilByteArray cPersonalInfo;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asPersonalInfo, cPersonalInfo);

    VirgilRandom *cSelf = new VirgilRandom(cPersonalInfo);
    AS3_DeclareVar(asSelf, int);
    AS3_CopyScalarToVar(asSelf, cSelf);
    AS3_ReturnAS3Var(asSelf);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilRandom_randomize(asSelf, asBytesNum:uint):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilRandom_randomize() {

    VirgilRandom *cSelf = (VirgilRandom *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    size_t cBytesNum = 0;
    AS3_GetScalarFromVar(cBytesNum, asBytesNum);

    VirgilByteArray cRandomBytes = cSelf->randomize(cBytesNum);
    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cRandomBytes, asRandomBytes);
    AS3_ReturnAS3Var(asRandomBytes);
}
