#include <virgil/service/data/VirgilKeyPair.h>
using virgil::service::data::VirgilKeyPair;

GEN_DESTRUCTOR(VirgilKeyPair, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_new_VirgilKeyPair(asPublicKey:ByteArray, asPrivateKey:ByteArray):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_new_VirgilKeyPair() {
    VirgilByteArray cPublicKey;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asPublicKey, cPublicKey);

    VirgilByteArray cPrivateKey;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asPrivateKey, cPrivateKey);

    VirgilKeyPair *cSelf = new VirgilKeyPair(cPublicKey, cPrivateKey);
    AS3_DeclareVar(asSelf, int);
    AS3_CopyScalarToVar(asSelf, cSelf);
    AS3_ReturnAS3Var(asSelf);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilKeyPair_publicKey(asSelf):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilKeyPair_publicKey() {
    VirgilKeyPair *cSelf = (VirgilKeyPair *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cPublicKey = cSelf->publicKey();
    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cPublicKey, asPublicKey);

    AS3_ReturnAS3Var(asPublicKey);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilKeyPair_privateKey(asSelf):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilKeyPair_privateKey() {
    VirgilKeyPair *cSelf = (VirgilKeyPair *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cPrivateKey = cSelf->privateKey();
    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cPrivateKey, asPrivateKey);

    AS3_ReturnAS3Var(asPrivateKey);
}
