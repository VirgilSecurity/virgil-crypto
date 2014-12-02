#include <virgil/service/data/VirgilCertificate.h>
using virgil::service::data::VirgilCertificate;

GEN_DESTRUCTOR(VirgilCertificate, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_new_VirgilCertificate(asPublicKey:ByteArray):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_new_VirgilCertificate() {
    VirgilByteArray cPublicKey;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asPublicKey, cPublicKey);

    VirgilCertificate *cSelf = new VirgilCertificate(cPublicKey);
    AS3_DeclareVar(asSelf, int);
    AS3_CopyScalarToVar(asSelf, cSelf);
    AS3_ReturnAS3Var(asSelf);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilCertificate_id(asSelf):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilCertificate_id() {

    VirgilCertificate *cSelf = (VirgilCertificate *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    const VirgilCertificateId& cCertificateId = cSelf->id();

    AS3_DeclareVar(asCertificateId, int);
    AS3_CopyScalarToVar(asCertificateId, &cCertificateId);

    AS3_ReturnAS3Var(asCertificateId);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilCertificate_setId(asSelf, asCertificateId:int):void"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilCertificate_setId() {
    VirgilCertificate *cSelf = (VirgilCertificate *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilCertificateId *cCertificateId = (VirgilCertificateId *)0;
    AS3_GetScalarFromVar(cCertificateId, asCertificateId);

    cSelf->setId(*cCertificateId);

    AS3_ReturnAS3Var(undefined);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilCertificate_publicKey(asSelf):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilCertificate_publicKey() {

    VirgilCertificate *cSelf = (VirgilCertificate *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cPublicKey = cSelf->publicKey();
    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cPublicKey, asPublicKey);

    AS3_ReturnAS3Var(asPublicKey);
}
