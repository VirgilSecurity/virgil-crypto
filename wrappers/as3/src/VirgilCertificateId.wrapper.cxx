#include <virgil/service/data/VirgilCertificateId.h>
using virgil::service::data::VirgilCertificateId;

GEN_CONSTRUCTOR(VirgilCertificateId, com.virgilsecurity.wrapper)
GEN_DESTRUCTOR(VirgilCertificateId, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilCertificateId_certificateId(asSelf):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilCertificateId_certificateId() {

    VirgilCertificateId *cSelf = (VirgilCertificateId *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cCertificateId = cSelf->certificateId();
    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cCertificateId, asCertificateId);

    AS3_ReturnAS3Var(asCertificateId);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilCertificateId_setCertificateId(asSelf, asCertificateId:ByteArray):void"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilCertificateId_setCertificateId() {
    VirgilCertificateId *cSelf = (VirgilCertificateId *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilByteArray cCertificateId;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asCertificateId, cCertificateId);

    cSelf->setCertificateId(cCertificateId);

    AS3_ReturnAS3Var(undefined);
}
