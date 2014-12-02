#include <virgil/service/VirgilSigner.h>
using virgil::service::VirgilSigner;

GEN_CONSTRUCTOR(VirgilSigner, com.virgilsecurity.wrapper)
GEN_DESTRUCTOR(VirgilSigner, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilSigner_sign"
            "(asSelf, asDataSource:*, asSignerCertificate:int,"
            "asPrivateKey:ByteArray, asPrivateKeyPassword:ByteArray):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilSigner_sign() {
WRAPPER_THROWABLE_SECTION_START
    VirgilSigner *cSelf = (VirgilSigner *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    AS3::local::var cDataSource;
    AS3_GetVarxxFromVar(cDataSource, asDataSource);
    VirgilDataSourceWrapper cDataSourceWrapper(cDataSource);

    VirgilCertificate *cSignerCertificate = (VirgilCertificate *)0;
    AS3_GetScalarFromVar(cSignerCertificate, asSignerCertificate);

    VirgilByteArray cPrivateKey;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asPrivateKey, cPrivateKey);

    VirgilByteArray cPrivateKeyPassword;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asPrivateKeyPassword, cPrivateKeyPassword);

    VirgilSign *cSign = new VirgilSign(
            cSelf->sign(cDataSourceWrapper, *cSignerCertificate, cPrivateKey, cPrivateKeyPassword));

    AS3_DeclareVar(asSign, int);
    AS3_CopyScalarToVar(asSign, cSign);
    AS3_ReturnAS3Var(asSign);
WRAPPER_THROWABLE_SECTION_END
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilSigner_verify(asSelf, asDataSource:*, asSign:int):Boolean"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilSigner_verify() {
WRAPPER_THROWABLE_SECTION_START
    VirgilSigner *cSelf = (VirgilSigner *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    AS3::local::var cDataSource;
    AS3_GetVarxxFromVar(cDataSource, asDataSource);
    VirgilDataSourceWrapper cDataSourceWrapper(cDataSource);

    VirgilSign *cSign = (VirgilSign *)0;
    AS3_GetScalarFromVar(cSign, asSign);

    bool cVerified = cSelf->verify(cDataSourceWrapper, *cSign);

    AS3_DeclareVar(asVerified, Boolean);
    AS3_CopyScalarToVar(asVerified, cVerified);
    AS3_ReturnAS3Var(asVerified);
WRAPPER_THROWABLE_SECTION_END
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilSigner_signTicket"
            "(asSelf, asTicket:int, asSignerCertificate:int,"
            "asPrivateKey:ByteArray, asPrivateKeyPassword:ByteArray):int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilSigner_signTicket() {
WRAPPER_THROWABLE_SECTION_START
    VirgilSigner *cSelf = (VirgilSigner *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilTicket *cTicket = (VirgilTicket *)0;
    AS3_GetScalarFromVar(cTicket, asTicket);

    VirgilCertificate *cSignerCertificate = (VirgilCertificate *)0;
    AS3_GetScalarFromVar(cSignerCertificate, asSignerCertificate);

    VirgilByteArray cPrivateKey;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asPrivateKey, cPrivateKey);

    VirgilByteArray cPrivateKeyPassword;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asPrivateKeyPassword, cPrivateKeyPassword);

    VirgilSign *cSign = new VirgilSign(
            cSelf->sign(*cTicket, *cSignerCertificate, cPrivateKey, cPrivateKeyPassword));

    AS3_DeclareVar(asSign, int);
    AS3_CopyScalarToVar(asSign, cSign);
    AS3_ReturnAS3Var(asSign);
WRAPPER_THROWABLE_SECTION_END
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilSigner_verifyTicket(asSelf, asTicket:int, asSign:int):Boolean"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilSigner_verifyTicket() {
WRAPPER_THROWABLE_SECTION_START
    VirgilSigner *cSelf = (VirgilSigner *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    VirgilTicket *cTicket = (VirgilTicket *)0;
    AS3_GetScalarFromVar(cTicket, asTicket);

    VirgilSign *cSign = (VirgilSign *)0;
    AS3_GetScalarFromVar(cSign, asSign);

    bool cVerified = cSelf->verify(*cTicket, *cSign);

    AS3_DeclareVar(asVerified, Boolean);
    AS3_CopyScalarToVar(asVerified, cVerified);
    AS3_ReturnAS3Var(asVerified);
WRAPPER_THROWABLE_SECTION_END
}
