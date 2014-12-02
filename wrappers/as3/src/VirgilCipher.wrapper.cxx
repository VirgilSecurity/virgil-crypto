#include <virgil/service/VirgilCipher.h>
using virgil::service::VirgilCipher;

GEN_THROWABLE_CONSTRUCTOR(VirgilCipher, com.virgilsecurity.wrapper)
GEN_DESTRUCTOR(VirgilCipher, com.virgilsecurity.wrapper)

__attribute__((
    annotate("as3sig:public function _wrap_VirgilCipher_generateKeyPair():int"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilCipher_generateKeyPair() {

    VirgilKeyPair *cKeyPair = new VirgilKeyPair(VirgilCipher::generateKeyPair());

    AS3_DeclareVar(asKeyPair, int);
    AS3_CopyScalarToVar(asKeyPair, cKeyPair);
    AS3_ReturnAS3Var(asKeyPair);
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilCipher_encrypt"
            "(asSelf, asDataSource:*, asDataSink:*, asPublicKey:ByteArray):ByteArray"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilCipher_encrypt() {
WRAPPER_THROWABLE_SECTION_START
    VirgilCipher *cSelf = (VirgilCipher *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    AS3::local::var cDataSource;
    AS3_GetVarxxFromVar(cDataSource, asDataSource);
    VirgilDataSourceWrapper cDataSourceWrapper(cDataSource);

    AS3::local::var cDataSink;
    AS3_GetVarxxFromVar(cDataSink, asDataSink);
    VirgilDataSinkWrapper cDataSinkWrapper(cDataSink);

    VirgilByteArray cPublicKey;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asPublicKey, cPublicKey);

    VirgilByteArray cEncryptionKey = cSelf->encrypt(cDataSourceWrapper, cDataSinkWrapper, cPublicKey);

    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cEncryptionKey, asEncryptionKey);

    AS3_ReturnAS3Var(asEncryptionKey);
WRAPPER_THROWABLE_SECTION_END
}

__attribute__((
    annotate("as3import:flash.utils.ByteArray"),
    annotate("as3sig:public function _wrap_VirgilCipher_decrypt"
            "(asSelf, asDataSource:*, asDataSink:*, asEncryptionKey:ByteArray,"
            "asPrivateKey:ByteArray, asPrivateKeyPassword:ByteArray):void"),
    annotate("as3package:com.virgilsecurity.wrapper")
))
void _wrap_VirgilCipher_decrypt() {
WRAPPER_THROWABLE_SECTION_START
    VirgilCipher *cSelf = (VirgilCipher *)0;
    AS3_GetScalarFromVar(cSelf, asSelf);

    AS3::local::var cDataSource;
    AS3_GetVarxxFromVar(cDataSource, asDataSource);
    VirgilDataSourceWrapper cDataSourceWrapper(cDataSource);

    AS3::local::var cDataSink;
    AS3_GetVarxxFromVar(cDataSink, asDataSink);
    VirgilDataSinkWrapper cDataSinkWrapper(cDataSink);

    VirgilByteArray cEncryptionKey;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asEncryptionKey, cEncryptionKey);

    VirgilByteArray cPrivateKey;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asPrivateKey, cPrivateKey);

    VirgilByteArray cPrivateKeyPassword;
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asPrivateKeyPassword, cPrivateKeyPassword);

    cSelf->decrypt(cDataSourceWrapper, cDataSinkWrapper, cEncryptionKey, cPrivateKey, cPrivateKeyPassword);

    AS3_ReturnAS3Var(undefined);
WRAPPER_THROWABLE_SECTION_END
}
