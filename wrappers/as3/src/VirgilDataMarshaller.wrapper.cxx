#include <virgil/service/data/marshalling/VirgilDataMarshaller.h>
using virgil::service::data::marshalling::VirgilDataMarshaller;

#define GEN_MARSHALLER_WRAPPER(className, methodName) \
__attribute__(( \
    annotate("as3import:flash.utils.ByteArray"), \
    annotate("as3sig:public function _wrap_VirgilDataMarshaller_marshal"#className"(asSelf, asObject:int):ByteArray"), \
    annotate("as3package:com.virgilsecurity.wrapper") \
)) \
void _wrap_VirgilDataMarshaller_marshal##className() { \
    VirgilDataMarshaller *cSelf = (VirgilDataMarshaller *)0; \
    AS3_GetScalarFromVar(cSelf, asSelf); \
    className *cObject = (className *)0; \
    AS3_GetScalarFromVar(cObject, asObject); \
    VirgilByteArray cData = cSelf->methodName(*cObject); \
    VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cData, asData); \
    AS3_ReturnAS3Var(asData); \
}

#define GEN_DEMARSHALLER_WRAPPER(className, methodName) \
__attribute__(( \
    annotate("as3import:flash.utils.ByteArray"), \
    annotate("as3sig:public function _wrap_VirgilDataMarshaller_demarshal"#className"(asSelf, asData:ByteArray):int"), \
    annotate("as3package:com.virgilsecurity.wrapper") \
)) \
void _wrap_VirgilDataMarshaller_demarshal##className() { \
    VirgilDataMarshaller *cSelf = (VirgilDataMarshaller *)0; \
    AS3_GetScalarFromVar(cSelf, asSelf); \
    VirgilByteArray cData; \
    AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asData, cData); \
    className *cObject = cSelf->methodName(cData); \
    AS3_DeclareVar(asObject, int); \
    AS3_CopyScalarToVar(asObject, cObject); \
    AS3_ReturnAS3Var(asObject); \
}

GEN_MARSHALLER_WRAPPER(VirgilAccount, marshal)
GEN_DEMARSHALLER_WRAPPER(VirgilAccount, demarshalAccount)

GEN_MARSHALLER_WRAPPER(VirgilCertificate, marshal)
GEN_DEMARSHALLER_WRAPPER(VirgilCertificate, demarshalCertificate)

GEN_MARSHALLER_WRAPPER(VirgilTicket, marshal)
GEN_DEMARSHALLER_WRAPPER(VirgilTicket, demarshalTicket)

GEN_MARSHALLER_WRAPPER(VirgilSign, marshal)
GEN_DEMARSHALLER_WRAPPER(VirgilSign, demarshalSign)

#undef GEN_MARSHALLER_WRAPPER
#undef GEN_DEMARSHALLER_WRAPPER
