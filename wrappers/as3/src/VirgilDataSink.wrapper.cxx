#include <virgil/service/stream/VirgilDataSink.h>
using virgil::service::stream::VirgilDataSink;

class VirgilDataSinkWrapper : public VirgilDataSink {
public:
    explicit VirgilDataSinkWrapper(const AS3::local::var& cDataSink) : cDataSink_(cDataSink) {
    }

    virtual bool isGood() {
        inline_as3("var asDataSink:* = null;");
        AS3_CopyVarxxToVar(asDataSink, cDataSink_);
        bool result = false;
        inline_as3(
            "%0 = asDataSink.isGood();"
            : "=r"(result)
        );
        return result;
    }

    __attribute__((
        annotate("as3import:flash.utils.ByteArray")
    ))
    virtual void write(const VirgilByteArray& cData) {
        VIRGIL_BYTE_ARRAY_TO_AS3_BYTE_ARRAY(cData, asData);

        inline_as3("var asDataSink:* = null;");
        AS3_CopyVarxxToVar(asDataSink, cDataSink_);
        inline_as3("asDataSink.write(asData);");
    }
    virtual ~VirgilDataSinkWrapper() throw() {}
private:
    AS3::local::var cDataSink_;
};
