#include <virgil/service/stream/VirgilDataSource.h>
using virgil::service::stream::VirgilDataSource;

class VirgilDataSourceWrapper : public VirgilDataSource {
public:
    explicit VirgilDataSourceWrapper(const AS3::local::var& cDataSource) : cDataSource_(cDataSource) {
    }

    virtual bool hasData() {
        inline_as3("var asDataSource:* = null;");
        AS3_CopyVarxxToVar(asDataSource, cDataSource_);
        bool result = false;
        inline_as3(
            "%0 = asDataSource.hasData();"
            : "=r"(result)
        );
        return result;
    }

    __attribute__((
        annotate("as3import:flash.utils.ByteArray")
    ))
    virtual VirgilByteArray read() {
        inline_as3("var asDataSource:* = null;");
        AS3_CopyVarxxToVar(asDataSource, cDataSource_);
        inline_as3(
            ""
            "var asData:ByteArray = asDataSource.read();"
        );
        VirgilByteArray cData;
        AS3_BYTE_ARRAY_TO_VIRGIL_BYTE_ARRAY(asData, cData);
        return cData;
    }
    virtual ~VirgilDataSourceWrapper() throw() {}
private:
    AS3::local::var cDataSource_;
};
