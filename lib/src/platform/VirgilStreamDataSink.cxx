#include <virgil/service/stream/VirgilStreamDataSink.h>
using virgil::service::stream::VirgilStreamDataSink;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

VirgilStreamDataSink::VirgilStreamDataSink(std::ostream& out) : out_(out) {
}

bool VirgilStreamDataSink::isGood() {
    return out_.good();
}

void VirgilStreamDataSink::write(const VirgilByteArray& data) {
    out_ << VIRGIL_BYTE_ARRAY_TO_STD_STRING(data);
}

VirgilStreamDataSink::~VirgilStreamDataSink() throw() {
}
