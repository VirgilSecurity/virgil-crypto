#include <virgil/service/stream/VirgilStreamDataSource.h>
using virgil::service::stream::VirgilStreamDataSource;

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include <algorithm>

static const size_t kChunkSizeMin = 32;

VirgilStreamDataSource::VirgilStreamDataSource(std::istream& in, size_t chunkSize)
        : in_(in), chunkSize_(std::max(chunkSize, kChunkSizeMin)) {
}

VirgilStreamDataSource::~VirgilStreamDataSource() throw() {
}

bool VirgilStreamDataSource::hasData() {
    return !in_.eof();
}

VirgilByteArray VirgilStreamDataSource::read() {
    size_t readBytesCount = 0;
    VirgilByteArray data;
    char byte;
    while (readBytesCount < chunkSize_ && in_.get(byte)) {
        data.push_back(byte);
    }
    return data;
}
