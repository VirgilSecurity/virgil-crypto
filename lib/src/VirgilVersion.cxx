#include <virgil/crypto/VirgilVersion.h>
using virgil::crypto::VirgilVersion;

#include <cstddef>
#include <string>

size_t VirgilVersion::asNumber() {
    return (majorVersion() << 16) | (minorVersion() << 8) | patchVersion();
}

std::string VirgilVersion::asString() {
    return std::string("@VIRGIL_VERSION@");
}

size_t VirgilVersion::majorVersion() {
    return @VIRGIL_VERSION_MAJOR@;
}

size_t VirgilVersion::minorVersion() {
    return @VIRGIL_VERSION_MINOR@;
}

size_t VirgilVersion::patchVersion() {
    return @VIRGIL_VERSION_PATCH@;
}
