#include <virgil/VirgilVersion.h>
using virgil::VirgilVersion;

#include <cstddef>
#include <string>

size_t VirgilVersion::asHexNumber() {
    return (majorNumber() << 24) | (minorNumber() << 8) | patchNumber();
}

std::string VirgilVersion::asString() {
    return std::string(VIRGIL_VERSION);
}

size_t VirgilVersion::majorNumber() {
    return VIRGIL_VERSION_MAJOR;
}

size_t VirgilVersion::minorNumber() {
    return VIRGIL_VERSION_MINOR;
}

size_t VirgilVersion::patchNumber() {
    return VIRGIL_VERSION_PATCH;
}
