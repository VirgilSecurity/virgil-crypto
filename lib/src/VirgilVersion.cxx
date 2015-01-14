#include <virgil/VirgilVersion.h>
using virgil::VirgilVersion;

#include <cstddef>
#include <string>

size_t VirgilVersion::number() {
    return (major() << 24) | (minor() << 8) | patch();
}

std::string VirgilVersion::string() {
    return std::string(VIRGIL_VERSION);
}

size_t VirgilVersion::major() {
    return VIRGIL_VERSION_MAJOR;
}

size_t VirgilVersion::minor() {
    return VIRGIL_VERSION_MINOR;
}

size_t VirgilVersion::patch() {
    return VIRGIL_VERSION_PATCH;
}
