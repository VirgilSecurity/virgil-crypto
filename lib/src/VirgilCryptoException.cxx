/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */

#include <virgil/crypto/VirgilCryptoException.h>

#include <sstream>
#include <tinyformat/tinyformat.h>

using virgil::crypto::VirgilCryptoException;

namespace virgil { namespace crypto { namespace internal {

static std::string format_message(const std::error_condition& condition) noexcept {
    try {
        return tfm::format("Module: %s. Error code: %s. %s",
                condition.category().name(), condition.value(), condition.message());
    } catch (...) {
        return std::string();
    }
}

static std::string format_message(const std::error_condition& condition, const std::string& what) noexcept {
    return tfm::format("%s %s", format_message(condition), what);
}

}}}

VirgilCryptoException::VirgilCryptoException(int ev, const std::error_category& ecat)
        : condition_(ev, ecat), what_(internal::format_message(condition_)) {
}

VirgilCryptoException::VirgilCryptoException(int ev, const std::error_category& ecat, const std::string& what)
        : condition_(ev, ecat), what_(internal::format_message(condition_, what)) {}

VirgilCryptoException::VirgilCryptoException(int ev, const std::error_category& ecat, const char* what)
        : condition_(ev, ecat), what_(internal::format_message(condition_, what)) {}

const char* VirgilCryptoException::what() const noexcept {
    return what_.c_str();
}

const std::error_condition& VirgilCryptoException::condition() const {
    return condition_;
}

std::string virgil::crypto::backtrace_exception(const std::exception& exception, size_t level) {
    std::ostringstream sstr;
    sstr << std::string(4 * level, ' ') << exception.what();
    try {
        std::rethrow_if_nested(exception);
    } catch(const std::exception& nested) {
        sstr << "\n" << backtrace_exception(nested, level + 1);
    } catch(...) {}
    return sstr.str();
}
