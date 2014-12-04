/**
 * Copyright (C) 2014 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
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
 */

#ifndef VIRGIL_DATA_VIRGIL_STREAM_DATA_SINK_H
#define VIRGIL_DATA_VIRGIL_STREAM_DATA_SINK_H

#include <virgil/service/stream/VirgilDataSink.h>
using virgil::service::stream::VirgilDataSink;

#include <ostream>

namespace virgil { namespace service { namespace stream {

/**
 * @brief C++ stream implementation of the VirgilDataSink class.
 *
 * @note This class CAN not be used in wrappers.
 */
class VirgilStreamDataSink : public VirgilDataSink {
public:
    /**
     * @brief Creates data sink based on std::ostream object.
     */
    explicit VirgilStreamDataSink(std::ostream& out);
    /**
     * @brief Polymorphic destructor.
     */
    virtual ~VirgilStreamDataSink() throw();
    /**
     * @brief Overriding of @link VirgilDataSink::isGood() @endlink method.
     */
    virtual bool isGood();
    /**
     * @brief Overriding of @link VirgilDataSink::write() @endlink method.
     */
    virtual void write(const VirgilByteArray& data);
private:
    std::ostream& out_;
};

}}}

#endif /* VIRGIL_DATA_VIRGIL_STREAM_DATA_SINK_H */
