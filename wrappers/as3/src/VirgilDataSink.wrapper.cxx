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
