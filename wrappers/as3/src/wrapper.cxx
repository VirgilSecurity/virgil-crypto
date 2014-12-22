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

#include <cstdlib>
#include <cstddef>

#include <string>

#include <AS3/AS3.h>
#include <AS3/AS3++.h>

#include <virgil/wrapper_utils.h>

#include <virgil/VirgilByteArray.h>
using virgil::VirgilByteArray;

#include "VirgilRandom.wrapper.cxx"

#include "VirgilAccountId.wrapper.cxx"
#include "VirgilCertificateId.wrapper.cxx"
#include "VirgilTicketId.wrapper.cxx"
#include "VirgilSigntId.wrapper.cxx"

#include "VirgilAccount.wrapper.cxx"
#include "VirgilCertificate.wrapper.cxx"
#include "VirgilTicket.wrapper.cxx"
#include "VirgilUserIdType.wrapper.cxx"
#include "VirgilUserIdTicket.wrapper.cxx"
#include "VirgilUserInfoTicket.wrapper.cxx"
#include "VirgilSign.wrapper.cxx"

#include "VirgilKeyPair.wrapper.cxx"

#include "VirgilDataSource.wrapper.cxx"
#include "VirgilDataSink.wrapper.cxx"

#include "VirgilDataMarshaller.wrapper.cxx"
#include "VirgilJsonDataMarshaller.wrapper.cxx"
#include "VirgilAsn1DataMarshaller.wrapper.cxx"

#include "VirgilCipherDatagram.wrapper.cxx"
#include "VirgilCipherBase.wrapper.cxx"
#include "VirgilCipher.wrapper.cxx"
#include "VirgilStreamCipher.wrapper.cxx"
#include "VirgilChunkCipher.wrapper.cxx"
#include "VirgilSigner.wrapper.cxx"
#include "VirgilStreamSigner.wrapper.cxx"

int main() {
    AS3_GoAsync();
}
