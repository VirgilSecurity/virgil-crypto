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

#ifndef VIRGIL_DATA_VIRGIL_ID_PROVIDER_H
#define VIRGIL_DATA_VIRGIL_ID_PROVIDER_H

#include <virgil/service/data/VirgilJsonCompatible.h>
using virgil::service::data::VirgilJsonCompatible;

namespace virgil { namespace service { namespace data {

/**
 * @brief This class provides template with identifier accessors.
 */
template <typename ID>
class VirgilIdProvider : public VirgilJsonCompatible {
public:
    typedef ID value_type;
public:
    /**
     * @name Accessors
     */
    ///@{
    /**
     * @brief Return immutable Virgil Service identifier.
     */
    virtual const ID& id() const { return id_; }
    /**
     * @brief Return mutable Virgil Service identifier.
     */
    virtual ID& id() { return id_; }
    /**
     * @brief Set Virgil Service identifier.
     */
    virtual void setId(const ID& id) { id_ = id; }
    ///@}
    /**
     * @brief Polymorphic destructor.
     */
    virtual ~VirgilIdProvider() throw() {}
private:
    ID id_;
};

}}}

#endif /* VIRGIL_DATA_VIRGIL_ID_PROVIDER_H */
