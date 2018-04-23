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

#if VIRGIL_CRYPTO_FEATURE_PYTHIA

#include <virgil/crypto/pythia/virgil_pythia_c.h>

#include <virgil/crypto/pythia/VirgilPythiaContext.h>

#include <pythia/pythia_wrapper.h>

using virgil::crypto::pythia::VirgilPythiaContext;


int virgil_pythia_blind(
        const pythia_buf_t* password, pythia_buf_t* blinded_password,
        pythia_buf_t* blinding_secret) {

    VirgilPythiaContext context;
    return pythia_w_blind(password, blinded_password, blinding_secret);
}

int virgil_pythia_deblind(
        const pythia_buf_t* transformed_password, const pythia_buf_t* blinding_secret,
        pythia_buf_t* deblinded_password) {

    VirgilPythiaContext context;
    return pythia_w_deblind(transformed_password, blinding_secret, deblinded_password);
}

int virgil_pythia_compute_transformation_key_pair(const pythia_buf_t* transformation_key_id,
                                                  const pythia_buf_t* pythia_secret,
                                                  const pythia_buf_t* pythia_scope_secret,
                                                  pythia_buf_t* transformation_private_key,
                                                  pythia_buf_t* transformation_public_key) {

    VirgilPythiaContext context;
    return pythia_w_compute_transformation_key_pair(
            transformation_key_id, pythia_secret, pythia_scope_secret,
            transformation_private_key, transformation_public_key);
}

int virgil_pythia_transform(
        const pythia_buf_t* blinded_password, const pythia_buf_t* tweak,
        const pythia_buf_t* transformation_private_key,
        pythia_buf_t* transformed_password, pythia_buf_t* transformed_tweak) {

    VirgilPythiaContext context;
    return pythia_w_transform(
            blinded_password, tweak, transformation_private_key,
            transformed_password, transformed_tweak);
}

int virgil_pythia_prove(
        const pythia_buf_t* transformed_password, const pythia_buf_t* blinded_password,
        const pythia_buf_t* transformed_tweak, const pythia_buf_t* transformation_private_key,
        const pythia_buf_t* transformation_public_key, pythia_buf_t* proof_value_c, pythia_buf_t* proof_value_u) {

    VirgilPythiaContext context;
    return pythia_w_prove(
            transformed_password, blinded_password, transformed_tweak, transformation_private_key,
            transformation_public_key, proof_value_c, proof_value_u);
}

int virgil_pythia_verify(
        const pythia_buf_t* transformed_password, const pythia_buf_t* blinded_password,
        const pythia_buf_t* tweak, const pythia_buf_t* transformation_public_key,
        const pythia_buf_t* proof_value_c, const pythia_buf_t* proof_value_u, int* verified) {

    VirgilPythiaContext context;
    return pythia_w_verify(
            transformed_password, blinded_password, tweak, transformation_public_key, proof_value_c,
            proof_value_u, verified);
}

int virgil_pythia_get_password_update_token(
        const pythia_buf_t* previous_transformation_private_key,
        const pythia_buf_t* new_transformation_private_key,
        pythia_buf_t* password_update_token) {

    VirgilPythiaContext context;
    return pythia_w_get_password_update_token(
            previous_transformation_private_key, new_transformation_private_key,
            password_update_token);
}

int virgil_pythia_update_deblinded_with_token(
        const pythia_buf_t* deblinded_password, const pythia_buf_t* password_update_token,
        pythia_buf_t* updated_deblinded_password) {

    VirgilPythiaContext context;
    return pythia_w_update_deblinded_with_token(
            deblinded_password, password_update_token, updated_deblinded_password);
}

#endif /* VIRGIL_CRYPTO_FEATURE_PYTHIA */
