/**
 * Copyright (C) 2015-2018 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *    (1) Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 *    (2) Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 *    (3) Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived from
 *    this software without specific prior written permission.
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

#ifndef VIRGIL_PYTHIA_C_H
#define VIRGIL_PYTHIA_C_H

#include <pythia/pythia_buf.h>
#include <pythia/pythia_buf_sizes.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 *  @brief Blinds password.
 *
 *  Turns password into a pseudo-random string. This step is necessary to prevent
 *  3rd-parties from knowledge of end user's password.
 *
 *  @param [in] password end user's password.
 *  @param [out] G1 linded_password password obfuscated into a pseudo-random string.
 *  @param [out] BN blinding_secret random value used to blind user's password.
 *  @return 0 if succeeded, -1 otherwise
 */
int virgil_pythia_blind(
        const pythia_buf_t* password, pythia_buf_t* blinded_password,
        pythia_buf_t* blinding_secret);

/**
 *  @brief Transforms blinded password using the private key.
 *
 *  Private key is generated from pythia_secret + pythia_scope_secret.
 *
 *  @param [in] G1 blinded_password password obfuscated into a pseudo-random string.
 *  @param [in] transformation_key_id ensemble key ID used to enclose operations in subsets.
 *  @param [in] tweak some random value used to transform a password
 *  @param [in] pythia_secret global common for all secret random Key.
 *  @param [in] pythia_scope_secret ensemble secret generated and versioned transparently.
 *  @param [out] GT transformed_password blinded password, protected using server secret
 *          (pythia_secret + pythia_scope_secret + tweak).
 *  @param [out] BN transformation_private_key Pythia's private key which was generated using
 *          pythia_secret and pythia_scope_secret. This key is used to emit proof tokens
 *          (proof_value_c, proof_value_u).
 *  @param [out] G2 transformed_tweak tweak value turned into an elliptic curve point.
 *          This value is used by Prove() operation.
 *
 *  @return 0 if succeeded, -1 otherwise
 */
int virgil_pythia_transform(
        const pythia_buf_t* blinded_password, const pythia_buf_t* transformation_key_id,
        const pythia_buf_t* tweak, const pythia_buf_t* pythia_secret,
        const pythia_buf_t* pythia_scope_secret, pythia_buf_t* transformed_password,
        pythia_buf_t* transformation_private_key, pythia_buf_t* transformed_tweak);

/**
 *  Deblinds transformed_password value with previously returned blinding_secret from pythia_blind.
 *  @param [in] GT transformed_password transformed password from pythia_transform.
 *  @param [in] BN blinding_secret value that was generated in pythia_blind.
 *  @param [out] GT deblinded_password deblinded transformed_password value. This value is not
 *  equal to password and is zero-knowledge protected.
 *  @return 0 if succeeded, -1 otherwise
 */
int virgil_pythia_deblind(
        const pythia_buf_t* transformed_password, const pythia_buf_t* blinding_secret,
        pythia_buf_t* deblinded_password);

/**
 *  Generates proof that server possesses secret values that were used to transform password.
 *  @param [in] GT transformed_password transformed password from pythia_transform
 *  @param [in] G1 blinded_password blinded password from pythia_blind.
 *  @param [in] G2 transformed_tweak transformed tweak from pythia_transform.
 *  @param [in] BN transformation_private_key transformation private key from pythia_transform.
 *  @param [out] G1 transformation_public_key public key corresponding
 * to transformation_private_key value. This value is exposed to the client so he can verify, that
 * each and every Prove operation returns exactly the same value of transformation_public_key.
 *  @param [out] BN proof_value_c first part of proof that transformed+password was created
 *  using transformation_private_key.
 *  @param [out] BN proof_value_u second part of proof that transformed+password was created
 *  using transformation_private_key.
 *  @return 0 if succeeded, -1 otherwise
 */
int virgil_pythia_prove(
        const pythia_buf_t* transformed_password, const pythia_buf_t* blinded_password,
        const pythia_buf_t* transformed_tweak, const pythia_buf_t* transformation_private_key,
        pythia_buf_t* transformation_public_key, pythia_buf_t* proof_value_c,
        pythia_buf_t* proof_value_u);

/**
 *  This operation allows client to verify that the output of pythia_transform is correct, assuming
 *  that client has previously stored tweak. 
 *  @param [in] GT transformed_password transformed password from pythia_transform
 *  @param [in] G1 blinded_password blinded password from pythia_blind.
 *  @param [in] tweak tweak from pythia_transform
 *  @param [in] G1 transformation_public_key transformation public key from pythia_prove
 *  @param [in] BN proof_value_c proof value C from pythia_prove
 *  @param [in] BN proof_value_u proof value U from pythia_prove
 *  @param [out] verified 0 if verification failed, not 0 - otherwise
 *  @return 0 if succeeded, -1 otherwise
 */
int virgil_pythia_verify(
        const pythia_buf_t* transformed_password, const pythia_buf_t* blinded_password,
        const pythia_buf_t* tweak, const pythia_buf_t* transformation_public_key,
        const pythia_buf_t* proof_value_c, const pythia_buf_t* proof_value_u, int* verified);

/**
 *  Rotates old previous_transformation_key_id, previous_pythia_secret,
 * previous_pythia_scope_secret and generates a password_update_token that can
 * update deblinded_passwords. This action should increment version of the pythia_scope_secret.
 *  @param [in] previous_transformation_key_id previous transformation key id
 *  @param [in] previous_pythia_secret previous pythia secret
 *  @param [in] previous_pythia_scope_secret previous pythia scope secret
 *  @param [in] new_transformation_key_id new transformation key id
 *  @param [in] new_pythia_secret new pythia secret
 *  @param [in] new_pythia_scope_secret new pythia scope secret
 *  @param [out] BN password_update_token value that allows to update all deblinded passwords (one
 *  by one) after server issued new pythia_secret or pythia_scope_secret.
 *  @param [out] G1 updated_transformation_public_key public key corresponding to the new
 *  transformation_private_key after issuing password_update_token.
 *  @return 0 if succeeded, -1 otherwise
 */
int virgil_pythia_get_password_update_token(
        const pythia_buf_t* previous_transformation_key_id,
        const pythia_buf_t* previous_pythia_secret,
        const pythia_buf_t* previous_pythia_scope_secret,
        const pythia_buf_t* new_transformation_key_id, const pythia_buf_t* new_pythia_secret,
        const pythia_buf_t* new_pythia_scope_secret, pythia_buf_t* password_update_token,
        pythia_buf_t* updated_transformation_public_key);

/**
 *  Updates previously stored deblinded_password with password_update_token. After this call,
 *  pythia_transform called with new arguments will return corresponding values.
 *  @param [in] GT deblinded_password previous deblinded password from pythia_deblind.
 *  @param [in] BN password_update_token password update token from
 * pythia_get_password_update_token
 *  @param [out] GT updated_deblinded_password new deblinded password.
 *  @return 0 if succeeded, -1 otherwise
 */
int virgil_pythia_update_deblinded_with_token(
        const pythia_buf_t* deblinded_password, const pythia_buf_t* password_update_token,
        pythia_buf_t* updated_deblinded_password);

#ifdef __cplusplus
}
#endif

#endif // VIRGIL_PYTHIA_C_H
