#region Copyright (C) Virgil Security Inc.
// Copyright (C) 2015-2018 Virgil Security Inc.
// 
// Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions 
// are met:
// 
//   (1) Redistributions of source code must retain the above copyright
//   notice, this list of conditions and the following disclaimer.
//   
//   (2) Redistributions in binary form must reproduce the above copyright
//   notice, this list of conditions and the following disclaimer in
//   the documentation and/or other materials provided with the
//   distribution.
//   
//   (3) Neither the name of the copyright holder nor the names of its
//   contributors may be used to endorse or promote products derived 
//   from this software without specific prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
// HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
// IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
#endregion

// ReSharper disable once CheckNamespace
using Virgil.CryptoAPI;

namespace Virgil.Crypto
{
    using System;

    internal static class VirgilCryptoExtentions
    {
        public static VirgilKeyPair.Type ToVirgilKeyPairType(KeyPairType keyPairType)
        {
            VirgilKeyPair.Type type;

            switch (keyPairType)
            {
                case KeyPairType.Default: type = VirgilKeyPair.Type.FAST_EC_ED25519; break;
                case KeyPairType.RSA_2048: type = VirgilKeyPair.Type.RSA_2048; break;
                case KeyPairType.RSA_3072: type = VirgilKeyPair.Type.RSA_3072; break;
                case KeyPairType.RSA_4096: type = VirgilKeyPair.Type.RSA_4096; break;
                case KeyPairType.RSA_8192: type = VirgilKeyPair.Type.RSA_8192; break;
                case KeyPairType.EC_SECP256R1: type = VirgilKeyPair.Type.EC_SECP256R1; break;
                case KeyPairType.EC_SECP384R1: type = VirgilKeyPair.Type.EC_SECP384R1; break;
                case KeyPairType.EC_SECP521R1: type = VirgilKeyPair.Type.EC_SECP521R1; break;
                case KeyPairType.EC_BP256R1: type = VirgilKeyPair.Type.EC_BP256R1; break;
                case KeyPairType.EC_BP384R1: type = VirgilKeyPair.Type.EC_BP384R1; break;
                case KeyPairType.EC_BP512R1: type = VirgilKeyPair.Type.EC_BP512R1; break;
                case KeyPairType.EC_SECP256K1: type = VirgilKeyPair.Type.EC_SECP256K1; break;
                case KeyPairType.EC_CURVE25519: type = VirgilKeyPair.Type.EC_CURVE25519; break;
                case KeyPairType.FAST_EC_X25519: type = VirgilKeyPair.Type.FAST_EC_X25519; break;
                case KeyPairType.FAST_EC_ED25519: type = VirgilKeyPair.Type.FAST_EC_ED25519; break;

                default:
                    throw new ArgumentOutOfRangeException("keyPairType", keyPairType, null);
            }

            return type;
        }

        internal static PublicKey Get(IPublicKey publicKey)
        {
            PublicKey theKey = publicKey as PublicKey;
            if (theKey != null)
            {
                return theKey;
            }

            throw new NotSupportedException();
        }

        internal static PrivateKey Get(IPrivateKey privateKey)
        {
            PrivateKey theKey = privateKey as PrivateKey;
            if (theKey != null)
            {
                return theKey;
            }

            throw new NotSupportedException();
        }
    }
}