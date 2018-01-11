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
using Virgil.Crypto.Foundation;
using Virgil.CryptoAPI;

namespace Virgil.Crypto
{
    using System;
    using System.IO;
    using System.Text;

    /// <summary>
    /// The <see cref="VirgilCardCrypto"/> class provides a cryptographic operations in applications, such as hashing, 
    /// signature generation and verification, and encryption and decryption.
    /// </summary>
    public sealed class VirgilCardCrypto : ICardCrypto
    {
        private readonly VirgilCrypto virgilCrypto;

        /// <summary>
        /// Initializes a new instance of the <see cref="VirgilCardCrypto" /> class.
        /// </summary>
        public VirgilCardCrypto()
        {
            this.virgilCrypto = new VirgilCrypto();
        }
 
        /// <summary>
        /// Imports the Public key from material representation.
        /// </summary>
        /// <param name="keyData">public key material representation bytes.</param>
        /// <returns>Imported public key.</returns>
        /// <example>
        ///     <code>
        ///         var crypto = new VirgilCrypto();
        ///         var publicKey = crypto.ImportPublicKey(exportedPublicKey);
        ///     </code>
        /// </example>
        /// How to get exportedPublicKey <see cref="ExportPublicKey(IPublicKey)"/>    
        public IPublicKey ImportPublicKey(byte[] keyData)
        {
            return this.virgilCrypto.ImportPublicKey(keyData);
        }
       
        /// <summary>
        /// Exports the Public key into material representation.
        /// </summary>
        /// <param name="publicKey">public key for export.</param>
        /// <returns>Key material representation bytes.</returns>
        /// <example>
        ///     <code>
        ///         var crypto = new VirgilCrypto();
        ///         var keyPair = crypto.GenerateKeys();
        ///         var exportedPublicKey = crypto.ExportPublicKey(keyPair.PublicKey);
        ///     </code>
        /// </example>
        public byte[] ExportPublicKey(IPublicKey publicKey)
        {
            return this.virgilCrypto.ExportPublicKey(publicKey);
        }

        /// <summary>
        /// Signs the specified data using Private key. 
        /// </summary>
        /// <param name="data">raw data bytes for signing.</param>
        /// <param name="privateKey">private key for signing.</param>
        /// <returns>Signature data.</returns>
        /// <example>
        ///     <code>
        ///         var crypto = new VirgilCrypto();
        ///         var keyPair = crypto.GenerateKeys();
        ///         var data = Encoding.UTF8.GetBytes("Hello Bob!");
        ///         var sugnature = crypto.Sign(data, keyPair.PrivateKey);
        ///     </code>
        /// </example>
        public byte[] GenerateSignature(byte[] data, IPrivateKey privateKey)
        {
            return this.virgilCrypto.GenerateVirgilSignature(data, privateKey);
        }

        /// <summary>
        /// Verifies the specified signature using original data and signer's Public key.
        /// </summary>
        /// <param name="data"> original data bytes for verification.</param>
        /// <param name="signature">signature bytes for verification.</param>
        /// <param name="signerKey"> signer public key for verification.</param>
        /// <returns>True if signature is valid, False otherwise.</returns>
        /// <example>
        ///     <code>
        ///         var crypto = new VirgilCrypto();
        ///         var publicKey = crypto.ImportPublicKey(exportedPublicKey);
        ///         var data = Encoding.UTF8.GetBytes("Hello Bob!");
        ///         crypto.Verify(data, signature, publicKey)
        ///     </code>
        /// </example>
        /// How to get signature <see cref="GenerateSignature(byte[], IPrivateKey)"/>
        /// How to get exportedPublicKey <see cref="ExportPublicKey(IPublicKey)"/>     
        public bool VerifySignature(byte[] signature, byte[] data, IPublicKey signerKey)
        {
            return this.virgilCrypto.VerifyVirgilSignature(signature, data, signerKey);
        }
  
        /// <summary>
        /// Calculates the fingerprint.
        /// </summary>
        public byte[] GenerateSHA256(byte[] payload)
        {
            return this.virgilCrypto.GenerateSHA256(payload);
        }
    }
}