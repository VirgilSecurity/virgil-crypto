using System;
using System.Collections.Generic;
using System.Text;

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
    public sealed class VirgilCrypto
    {
        private readonly KeyPairType defaultKeyPairType;
        private readonly byte[] CustomParamKeySignature = Encoding.UTF8.GetBytes("VIRGIL-DATA-SIGNATURE");
        private readonly byte[] CustomParamKeySignerId = Encoding.UTF8.GetBytes("VIRGIL-DATA-SIGNER-ID");

        /// <summary>
        /// Initializes a new instance of the <see cref="VirgilCardCrypto" /> class.
        /// </summary>
        /// <param name="defaultKeyPairType">Default type of the key pair.</param>
        public VirgilCrypto(KeyPairType defaultKeyPairType)
        {
            this.defaultKeyPairType = defaultKeyPairType;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="VirgilCardCrypto" /> class.
        /// </summary>
        public VirgilCrypto()
        {
            this.defaultKeyPairType = KeyPairType.Default;
        }

        /// <summary>
        /// Generates asymmetric key pair that is comprised of both public and private keys by specified type.
        /// </summary>
        /// <param name="keyPairType">type of the generated keys.
        ///   The possible values can be found in <see cref="KeyPairType"/>.</param>
        /// <returns>Generated key pair with type EC_SECP256R1.</returns>
        /// <example>
        ///     <code>
        ///         var crypto = new VirgilCrypto();
        ///         var keyPair = crypto.GenerateKeys(KeyPairType.EC_SECP256R1);
        ///     </code>
        /// </example>
        public KeyPair GenerateVirgilKeys(KeyPairType keyPairType)
        {
            try
            {
                using (VirgilKeyPair keyPair = VirgilKeyPair.Generate(VirgilCryptoExtentions.ToVirgilKeyPairType(keyPairType)))
                {
                    byte[] keyPairId = this.ComputePublicKeyHash(keyPair.PublicKey());
                    PrivateKey privateKey = new PrivateKey();
                    privateKey.ReceiverId = keyPairId;
                    privateKey.Value = VirgilKeyPair.PrivateKeyToDER(keyPair.PrivateKey());

                    PublicKey publicKey = new PublicKey();
                    publicKey.ReceiverId = keyPairId;
                    publicKey.Value = VirgilKeyPair.PublicKeyToDER(keyPair.PublicKey());

                    return new KeyPair(publicKey, privateKey);
                }
            }
            catch (Exception ex)
            {
                throw new VirgilCryptoException(ex.Message);
            }
        }

        /// <summary>
        /// Generates recommended asymmetric key pair that is comprised of both Public and Private keys.
        /// </summary>
        /// <returns>Generated key pair.</returns>
        /// <example>
        ///     <code>
        ///         var crypto = new VirgilCrypto();
        ///         var keyPair = crypto.GenerateKeys();
        ///     </code>
        /// </example>
        public KeyPair GenerateVirgilKeys()
        {
            return this.GenerateVirgilKeys(this.defaultKeyPairType);
        }

        /// <summary>
        /// Imports the Private key from material representation.
        /// </summary>
        /// <example>
        ///     <code>
        ///         var crypto = new VirgilCrypto();
        ///         var publicKey = crypto.ImportPrivateKey(exportedPrivateKey, password);
        ///     </code>
        /// </example>
        /// How to get exportedPrivateKey <see cref="ExportVirgilPrivateKey"/>
        public IPrivateKey ImportVirgilPrivateKey(byte[] keyBytes, string password)
        {
            if (keyBytes == null)
                throw new ArgumentNullException("keyBytes");

            try
            {
                byte[] privateKeyBytes = string.IsNullOrEmpty(password)
                    ? keyBytes
                    : VirgilKeyPair.DecryptPrivateKey(keyBytes, Encoding.UTF8.GetBytes(password));

                byte[] publicKey = VirgilKeyPair.ExtractPublicKey(privateKeyBytes, new byte[] { });
                PrivateKey privateKey = new PrivateKey();
                privateKey.ReceiverId = this.ComputePublicKeyHash(publicKey);
                privateKey.Value = VirgilKeyPair.PrivateKeyToDER(privateKeyBytes);

                return privateKey;
            }
            catch (Exception ex)
            {
                throw new VirgilCryptoException(ex.Message);
            }
        }

        /// <summary>
        /// Imports the Private key from material representation.
        /// </summary>
        /// <example>
        ///     <code>
        ///         var crypto = new VirgilCrypto();
        ///         var publicKey = crypto.ImportPrivateKey(exportedPrivateKey);
        ///     </code>
        /// </example>
        /// How to get exportedPrivateKey <see cref="ExportVirgilPrivateKey"/>
        public IPrivateKey ImportVirgilPrivateKey(byte[] keyBytes)
        {
            return ImportVirgilPrivateKey(keyBytes, null);
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
            try
            {
                PublicKey publicKey = new PublicKey();
                publicKey.ReceiverId = this.ComputePublicKeyHash(keyData);
                publicKey.Value = VirgilKeyPair.PublicKeyToDER(keyData);

                return publicKey;
            }
            catch (Exception ex)
            {
                throw new VirgilCryptoException(ex.Message);
            }
        }

        /// <summary>
        /// Exports the Private key into material representation.
        /// </summary>
        public byte[] ExportVirgilPrivateKey(IPrivateKey privateKey, string password)
        {
            try
            {
                if (string.IsNullOrEmpty(password))
                {
                    return VirgilKeyPair.PrivateKeyToDER(VirgilCryptoExtentions.Get(privateKey).Value);
                }

                byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
                byte[] encryptedKey = VirgilKeyPair.EncryptPrivateKey(VirgilCryptoExtentions.Get(privateKey).Value,
                    passwordBytes);

                return VirgilKeyPair.PrivateKeyToDER(encryptedKey, passwordBytes);
            }
            catch (Exception ex)
            {
                throw new VirgilCryptoException(ex.Message);
            }
        }


        /// <summary>
        /// Exports the Private key into material representation.
        /// </summary>
        public byte[] ExportVirgilPrivateKey(IPrivateKey privateKey)
        {
            return ExportVirgilPrivateKey(privateKey, null);
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
            try
            {
                return VirgilKeyPair.PublicKeyToDER(VirgilCryptoExtentions.Get(publicKey).Value);
            }
            catch (Exception ex)
            {
                throw new VirgilCryptoException(ex.Message);
            }
        }

        /// <summary>
        /// Extracts the Public key from Private key.
        /// </summary>
        public IPublicKey ExtractVirgilPublicKey(IPrivateKey privateKey)
        {
            try
            {
                byte[] publicKeyData = VirgilKeyPair.ExtractPublicKey(
                    VirgilCryptoExtentions.Get(privateKey).Value, new byte[] { });

                PublicKey publicKey = new PublicKey();
                publicKey.ReceiverId = VirgilCryptoExtentions.Get(privateKey).ReceiverId;
                publicKey.Value = VirgilKeyPair.PublicKeyToDER(publicKeyData);

                return publicKey;
            }
            catch (Exception ex)
            {
                throw new VirgilCryptoException(ex.Message);
            }
        }


        /// <summary>
        /// Encrypts the specified data using recipients Public keys.
        /// </summary>
        /// <param name="data">raw data bytes for encryption.</param>
        /// <param name="recipients"> list of recipients' public keys.</param>
        /// <returns>Encrypted bytes.</returns>
        /// <example>
        ///     <code>
        ///         var crypto = new VirgilCrypto();
        ///         var keyPair = crypto.GenerateKeys();
        ///         var data = Encoding.UTF8.GetBytes("Encrypt me!");
        ///         var encryptedData = crypto.Encrypt(data, keyPair.PublicKey);
        ///     </code>
        /// </example>
        public byte[] Encrypt(byte[] data, params IPublicKey[] recipients)
        {
            try
            {
                using (VirgilCipher cipher = new VirgilCipher())
                {
                    foreach (IPublicKey publicKey in recipients)
                    {
                        cipher.AddKeyRecipient(VirgilCryptoExtentions.Get(publicKey).ReceiverId,
                            VirgilCryptoExtentions.Get(publicKey).Value);
                    }

                    byte[] encryptedData = cipher.Encrypt(data, true);
                    return encryptedData;
                }
            }
            catch (Exception ex)
            {
                throw new VirgilCryptoException(ex.Message);
            }
        }


        /// <summary>
        /// Decrypts the specified data using Private key.
        /// </summary>
        /// <param name="cipherData">encrypted data bytes for decryption.</param>
        /// <param name="privateKey">private key for decryption.</param>
        /// <returns>Decrypted data bytes.</returns>
        /// <example>
        ///     <code>
        ///         var crypto = new VirgilCrypto();
        ///         var keyPair = crypto.GenerateKeys();
        ///         var plainData = crypto.Decrypt(encryptedData, keyPair.PrivateKey);
        ///     </code>
        /// </example>
        /// How to get encryptedData <see cref="Encrypt(byte[], IPublicKey[])"/>
        public byte[] Decrypt(byte[] cipherData, IPrivateKey privateKey)
        {
            try
            {
                using (VirgilCipher cipher = new VirgilCipher())
                {
                    byte[] data = cipher.DecryptWithKey(cipherData,
                        VirgilCryptoExtentions.Get(privateKey).ReceiverId,
                        VirgilCryptoExtentions.Get(privateKey).Value);
                    return data;
                }
            }
            catch (Exception ex)
            {
                throw new VirgilCryptoException(ex.Message);
            }
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
        public byte[] GenerateVirgilSignature(byte[] data, IPrivateKey privateKey)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            if (privateKey == null)
                throw new ArgumentNullException("privateKey");

            try
            {
                using (VirgilSigner signer = new VirgilSigner())
                {
                    byte[] signature = signer.Sign(data, VirgilCryptoExtentions.Get(privateKey).Value);
                    return signature;
                }
            }
            catch (Exception ex)
            {
                throw new VirgilCryptoException(ex.Message);
            }
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
        /// How to get signature <see cref="GenerateVirgilSignature"/>
        /// How to get exportedPublicKey <see cref="ExportPublicKey(IPublicKey)"/>     
        public bool VerifyVirgilSignature(byte[] signature, byte[] data, IPublicKey signerKey)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            if (signature == null)
                throw new ArgumentNullException("signature");

            try
            {
                using (VirgilSigner virgilSigner = new VirgilSigner())
                {
                    bool isValid = virgilSigner.Verify(data, signature, VirgilCryptoExtentions.Get(signerKey).Value);
                    return isValid;
                }
            }
            catch (Exception ex)
            {
                throw new VirgilCryptoException(ex.Message);
            }
        }

        /// <summary>
        /// Encrypts the specified stream using recipients Public keys.
        /// </summary>
        /// <param name="inputStream">readable stream containing input bytes.</param>
        /// <param name="cipherStream">writable stream for output.</param>
        /// <param name="recipients"> list of recipients' public keys.</param>
        /// <returns>Encrypted bytes.</returns>
        /// <example>
        ///     <code>
        ///         var crypto = new VirgilCrypto();
        ///         var aliceKeyPair = crypto.GenerateKeys();
        ///         var bobKeyPair = crypto.GenerateKeys();
        ///         using (var inputStream = new FileStream("[YOUR_FILE_PATH_HERE]", 
        ///         FileMode.Open, FileAccess.Read))
        ///         {
        ///             using (var cipherStream = new FileStream("[YOUR_CIPHER_FILE_PATH_HERE]", 
        ///             FileMode.Create, FileAccess.Write))
        ///             {
        ///                crypto.Encrypt(inputStream, cipherStream, aliceKeyPair.PublicKey, bobKeyPair.PublicKey);
        ///             }
        ///          }
        ///     </code>
        /// </example>
        public void Encrypt(Stream inputStream, Stream cipherStream, params IPublicKey[] recipients)
        {
            try
            {
                using (VirgilChunkCipher cipher = new VirgilChunkCipher())
                using (VirgilStreamDataSource source = new VirgilStreamDataSource(inputStream))
                using (VirgilStreamDataSink sink = new VirgilStreamDataSink(cipherStream))
                {
                    foreach (IPublicKey publicKey in recipients)
                    {
                        cipher.AddKeyRecipient(VirgilCryptoExtentions.Get(publicKey).ReceiverId,
                            VirgilCryptoExtentions.Get(publicKey).Value);
                    }

                    cipher.Encrypt(source, sink);
                }
            }
            catch (Exception ex)
            {
                throw new VirgilCryptoException(ex.Message);
            }
        }


        /// <summary>
        /// Decrypts the specified stream using Private key.
        /// <param name="cipherStream">readable stream containing encrypted data.</param>
        /// <param name="outputStream">writable stream for output.</param>
        /// <param name="privateKey">private key for decryption.</param>
        /// </summary>
        /// <example>
        ///     <code>
        ///         var crypto = new VirgilCrypto();
        ///         var alicePrivateKey = crypto.ImportPrivateKey(exportedPrivateKey);
        ///         using (var encryptedStream = new FileStream("[YOUR_CIPHER_FILE_PATH_HERE]", 
        ///                 FileMode.Open, FileAccess.Read))
        ///         {
        ///             using (var decryptedStream = new FileStream("[YOUR_DECRYPTED_FILE_PATH_HERE]", 
        ///                     FileMode.Create, FileAccess.Write))
        ///             {
        ///                 crypto.Decrypt(encryptedStream, decryptedStream, alicePrivateKey);
        ///             }
        ///          }
        ///     </code>
        /// </example>
        /// <remarks>How to get encryptedStream <see cref="Encrypt(Stream, Stream, IPublicKey[])"/></remarks>
        /// <remarks>How to get exportedPrivateKey <see cref="ExportVirgilPrivateKey"/> </remarks>
        public void Decrypt(Stream cipherStream, Stream outputStream, IPrivateKey privateKey)
        {
            try
            {
                using (VirgilChunkCipher cipher = new VirgilChunkCipher())
                using (VirgilStreamDataSource source = new VirgilStreamDataSource(cipherStream))
                using (VirgilStreamDataSink sink = new VirgilStreamDataSink(outputStream))
                {
                    cipher.DecryptWithKey(source, sink, VirgilCryptoExtentions.Get(privateKey).ReceiverId,
                        VirgilCryptoExtentions.Get(privateKey).Value);
                }
            }
            catch (Exception ex)
            {
                throw new VirgilCryptoException(ex.Message);
            }
        }


        /// <summary>
        /// Signs and encrypts the data.
        /// </summary>
        /// <param name="data">The data to encrypt.</param>
        /// <param name="privateKey">The Private key to sign the data.</param>
        /// <param name="recipients">The list of Public key recipients to encrypt the data.</param>
        /// <returns>Signed and encrypted data bytes.</returns>
        /// <exception cref="Virgil.Crypto.VirgilCryptoException"></exception>
        /// <example>
        ///   <code>
        ///     var crypto = new VirgilCrypto();
        /// 
        ///     var alice = crypto.GenerateKeys();
        ///     var bob = crypto.GenerateKeys();
        ///     var originalData = Encoding.UTF8.GetBytes("Hello Bob, How are you?");
        ///     // The data to be signed with Alice's Private key and then encrypted for Bob.
        ///     var cipherData = crypto.SignThenEncrypt(originalData, alice.PrivateKey, bob.PublicKey);
        ///   </code>
        /// </example>
        public byte[] SignThenEncrypt(byte[] data, IPrivateKey privateKey, params IPublicKey[] recipients)
        {
            try
            {
                using (VirgilSigner signer = new VirgilSigner())
                using (VirgilCipher cipher = new VirgilCipher())
                {
                    byte[] signature = signer.Sign(data, VirgilCryptoExtentions.Get(privateKey).Value);

                    VirgilCustomParams customData = cipher.CustomParams();
                    customData.SetData(this.CustomParamKeySignature, signature);

                    IPublicKey publicKey = this.ExtractVirgilPublicKey(privateKey);

                    customData.SetData(this.CustomParamKeySignerId, VirgilCryptoExtentions.Get(publicKey).ReceiverId);

                    foreach (IPublicKey recipientPublicKey in recipients)
                    {
                        cipher.AddKeyRecipient(VirgilCryptoExtentions.Get(recipientPublicKey).ReceiverId,
                            VirgilCryptoExtentions.Get(recipientPublicKey).Value);
                    }

                    return cipher.Encrypt(data, true);
                }
            }
            catch (Exception ex)
            {
                throw new VirgilCryptoException(ex.Message);
            }
        }

        /// <summary>
        /// Decrypts and verifies the data.
        /// </summary>
        /// <param name="cipherData">The cipher data.</param>
        /// <param name="privateKey">The Private key to decrypt.</param>
        /// <param name="publicKeys"> The list of trusted public keys for verification, 
        /// which can contain signer's public key.</param>
        /// <returns>The decrypted data</returns>
        /// <exception cref="VirgilCryptoException"></exception>
        /// <example>
        ///     <code>
        ///         var crypto = new VirgilCrypto();
        ///         var decryptedData = crypto.DecryptThenVerify(cipherData, bob.PrivateKey, alice.PublicKey);
        ///     </code>
        /// </example>
        /// How to get cipherData as well as Alice's and Bob's key pairs.
        /// <see cref="SignThenEncrypt(byte[], IPrivateKey, IPublicKey[])"/>
        public byte[] DecryptThenVerify(byte[] cipherData, IPrivateKey privateKey, params IPublicKey[] publicKeys)
        {
            try
            {
                using (VirgilSigner signer = new VirgilSigner())
                using (VirgilCipher cipher = new VirgilCipher())
                {
                    byte[] decryptedData =
                        cipher.DecryptWithKey(cipherData, VirgilCryptoExtentions.Get(privateKey).ReceiverId,
                        VirgilCryptoExtentions.Get(privateKey).Value);
                    byte[] signature = cipher.CustomParams().GetData(this.CustomParamKeySignature);

                    IPublicKey signerPublicKey = (publicKeys.Length > 0) ? publicKeys[0] : null;
                    if (publicKeys.Length > 1)
                    {
                        byte[] signerId = cipher.CustomParams().GetData(this.CustomParamKeySignerId);
                        signerPublicKey = FindPublicKeyBySignerId(publicKeys, signerId);
                    }

                    bool isValid = signer.Verify(decryptedData, signature, VirgilCryptoExtentions.Get(signerPublicKey).Value);
                    if (!isValid)
                        throw new VirgilCryptoException("Signature is not valid.");

                    return decryptedData;
                }
            }
            catch (Exception ex)
            {
                throw new VirgilCryptoException(ex.Message);
            }
        }


        /// <summary>
        /// Signs the specified stream using Private key. 
        /// </summary>
        /// <param name="inputStream">readable stream containing input data.</param>
        /// <param name="privateKey">private key for signing.</param>
        /// <returns>Signature data.</returns>
        /// <example>
        ///     <code>
        ///         var crypto = new VirgilCrypto();
        ///         var keyPair = crypto.GenerateKeys();
        ///         using (var inputStream = new FileStream("[YOUR_FILE_PATH_HERE]", FileMode.Open, FileAccess.Read))
        ///         {
        ///             signature = crypto.Sign(inputStream, keyPair.PrivateKey);
        ///         }
        ///     </code>
        /// </example>
        public byte[] Sign(Stream inputStream, IPrivateKey privateKey)
        {
            try
            {
                using (VirgilStreamSigner signer = new VirgilStreamSigner())
                using (VirgilStreamDataSource source = new VirgilStreamDataSource(inputStream))
                {
                    byte[] signature = signer.Sign(source, VirgilCryptoExtentions.Get(privateKey).Value);
                    return signature;
                }
            }
            catch (Exception ex)
            {
                throw new VirgilCryptoException(ex.Message);
            }
        }

        /// <summary>
        /// Calculates the fingerprint.
        /// </summary>
        public byte[] GenerateSHA256(byte[] payload)
        {
            if (payload == null)
                throw new ArgumentNullException("payload");

            try
            {
                using (VirgilHash sha256 = new VirgilHash(VirgilHash.Algorithm.SHA256))
                {
                    byte[] hash = sha256.Hash(payload);
                    return hash;
                }
            }
            catch (Exception ex)
            {
                throw new VirgilCryptoException(ex.Message);
            }
        }

        /// <summary>
        /// Computes the hash of specified data.
        /// </summary>
        public byte[] ComputeHash(byte[] data, HashAlgorithm algorithm)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            VirgilHash.Algorithm virgilHashAlg = (VirgilHash.Algorithm)algorithm;
            VirgilHash hasher = new VirgilHash(virgilHashAlg);

            try
            {
                using (hasher)
                {
                    return hasher.Hash(data);
                }
            }
            catch (Exception ex)
            {
                throw new VirgilCryptoException(ex.Message);
            }
        }

        /// <summary>
        /// Verifies the specified signature using original stream and signer's Public key.
        /// </summary>
        /// <param name="inputStream">readable stream containing input data.</param>
        /// <param name="publicKey">signer public key for verification.</param>
        /// <param name="signature">signature bytes for verification.</param>
        /// <returns>True if signature is valid, False otherwise.</returns>
        /// <example>
        /// <code>
        ///    var publicKey = crypto.ImportPublicKey(exportedPublicKey);
        ///    using (var inputStream = new FileStream("[YOUR_FILE_PATH_HERE]", FileMode.Open, FileAccess.Read))
        ///    {
        ///       crypto.Verify(inputStream, signature, publicKey);
        ///    }
        /// </code>
        /// </example>
        /// How to get exportedPublicKey <see cref="ExportPublicKey(IPublicKey)"/>     
        public bool VerifyVirgilSignature(byte[] signature, Stream inputStream, IPublicKey publicKey)
        {
            if (signature == null)
                throw new ArgumentNullException("signature");

            try
            {
                using (VirgilStreamSigner streamSigner = new VirgilStreamSigner())
                {
                    VirgilStreamDataSource source = new VirgilStreamDataSource(inputStream);
                    bool isValid = streamSigner.Verify(source, signature, VirgilCryptoExtentions.Get(publicKey).Value);
                    return isValid;
                }
            }
            catch (Exception ex)
            {
                throw new VirgilCryptoException(ex.Message);
            }
        }

        private byte[] ComputePublicKeyHash(byte[] publicKey)
        {
            byte[] publicKeyDER = VirgilKeyPair.PublicKeyToDER(publicKey);
            return this.ComputeHash(publicKeyDER, HashAlgorithm.SHA256);
        }

        private IPublicKey FindPublicKeyBySignerId(IPublicKey[] publicKeys, byte[] signerId)
        {
            foreach (IPublicKey publicKey in publicKeys)
            {
                if (ByteSequencesEqual(VirgilCryptoExtentions.Get(publicKey).ReceiverId, signerId))
                {
                    return publicKey;
                }
            }
            return null;
        }

        private bool ByteSequencesEqual(byte[] sequence1, byte[] sequence2)
        {
            if (sequence1.Length != sequence2.Length)
            {
                return false;
            }
            for (int i = 0; i < sequence1.Length; i++)
            {
                if (sequence1[i] != sequence2[i])
                {
                    return false;
                }
            }
            return true;
        }
    }
}
