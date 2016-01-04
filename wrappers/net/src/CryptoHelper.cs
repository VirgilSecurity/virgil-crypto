#region "Copyright (C) 2015 Virgil Security Inc."
/**
 * Copyright (C) 2015 Virgil Security Inc.
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
#endregion

namespace Virgil.Crypto
{
    /// <summary>
    /// Performs cryptographic operations like encryption and decryption using the Virgil Security Crypto Library.
    /// </summary>
    public class CryptoHelper
    {
        /// <summary>
        /// Encrypts text for the specified recipient's public key.
        /// </summary>
        /// <param name="text">The text to be encrypted.</param>
        /// <param name="recipientId">The unique recipient ID, that identifies a Public Key</param>
        /// <param name="recipientPublicKey">A byte array that represents a <c>Public Key</c></param>
        /// <remarks>This method encrypts a data that is decrypted using the <see cref="CryptoHelper.Decrypt(string, string, byte[], string)"/> method.</remarks>
        /// <returns>The encrypted text in Base64 format.</returns>
        public static string Encrypt(string text, string recipientId, byte[] recipientPublicKey)
        {
            var textData = System.Text.Encoding.UTF8.GetBytes(text);

            var recipients = new System.Collections.Generic.Dictionary<string, byte[]> { { recipientId, recipientPublicKey } };
            var cipherDataBase64 = System.Convert.ToBase64String(Encrypt(textData, recipients));
            return cipherDataBase64;
        }

        /// <summary>
        /// Encrypts text for the specified dictionary of recipients.
        /// </summary>
        /// <param name="text">The text to be encrypted.</param>
        /// <param name="recipients">The dictionary of recipients Public Keys</param>
        /// <remarks>This method encrypts a data that is decrypted using the <see cref="CryptoHelper.Decrypt(string, string, byte[], string)"/> method.</remarks>
        /// <returns>The encrypted text in Base64 format.</returns>
        public static string Encrypt(string text, System.Collections.Generic.IDictionary<string, byte[]> recipients)
        {
            var textData = System.Text.Encoding.UTF8.GetBytes(text);
            var cipherDataBase64 = System.Convert.ToBase64String(Encrypt(textData, recipients));
            return cipherDataBase64;
        }

        /// <summary>
        /// Encrypts data for the specified dictionary of recipients.
        /// </summary>
        /// <param name="data">The data to be encrypted.</param>
        /// <param name="recipients">The dictionary of recipients Public Keys</param>
        /// <remarks>This method encrypts a data that is decrypted using the <see cref="CryptoHelper.Decrypt(byte[], string, byte[], string)"/> method.</remarks>
        /// <returns>The encrypted data.</returns>
        public static byte[] Encrypt(byte[] data, System.Collections.Generic.IDictionary<string, byte[]> recipients)
        {
            using (var cipher = new VirgilCipher())
            {
                foreach (var recipient in recipients)
                {
                    var recipientIdData = System.Text.Encoding.UTF8.GetBytes(recipient.Key);
                    cipher.AddKeyRecipient(recipientIdData, recipient.Value);
                }

                var cipherData = cipher.Encrypt(data, true);
                return cipherData;
            }
        }

        /// <summary>
        /// Encrypts text with the specified password.
        /// </summary>
        /// <param name="text">The text to be encrypted.</param>
        /// <param name="password">The password that uses to encrypt specified data.</param>
        /// <remarks>This method encrypts a text that is decrypted using the <see cref="CryptoHelper.Decrypt(string, string)"/> method.</remarks>
        /// <returns>The encrypted text in Base64 format.</returns>
        public static string Encrypt(string text, string password)
        {
            var textData = System.Text.Encoding.UTF8.GetBytes(text);
            var cipherDataBase64 = System.Convert.ToBase64String(Encrypt(textData, password));
            return cipherDataBase64;
        }

        /// <summary>
        /// Encrypts data with the specified password.
        /// </summary>
        /// <param name="data">The data to be encrypted.</param>
        /// <param name="password">The password that uses to encrypt specified data.</param>
        /// <remarks>This method encrypts a data that is decrypted using the <see cref="CryptoHelper.Decrypt(byte[], string)"/> method.</remarks>
        /// <returns>The encrypted data.</returns>
        public static byte[] Encrypt(byte[] data, string password)
        {
            using (var cipher = new VirgilCipher())
            {
                var passwordData = System.Text.Encoding.UTF8.GetBytes(password);
                cipher.AddPasswordRecipient(passwordData);

                var cipherData = cipher.Encrypt(data, true);

                return cipherData;
            }
        }


        /// <summary>
        /// Decrypts data that was previously encrypted with <c>Public Key</c>.
        /// </summary>
        /// <param name="cipherTextBase64">The text to decrypt in Base64 format.</param>
        /// <param name="recipientId">The unique recipient ID, that identifies a Public Key.</param>
        /// <param name="privateKey">A byte array that represents a <c>Private Key</c></param>
        /// <remarks>This method decrypts a data that is ecrypted using the <see cref="CryptoHelper.Encrypt(string, string, byte[])"/> method.</remarks>
        /// <returns>The decrypted data.</returns>
        public static string Decrypt(string cipherTextBase64, string recipientId, byte[] privateKey)
        {
            return Decrypt(cipherTextBase64, recipientId, privateKey, null);
        }

        /// <summary>
        /// Decrypts data that was previously encrypted with <c>Public Key</c>.
        /// </summary>
        /// <param name="cipherTextBase64">The text to decrypt in Base64 format.</param>
        /// <param name="recipientId">The unique recipient ID, that identifies a Public Key.</param>
        /// <param name="privateKey">A byte array that represents a <c>Private Key</c></param>
        /// <param name="privateKeyPassword">The <c>Private Key</c>'s password.</param>
        /// <remarks>This method decrypts a data that is ecrypted using the <see cref="CryptoHelper.Encrypt(string, string, byte[])"/> method.</remarks>
        /// <returns>The decrypted data.</returns>
        public static string Decrypt(string cipherTextBase64, string recipientId, byte[] privateKey, string privateKeyPassword)
        {
            var cipherData = System.Convert.FromBase64String(cipherTextBase64);
            var textData = Decrypt(cipherData, recipientId, privateKey);
            var text = System.Text.Encoding.UTF8.GetString(textData, 0, textData.Length);
            return text;
        }


        /// <summary>
        /// Decrypts data that was previously encrypted with <c>Public Key</c>.
        /// </summary>
        /// <param name="cipherData">The data to decrypt.</param>
        /// <param name="recipientId">The unique recipient ID, that identifies a Public Key.</param>
        /// <param name="privateKey">A byte array that represents a <c>Private Key</c></param>
        /// <remarks>This method decrypts a data that is ecrypted using the <see cref="CryptoHelper.Encrypt"/> method.</remarks>
        /// <returns>The decrypted data.</returns>
        public static byte[] Decrypt(byte[] cipherData, string recipientId, byte[] privateKey)
        {
            return Decrypt(cipherData, recipientId, privateKey, null);
        }

        /// <summary>
        /// Decrypts data that was previously encrypted with <c>Public Key</c>.
        /// </summary>
        /// <param name="cipherData">The data to decrypt.</param>
        /// <param name="recipientId">The unique recipient ID, that identifies a Public Key.</param>
        /// <param name="privateKey">A byte array that represents a <c>Private Key</c></param>
        /// <param name="privateKeyPassword">The <c>Private Key</c>'s password</param>
        /// <remarks>This method decrypts a data that is ecrypted using the <see cref="CryptoHelper.Encrypt"/> method.</remarks>
        /// <returns>The decrypted data.</returns>
        public static byte[] Decrypt(byte[] cipherData, string recipientId, byte[] privateKey, string privateKeyPassword)
        {
            using (var cipher = new VirgilCipher())
            {
                var recipientIdData = System.Text.Encoding.UTF8.GetBytes(recipientId);

                byte[] textData;

                if (privateKeyPassword == null)
                {
                    textData = cipher.DecryptWithKey(cipherData, recipientIdData, privateKey);
                }
                else
                {
                    var privateKeyPasswordData = System.Text.Encoding.UTF8.GetBytes(privateKeyPassword);
                    textData = cipher.DecryptWithKey(cipherData, recipientIdData, privateKey, privateKeyPasswordData);
                }

                return textData;
            }
        }

        /// <summary>
        /// Decrypts data that was previously encrypted with specified password.
        /// </summary>
        /// <param name="cipherTextBase64">The text to decrypt in Base64 format.</param>
        /// <param name="password">The password that was used to encrypt specified data.</param>
        /// <remarks>This method decrypts a data that is ecrypted using the <see cref="CryptoHelper.Encrypt(string, string)"/> method.</remarks>
        /// <returns>The decrypted text.</returns>
        public static string Decrypt(string cipherTextBase64, string password)
        {
            var cipherData = System.Convert.FromBase64String(cipherTextBase64);

            var textData = Decrypt(cipherData, password);
            var text = System.Text.Encoding.UTF8.GetString(textData, 0, textData.Length);

            return text;
        }

        /// <summary>
        /// Decrypts data that was previously encrypted with specified password.
        /// </summary>
        /// <param name="cipherData">The data to decrypt.</param>
        /// <param name="password">The password that was used to encrypt specified data.</param>
        /// <remarks>This method decrypts a data that is ecrypted using the <see cref="CryptoHelper.Encrypt(byte[], string)"/> method.</remarks>
        /// <returns>The decrypted data.</returns>
        public static byte[] Decrypt(byte[] cipherData, string password)
        {
            using (var cipher = new VirgilCipher())
            {
                var passwordData = System.Text.Encoding.UTF8.GetBytes(password);
                var textData = cipher.DecryptWithPassword(cipherData, passwordData);
                return textData;
            }
        }

        /// <summary>
        /// Computes the hash value of the specified string and signs the resulting hash value.
        /// </summary>
        /// <param name="text">The input text for which to compute the hash.</param>
        /// <param name="privateKey">A byte array that represents a <c>Private Key</c></param>
        /// <remarks>This method creates a digital signature that is verified using the <see cref="CryptoHelper.Verify(string, string, byte[])"/> method.</remarks>
        /// <returns>The digital signature in Base64 format for the specified data.</returns>
        public static string Sign(string text, byte[] privateKey)
        {
            return Sign(text, privateKey, null);
        }

        /// <summary>
        /// Computes the hash value of the specified string and signs the resulting hash value.
        /// </summary>
        /// <param name="text">The input text for which to compute the hash.</param>
        /// <param name="privateKey">A byte array that represents a <c>Private Key</c></param>
        /// <param name="privateKeyPassword">The <c>Private Key</c> password</param>
        /// <remarks>This method creates a digital signature that is verified using the <see cref="CryptoHelper.Verify(string, string, byte[])"/> method.</remarks>
        /// <returns>The digital signature in Base64 format for the specified data.</returns>
        public static string Sign(string text, byte[] privateKey, string privateKeyPassword)
        {
            var textData = System.Text.Encoding.UTF8.GetBytes(text);

            var signData = Sign(textData, privateKey, privateKeyPassword);
            var signBase64 = System.Convert.ToBase64String(signData);
            return signBase64;
        }

        /// <summary>
        /// Computes the hash value of the specified byte array and signs the resulting hash value.
        /// </summary>
        /// <param name="data">The input data for which to compute the hash.</param>
        /// <param name="privateKey">A byte array that represents a <c>Private Key</c></param>
        /// <remarks>This method creates a digital signature that is verified using the <see cref="CryptoHelper.Verify(byte[], byte[], byte[])"/> method.</remarks>
        /// <returns>The digital signature for the specified data.</returns>
        public static byte[] Sign(byte[] data, byte[] privateKey)
        {
            using (var signer = new VirgilSigner())
            {
                return signer.Sign(data, privateKey);
            }
        }

        /// <summary>
        /// Computes the hash value of the specified byte array and signs the resulting hash value.
        /// </summary>
        /// <param name="data">The input data for which to compute the hash.</param>
        /// <param name="privateKey">A byte array that represents a <c>Private Key</c></param>
        /// <param name="privateKeyPassword">The <c>Private Key</c> password</param>
        /// <remarks>This method creates a digital signature that is verified using the <see cref="CryptoHelper.Verify(byte[], byte[], byte[])"/> method.</remarks>
        /// <returns>The digital signature for the specified data.</returns>
        public static byte[] Sign(byte[] data, byte[] privateKey, string privateKeyPassword)
        {
            using (var signer = new VirgilSigner())
            {
                return signer.Sign(data, privateKey, System.Text.Encoding.UTF8.GetBytes(privateKeyPassword));
            }
        }

        /// <summary>
        /// Verifies the specified signature by comparing it to the signature computed for the specified text.
        /// </summary>
        /// <param name="text">The text that was signed.</param>
        /// <param name="signBase64">The signature text in Base64 format to be verified.</param>
        /// <param name="publicKey">A byte array that represents a <c>Public Key</c></param>
        /// <remarks>This method verifies the digital signature produced by <see cref="CryptoHelper.Sign(string, byte[], string)"/>.</remarks>
        /// <returns><c>true</c> if the signature verifies as valid; otherwise, <c>false</c>.</returns>
        public static bool Verify(string text, string signBase64, byte[] publicKey)
        {
            var textData = System.Text.Encoding.UTF8.GetBytes(text);
            var signData = System.Convert.FromBase64String(signBase64);

            var isValid = Verify(textData, signData, publicKey);
            return isValid;
        }

        /// <summary>
        /// Verifies the specified signature by comparing it to the signature computed for the specified data.
        /// </summary>
        /// <param name="data">The data that was signed.</param>
        /// <param name="signData">The signature data to be verified.</param>
        /// <param name="publicKey">A byte array that represents a <c>Public Key</c></param>
        /// <remarks>This method verifies the digital signature produced by <see cref="CryptoHelper.Sign(byte[], byte[], string)"/>.</remarks>
        /// <returns><c>true</c> if the signature verifies as valid; otherwise, <c>false</c>.</returns>
        public static bool Verify(byte[] data, byte[] signData, byte[] publicKey)
        {
            using (var signer = new VirgilSigner())
            {
                var isValid = signer.Verify(data, signData, publicKey);
                return isValid;
            }
        }


        /// <summary>
        /// Generates a random Public/Private key pair to be used for encryption and decryption.
        /// </summary>
        /// <returns>The generated instance of <see cref="VirgilKeyPair"/> key pair.</returns>
        public static VirgilKeyPair GenerateKeyPair()
        {
            return GenerateKeyPair(null);
        }

        /// <summary>
        /// Generates a random Public/Private key pair to be used for encryption and decryption.
        /// </summary>
        /// <param name="password">The <c>Private Key</c> password</param>
        /// <returns>The generated instance of <see cref="VirgilKeyPair"/> key pair.</returns>
        public static VirgilKeyPair GenerateKeyPair(string password)
        {
            if (password == null)
            {
                return new VirgilKeyPair();
            }

            var passwordData = System.Text.Encoding.UTF8.GetBytes(password);
            return new VirgilKeyPair(passwordData);
        }
    }
}
