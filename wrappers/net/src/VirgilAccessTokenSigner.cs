using System;
using System.Collections.Generic;
using System.Text;
using Virgil.Crypto;
using Virgil.CryptoAPI;

namespace Virgil.SDK.Crypto
{
    class VirgilAccessTokenSigner : IAccessTokenSigner
    {
        private readonly string algorithm = "VEDS512";
        private readonly VirgilCrypto virgilCrypto;

        public VirgilAccessTokenSigner()
        {
            virgilCrypto = new VirgilCrypto();
        }
        public byte[] GenerateTokenSignature(byte[] tokenBytes, IPrivateKey privateKey)
        {
            return virgilCrypto.GenerateVirgilSignature(tokenBytes, privateKey);
        }

        public string GetAlgorithm()
        {
            return algorithm;
        }

        public bool VerifyTokenSignature(byte[] signature, byte[] tokenBytes, IPublicKey publicKey)
        {
            return virgilCrypto.VerifyVirgilSignature(signature, tokenBytes, publicKey);
        }
    }
}
