/**
 * Copyright (C) 2015-2016 Virgil Security Inc.
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

/**
 * @file rsa_keys.h
 * @brief Hardcoded constants of deterministic keys.
 *
 * Deterministic keys can be generated via 'VirgilAsymmentricCipher::genKeyPairFromKeyMaterial()' method and
 * 'VirgilKeyPair::genKeyPairFromKeyMaterial()' method.
 *
 * @note Key Material that was used to generated this keys is 512 byte array of 0xAB.
 */

#ifndef VIRGIL_CRYPTO_TEST_DETERMINISTIC_KEYS_H
#define VIRGIL_CRYPTO_TEST_DETERMINISTIC_KEYS_H


constexpr char kDeterministic_KeyMaterial[] =
        "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"
        "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"
        "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"
        "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"
        "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"
        "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"
        "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"
        "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"
        "ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"
        "ABABABABABABABABABABABABABABABABAB";

constexpr char kDeterministic_RSA_256_Public[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MDwwDQYJKoZIhvcNAQEBBQADKwAwKAIhAPLAt35Fu5IUBPwiWpg+Tm/dvEeCmC+E\n"
        "O6tYbFB5L/eFAgMBAAE=\n"
        "-----END PUBLIC KEY-----\n";

constexpr char kDeterministic_RSA_256_Private[] =
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIGqAgEAAiEA8sC3fkW7khQE/CJamD5Ob928R4KYL4Q7q1hsUHkv94UCAwEAAQIg\n"
        "JDBKqo5mug41+Ah/DPcs5gIKh11bkbxbfWQBRkObvHkCEQD5+UWLcmapCpsVWxN2\n"
        "NVoPAhEA+JrheiLtEfm66C3YNou5KwIRAPmxA8WZ3W/m9ygq1FLUUgMCEEppEVQd\n"
        "YBghR3B3SGALMkECEB3Y4ry/oh3PUw+3u/7f7Qs=\n"
        "-----END RSA PRIVATE KEY-----\n";


constexpr char kDeterministic_RSA_8192_Public[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MIIEIjANBgkqhkiG9w0BAQEFAAOCBA8AMIIECgKCBAEA58IFLmkTgewY9qQM/+4g\n"
        "MNAg+hchp5DtifltVXImahSr3H3god7mMO9BENV+eoGdgGqPcMf7OwFGJHtBuy5M\n"
        "rEQ4dLO7o+HTFD9XuTltD0tPQghsH2ruRB6Nq20Gg8LSAPkq1imS/2qCXBs/8JYt\n"
        "gQazh+KJzdZgMhKReM2V6QRCsMlU8geFgWk+igafCu+aufKuc9zFpzYJgeZr+vpu\n"
        "TJIR6EkjBbOOwwpg76Gsk1j0BB2uN/z9e/mNcdZszQKf0PRj2AHT+zH+k7igaVCc\n"
        "UwHHxmYSdtaUD2ZfpouczDsNvrlTX5zhWYrQ7gwuKYvBvOlit9L5e9iLElq5S63L\n"
        "fYmySm+cDOnZvckD7+nKARZ+aiCO6MPGrGE6M9m0FZXentaAd2RblpYr69C0jfi1\n"
        "O9V0uHYJ6Fn0ME/cOdOiHq+7KgkxZZ9EpUgV4LlBmgQ4mwXAbcGfrChudH3bLo8j\n"
        "aOm3xRbBQBKBsJ3p0k2VQdhxN7vavtT71oLr/7SRFfAN+2P3/qHbwRHcixUcPYNZ\n"
        "64ZaTJiC4eqiFhUtGUPeoXmQ/YaTQxB7IE8RF9E+FrAsJIB5CCui3ASMDhSwwdeC\n"
        "4zoYTpLlJaq81AXDbuyFqeGqEwe1yxLDMsLp6vflJcBHcCgcJm2SJlW87QT8EviC\n"
        "CiBh1oXaZSDR1MAlvhkA5f0ni8D5X2CmalbY9Rr4Ixuw4GoNTegB9OH0L5q1arme\n"
        "o6yUfgm63SxTnh5EED3m8bPFjfewKBut9NnE0ZEB3FYpOW/LIdoKKQS2oC5O0kEJ\n"
        "f7jOKK6jGuqxNqyI3JuNskYpotnqPBkBcG6ZiuZkjOJ94XAFM9thW3iCIMaWO18g\n"
        "GOIuqaP9vpkiA9fsVSOK47Pf2sOxmQo5LCm/6cjKQWun0gHPJTcXoGrfCfkLfDZH\n"
        "EigtNK0mZ2N1C75vBzIqnDZPguTIbuxBYzLpi/qXWjjkNfAvDWRnsahp0RQw7Dhi\n"
        "f16rwh5/zKFhW3ZKqTB4YraGUiVVIgVYLIn4ZwLiv4Js/FaCmG+2brgqdvxfB5zN\n"
        "XfdpBhWTb8S06QBoOhJ2Saw9CvyiT31c34n2vfkrpKlshOvZJQcOVmZX0Fxey2Y3\n"
        "VQvIanh/DpA2dAllWpA4jAMW3wIDTVv16+PzzrgC1nprbSDah5jSD5aReInORy4q\n"
        "L3VBVae3KiYy6AR93nqsAVN6mu0Zs6pDdIbh554hT1yxxtSsn4pKbWIk6UggTICy\n"
        "Z4YZ+w5ZfAtKurLyBC6SjL0wyChSsx/q+BeDFVHOL15jI1/kqB+CrJJTLDJmhshX\n"
        "7b9f1uBWBRBq4hPJuyHlX1voIrdplbn7zfttzb8SgOFUAFKJFPUKPSa9zFjKwxuE\n"
        "3wIDAQAB\n"
        "-----END PUBLIC KEY-----\n";

constexpr char kDeterministic_RSA_8192_Private[] =
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "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\n"
        "-----END RSA PRIVATE KEY-----\n";


constexpr char kDeterministic_EC_SECP192R1_Public[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MEkwEwYHKoZIzj0CAQYIKoZIzj0DAQEDMgAEKJVTlIvk+QQNlr/Af9uCQG3/VJdF\n"
        "io8yY5+jyOqtQY9ND1kc5rw7uXWfVXX9A/85\n"
        "-----END PUBLIC KEY-----\n";

constexpr char kDeterministic_EC_SECP192R1_Private[] =
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MF8CAQEEGHn5RYtyZqkKmxVbE3Y1WftrdI0w44w9gKAKBggqhkjOPQMBAaE0AzIA\n"
        "BCiVU5SL5PkEDZa/wH/bgkBt/1SXRYqPMmOfo8jqrUGPTQ9ZHOa8O7l1n1V1/QP/\n"
        "OQ==\n"
        "-----END EC PRIVATE KEY-----\n";


constexpr char kDeterministic_EC_SECP521R1_Public[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQA83FedxqHmVpjcsTm63/Lyb/tOU35\n"
        "GTDJxFYrz9Gy5xQtoHH815VHLBPb/d+NXNOlhxHOLcldLA/Dq1rI7+jeYzcAb0yu\n"
        "yL39PAmjAPVLdr8R2VVsPxd+agQW0SJDzygWyEWxHK2rZPoOUamYTEVH2kVfBcdK\n"
        "p7lK0IuGLnjxyF8gCp8=\n"
        "-----END PUBLIC KEY-----\n";

constexpr char kDeterministic_EC_SECP521R1_Private[] =
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MIHcAgEBBEIA8/KLFuTNUhU2KrYm7Gqz9tbpGmHHGHsAXtSVAlCk6hcHygyoUvjO\n"
        "yPl2e+r5foYvCUI/SZkhl6nwV0tXyIasIY+gBwYFK4EEACOhgYkDgYYABADzcV53\n"
        "GoeZWmNyxObrf8vJv+05TfkZMMnEVivP0bLnFC2gcfzXlUcsE9v9341c06WHEc4t\n"
        "yV0sD8OrWsjv6N5jNwBvTK7Ivf08CaMA9Ut2vxHZVWw/F35qBBbRIkPPKBbIRbEc\n"
        "ratk+g5RqZhMRUfaRV8Fx0qnuUrQi4YuePHIXyAKnw==\n"
        "-----END EC PRIVATE KEY-----\n";


constexpr char kDeterministic_EC_BP512R1_Public[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGbMBQGByqGSM49AgEGCSskAwMCCAEBDQOBggAEYcWHH2onaD/P8wdWagF9C8tc\n"
        "RgqGPGWb4mjK6vRh98ImV+mRAoO0Lfs23hF36xgJhyg01jf1fNVpjVIITsLjhEtH\n"
        "ucgPQm3I/SKNb0qrRL6zSGcctH028EsNgZyYmm8T+7JCK3zS21POvmmwVBvMxkYD\n"
        "jrtpeVmtvnpZZ4oMwK0=\n"
        "-----END PUBLIC KEY-----\n";

constexpr char kDeterministic_EC_BP512R1_Private[] =
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MIHaAgEBBEB5+UWLcmapCpsVWxN2NVn7a3SNMOOMPYAvakqBKFJ1C4PlBlQpfGdk\n"
        "fLs99Xy/QxeEoR+kzJDL1PgrpavkQ1YQoAsGCSskAwMCCAEBDaGBhQOBggAEYcWH\n"
        "H2onaD/P8wdWagF9C8tcRgqGPGWb4mjK6vRh98ImV+mRAoO0Lfs23hF36xgJhyg0\n"
        "1jf1fNVpjVIITsLjhEtHucgPQm3I/SKNb0qrRL6zSGcctH028EsNgZyYmm8T+7JC\n"
        "K3zS21POvmmwVBvMxkYDjrtpeVmtvnpZZ4oMwK0=\n"
        "-----END EC PRIVATE KEY-----\n";


constexpr char kDeterministic_EC_SECP256K1_Public[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE+9D+eNiEeNEr54F8w4pDadPviB9g6XQ1\n"
        "tfUFsfGTjzEBMVvQdY9iiG3hFkvHW5b5AqWKC4O1C8c0C5G7mXrSEA==\n"
        "-----END PUBLIC KEY-----\n";

constexpr char kDeterministic_EC_SECP256K1_Private[] =
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHQCAQEEIHn5RYtyZqkKmxVbE3Y1WftrdI0w44w9gC9qSoEoUnULoAcGBSuBBAAK\n"
        "oUQDQgAE+9D+eNiEeNEr54F8w4pDadPviB9g6XQ1tfUFsfGTjzEBMVvQdY9iiG3h\n"
        "FkvHW5b5AqWKC4O1C8c0C5G7mXrSEA==\n"
        "-----END EC PRIVATE KEY-----\n";


constexpr char kDeterministic_FAST_EC_X25519_Public[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MCowBQYDK2VuAyEA1l8vn0g1OjUbDfqnon6PxMiRVtX+/95JmyxEzJnO4Vw=\n"
        "-----END PUBLIC KEY-----\n";

constexpr char kDeterministic_FAST_EC_X25519_Private[] =
        "-----BEGIN PRIVATE KEY-----\n"
        "MC4CAQAwBQYDK2VuBCIEIHn5RYtyZqkKmxVbE3Y1WftrdI0w44w9gC9qSoEoUnUL\n"
        "-----END PRIVATE KEY-----\n";


constexpr char kDeterministic_FAST_EC_ED25519_Public[] =
        "-----BEGIN PUBLIC KEY-----\n"
        "MCowBQYDK2VwAyEA1eQkkQRZQagM4xOddC68mndhtJu4+IunGaYXc+C+gjg=\n"
        "-----END PUBLIC KEY-----\n";

constexpr char kDeterministic_FAST_EC_ED25519_Private[] =
        "-----BEGIN PRIVATE KEY-----\n"
        "MC4CAQAwBQYDK2VwBCIEIHn5RYtyZqkKmxVbE3Y1WftrdI0w44w9gC9qSoEoUnUL\n"
        "-----END PRIVATE KEY-----\n";


#endif /* VIRGIL_CRYPTO_TEST_DETERMINISTIC_KEYS_H */
