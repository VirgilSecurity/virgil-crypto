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

/**
 * @file test_cipher.cxx
 * @brief Covers class VirgilCipher
 */

#include "catch.hpp"

#include <virgil/crypto/VirgilByteArray.h>
#include <virgil/crypto/VirgilByteArrayUtils.h>
#include <virgil/crypto/VirgilCipher.h>
#include <virgil/crypto/VirgilKeyPair.h>

using virgil::crypto::str2bytes;
using virgil::crypto::bytes2hex;
using virgil::crypto::bytes2str;
using virgil::crypto::VirgilByteArray;
using virgil::crypto::VirgilCipher;
using virgil::crypto::VirgilKeyPair;
using virgil::crypto::VirgilByteArrayUtils;

constexpr char kRSA_8192_Public[] = "-----BEGIN PUBLIC KEY-----\n"
        "MIIEIjANBgkqhkiG9w0BAQEFAAOCBA8AMIIECgKCBAEAtWIfF94niOYRV8JKvX9C\n"
        "RzlxWCeGyv6RNTma1zRZq2lKHBFc+5j5I4eqPPVQ4Xfb4fVkB/Vua1zLSRT49G8X\n"
        "f/9KvfavHUZG/8ft2VzyAIuxmVbSt1UToOGut/kCsstFQkC0X7Jny66ETh6inV4k\n"
        "/BiVYm1hJCap/k6o7briD8vayKrzPpzK2LRVnFDiVjreFNI2aoUDQhWbdSSOQdI4\n"
        "FJWuYypgOWnZWcCIOtCG7s5D9HONlFR/C011AQekrB3e0rxMMlp6s2IH+9PSmHml\n"
        "FkgDX8Jn5CfkpQbT0CTEvVnfcb7/RbX+gxsvDO3HRL6Fzhzo/uliwNa0rbAzWYid\n"
        "BamWCXsox8z1Cfd4VMf70FnRPgLLoeQk0LulFwbzZZSfi16lMaAtTcnj9GI0dlZY\n"
        "0e83kZDHP/Udrq/FqCvOeIYeRZAvq5mRtPuGvqr0wR0owgZaPg4lf+IoBlj/JAJR\n"
        "UjUSty1LLfR/1p0I0rntzzHyQfWJa6MQi9e4n1zvK5TITnK7iRm5zAOm7SYWNs8H\n"
        "PMuCNtTOidt1pyaU9wpZZ+3BPM8CYTy89QNi9tUfv2+QqaA1OHjf519Tb4zgJZTl\n"
        "1SnDYzG8HNyVu+R083NnpPMedmGsLI09GvjWtkW3imrGk//Ll9e92Wxb2/8qB8Db\n"
        "PnPh5JI5SWrvY5fcEVsv7jTEsM2FlCg/hFXkIwMmwt9PLKMESpCxP39ldX7lCayo\n"
        "vNlpJzK82alLPttgarP0YX3rwEUVEURUPhwYF7j5IiVxRl5HumuRXP0bHexn1aJ0\n"
        "obuAM1mhC/9v6w0dFJiptbIp2DrdKC80BnWQZpXzxfxcCMvOlP1SuSZCQ7e2c82X\n"
        "34UWUXIiGRszdFCL/Y6Zvaz5OF425Tuh86+mK3zZ8hX1+1UYFmhRsCRkEwYOAs4W\n"
        "3tn+rSU01XNByWxWb1pxCSjntVNZQgeqOgDVMXihzwxMtBa/C9LiPNKzSlmQIOg2\n"
        "g599d4LyAAPExevRVDb7eRmZEGZzQl/ve4VjzjpqynDUfvQG6ABXy4OMcWEo5byG\n"
        "AsRByR288yQzEPxW6+GtwVubAy/0EP6PqM3Vu4BiKZcHJkcFYyRvNY2i0MI5Nibx\n"
        "rm94mgmJYw9kPU/RvOSRYGmdhhZaY3hQJPf0wTUphKLPJ3BxxzT8dIsRLeL+xPVD\n"
        "+9okwQ5OiuPG6iCT758fc5DVQYmyvwZMwmPzqp7RlaoFT0VYcv+0WDBUnC+6R+SU\n"
        "RQ9b0oS/9eRLq4uhJgkYFmyU5FhFAwXoQjtm5b2i+xJ1ctVmNUwh5f6hoJcmx/KP\n"
        "SOLk5teZy4WK9p5APVI8ApwwvJH2gs0qohIjFT4H6vppaK/K5XVMvZYech/237gz\n"
        "8wIDAQAB\n"
        "-----END PUBLIC KEY-----\n";

constexpr char kRSA_8192_Private[] = "-----BEGIN ENCRYPTED PRIVATE KEY-----\n"
        "MIISjjBABgkqhkiG9w0BBQ0wMzAbBgkqhkiG9w0BBQwwDgQIDNwUCARlFIkCAggA\n"
        "MBQGCCqGSIb3DQMHBAi3GE+zlnV+AwSCEkjSVqiCjDCUgWAu1bJYF0VYUALD5Y7x\n"
        "H8eMNUAzVjZvVP6L+83Sn69mmfNHCFpDz/ig7M+6tLeN982/YVomfOnany0wg3/1\n"
        "yfLQr87FtTeHyKY18rcqfjD72YrxKCYq9sPnueLYP+hGPBXIakpm1HrquMn9IoJi\n"
        "ibQwBM9w7JO9f5HRnfaKdWb5fdelv+Zt4kPyVNLE9Anp5PwL6TGTwN9EPK4unXt6\n"
        "xt64taT3vNwUCcGl0Ru1EpftRCNPUa5a2bDmLeTG4J5qwHEsEIVrXj83BAoqHxg/\n"
        "6SRe/wHL7w7e0lcIoI7gWKojg47s1yIz3Sz6WRQ+jeAge2MAchVMakDA8Oevrwx+\n"
        "HH/9KS8+wc1CdV8OOzRt/TlhGpgiltQCzYFbn3W+w7sixjDcQpJpsQi3ZCsIYhfz\n"
        "UisIrB/S8T/ue18tQWwfeY/xkrl2uz8I+zlWajRvKE+jiGFZ8JzLVQlfAUNlUXnI\n"
        "r3KOY24sxHk2J8+CfWqJCcxI7cGX0o6Y70Xcww8ZTMVft/SIbJxWyq49TxrDzg8z\n"
        "Qqp36/1givqDIk9e9QhHYnDUQ5OYyk55zn5KZw3ldKO7iZkHt9XFrk/4JIuSrIws\n"
        "h//CMKCmo4Nk3/qsY0PZiEYiyueTOClgYWUwPhjCsPmeicYfXShWBoyUZY4l593S\n"
        "W5y10Re47E8FmThUhOVuFAa210o0LKENd009hTJRc6cB3FM0ITur2EybXLS18pTf\n"
        "lVI4SywfxhxhToEBD9ICVIuoKJ2gZFiPJSEeb5tJhtuC2hf/bJqn+d97d4nkfHmI\n"
        "E/ANaVWEIvcvYGp2aFQjMNXGZKEoTcoDxth822PKVGVEU2OryAqwNNVJoDucfhfw\n"
        "bsLVJpjdCWFl0QI7h3a7A6t/YxBjCR91GACQJ8ifB3ZmKDjoMrPV0i7xFT+E6o7J\n"
        "rCdhFhudicdZGXScT7mM+VxNyRs6i59QfGLqy1H+n8BQwbY7fyTLFPS7wYKFT1jl\n"
        "3f4p0c8cfMARNU81JQOm9ccMWYVZkaANu/KbkTxL5qfmdeBNdOQwi9V7JBfqt1qU\n"
        "4xooTEiP/5lQ8myWNKkRoBTH4o2mn3pFaMzJb/JE4zNDuitWiXiBBcFFJkKyauVx\n"
        "Vwl8qXQmICMuw4DsAnfZfdbDuI+cqyETFLLwEMPJhM8iwERQLf259wzV6rVKNquY\n"
        "7YrpwInUm9lLyY7A9dlIoLgtasdftKTP3ptXig886PK/+Z+PH+3l90ijDOEVQN03\n"
        "3KJd531V1+tyG+fyQ7sJKlApfDPyKVjbj8lh2V/kU7MF1RYhKFyzlADXL+rLrPy+\n"
        "lnBoZ0McFdp39e+iqd+/5areieNqHE15U5c3f91OWpfYAicAdeiEnlD9xxVBdtPe\n"
        "9xYB24HInt8P4YZhxw2fvIa0M0zxfxamCGEBCdcblP4FpYPo9KK49N44IX/sQlL6\n"
        "OAXVuD4VoBAqJjs7VCu9to3AL3j9POh7kmwh0ZrNPp5wsm/rTs/U+ZpBhj49A3Lw\n"
        "zXjdE50ZMse5jvhryprUUThks9ZZIHC629aQIEAhTQVE5Io0R/IqOa8e6XHDvH8i\n"
        "fRHLNFjy4y+o8X2VljZVzFqfglb6CY00SUMo2Cphs3f11dLi0dPrDa0Y8vdpepVg\n"
        "wIs4oMJwn9sryFAgXB3hWw/SPydTw4h3J/+p6RxSmdcvkSaSXUS4L2qHpVmY1lcr\n"
        "bdATFrzzuAn2TmYkpAAlCzK2aLeqgOy3KNnuML8v0RRcnz9pCz7YBEKfwEw1/wXd\n"
        "FF1A/pfbZ8p/f8ou10ydN2gyt8enXZeT5ZijZNW2Wyqt4whqxYP/j9Is5m7ijn9s\n"
        "9vmw89HG+X2NDcvtPlfY4hRQE4Amhhop0bsRPFJLgeVUFIbOzTYnnSxJ6mQQ2a+K\n"
        "4PJxtxQPFwtevzb5rajkDlKShzNu/Bpn1FIrURGb4HpZxOY9ceDXSc13lh1vizyt\n"
        "zG9eJKG8jhfIUxl6eA64c+RzbDS9vUewISBhCbsc1+Wc4yAClp773Rst75aa7yre\n"
        "OzNBgK8NlfvYgffpFC9hn0/EjtJ4SiM7CVg+qOtRx9EOGPkfzEYl2DoJspJCylh8\n"
        "2fPQVbaUSpQQzUjNcem8ZRXcWvgBjn4MAiAHvBZUsiCaDOA95Hvda2aB0ZwWtQDZ\n"
        "Y63jGW+PEp9edDiceeAv6EnDMyV12lc0cWjKqqXzop5a757vRoVT/XxNLfiB8jw5\n"
        "38HL62XU6DUjEmx5dxloyt7hsd3fr/h/fVy69spkv9CDpwyiucj0aSSjMvzDxptd\n"
        "DEtK3zPcG2K7msJchU+P7ZTKI+LRr00BSKRAug4JSfJYteh0fkI2y/nnNubbvlyt\n"
        "0o6HinX4Npgy9JG/gIS+nicTa4EFj2S9x53h7V1+2t8HlXaKuANSuCaRZKtHSorC\n"
        "Z85K24887RpbKAOiCjaLZJqqyFGWCMzlDyGdxk9xgO5z0Wh8jSZXGlHNmqXFIBpZ\n"
        "J8hGYTVenZ84jdRM5fbnOuT+Fh5eAIZOa9AuKF1mNSXDDHoBCIUUeecinO92SshD\n"
        "gzeruPPodF54X3DwHDJSvr9fgZtnmNZRw/tZDrEHGGDSDlyPrfCqqSLleIzumswR\n"
        "4wBQMULx6bAhyHCqAJjWZs4ouAJKWK00WbrI7Z7ZiVbXHzff/qpC46zc7J9KkbdC\n"
        "4l89tYv+pjka/VzSPWiAzJz4lxXBVLoQ6ChAQeFAYK3CnCwcPbgcTe9aAdeKwd02\n"
        "ENpRbRjCewD0TpRzIbHvMJZalqyHO29mt6rg5IKuywgl3OqCKbBPCTEVfm3LngzH\n"
        "lrwM3c3J9VsmS4s5gYfMcBdBmbaeXMoNPlp+wB6QNr28uqhUn62BAmeApXC5XJw7\n"
        "+lfRADrxNBDDR1zOAF58S3wodDho9DggPzApdAib2z/cxZa9Zli0O33Cmy3QhRIG\n"
        "Kb2CYqcCK+KboITBrSgUJwwCjhukv5TWO7r+Du7B11UpgShUwfCD3jfx61ULAWr6\n"
        "4TaQymEJ/s4+bE3UWOyLOtPfLougXtAg+1CxZ14r6SidoQ06BD0io0C7/IdNCfaG\n"
        "mghUmStMxgcqXhixzSxckBwE6tnm1FrzmAKP1m9NI77xpKdsSC+PSt7h9mstjnIs\n"
        "u69Jv5+aRMuosLhoU8OM0KfLFatGV0U5A4N85MvZk2N882NRAYvuZ7iRr8tOn2Qi\n"
        "IfP5wUtQuVcMoGTz5wUX3vKzrP6FigHfpFiF0JtD9us18rWGWWmzpDuq3ppmJDh/\n"
        "sP+8kplT1BX0SLSF1QKUd8Htc+1TR85Ad95UehlCkEZz9jM/bsl4OoeZDEEPzH32\n"
        "XXZRAQ+qpKTZoCZdW1dkDdunLWl5fMhgUTHrbdfw44kKA+KblnJPqzr012tenegH\n"
        "3Eo+Ldh9eLqUwRxbbPOljsWoCnbfWypwI30IVHxeLjB6DuxR1JcChUzhLBxa8gn4\n"
        "1/ktuGsE93Lyvk9lsZI4PAPtNuMuaa9KIsbgg8fyJCVPbHxvCLCxKCsu57ikziaq\n"
        "nCcCreZnbCKq1iiBYyNeUEp+aXrfTlr/F9y3zZBukvZtmjeKBbasebVhUU9MZ/ZS\n"
        "XCazPs1oMR7r+YWfmK78Yu+XvzsXFZp0ooYcabJNR13w3rkpoJNrNgtOO1pRVFBh\n"
        "ilbhyBMCtVNRUuXyVirusXyacs7dxPHcc2rbWTCD4EY9Mnp5FGDECtSumSsYUGF7\n"
        "RmL5VCnFtUjXBjH1mEr6PGF0M4rCn+hfj5ij/29/Yw7chF0vCY3WUPGfwyrSV+gA\n"
        "3CPduEVAHzUaiK/ze0vwqoAEcpwFYm4bm8tSW6B9G1hj3aa9bnnkAcb2FF6Drh40\n"
        "HMvvLB3kmnWA2AU19hwqfSTFzAmkemsw1iHa2cwRVehTYfI+p/GiQQRdBGZud0ad\n"
        "kY4hdqnSLooMUfOYzE8fHQsa5phkM/DfFIHottTd1zoOUvSW0APHjvbaduy29EBw\n"
        "5C8oUIdI0XcN61uQae+Yp0YwTOwc1yV7RKQEPrz+aKW7Y7/hgYNxmxRlV3Z1JevI\n"
        "/iYgyCygBGosJ8lC95kcctShg8QMsX9VvM7YBqNShzYuLH+0rWYL/9Itk45Ur37Z\n"
        "GDiaya3NoxTfd+ZQ9tw8v0POusgKnba3iTIAcFi5BixBcL1zkyh2xGURNp4eC4a+\n"
        "GtGQ6fmAVPGsnqlEk6c3AhDK6MzET+A/wLJV2OPOJVpMdq6g46BdzRtePVlHwENi\n"
        "8H4JD9NNCLe6+cxFvmtgy15Rjq2ttcxChDqkG6hJ87stPiwAA5CmyzmuBDjrOhge\n"
        "K36MRFieqz1hBWpyGcd+MZC34jv6nHGOZ1PZy1o+hnxCwhVRbJEOj4KS6u6/m3YZ\n"
        "mkuFA0ZwwiwUbpWOQvoAuDVN30GYznYQBiFJX9tKvPWTxpTvhFi84nZOCZS3wQMC\n"
        "wubcm0dcGVbZLZGQUNw5XqeomjaP33aClWay+W+HC+iw4kGt9TG26IRKYKuLV0Db\n"
        "xMU3lAUgR7INJJE9on8cCX8KgTUE2EgOkHC/r9N7Vr6zGd64FRli0/LINEcR0oNt\n"
        "zYLl1ADNeaPh1KLEtUQxO7HK9juEJdtoUXK8ziz3hyn/3GczKX9smb3hhLBuHk8w\n"
        "AiZJjlHl7zF0zj08xRQ0RkGeIrQsdjDkzON+iwH/txxwp2aBkLOnXDwde00Gv4pD\n"
        "+MiCaSaMUnjXCzMx2FBtYiWnOA6Np4sPnsZoKx7gHksorVV6llquorCWTtc57Nrz\n"
        "uddusXpyLozpjPxUI73YvOwzPwomVKCbucTMimVcJjiJJ0arbv8rBz//EEPHJpyw\n"
        "kcT0fv/xjj+te0GKwdlk9LYDpm0oiWAgU5GU2CsCwe1mngVZlaTDRtbsIvEnpds2\n"
        "Pxr3Q5XbbdHKT1FN5qq0rXp4Oxy3x7vbCpLdVpvw3YVO89/D+G2QYdc5pWyKhuro\n"
        "MYkJIuQSefjcODWKjdO8vEaciEojs0M58vEtK+uwx0HgyzpqnhlMEf9W4dTgrSbk\n"
        "Hhpb5IfS3264YWURNi1hxgKuBoyH7TcpVrUJYjnLBE8a81jAUry7DqSxnU/bpJS5\n"
        "FJicXuZBI+9PgyIE/FCIMdrZrCb2+tosJUuPvc1WK3Uo1RZ8oSAf+sOQBXlWJDOD\n"
        "KvzPtl/Wo+Tlci8EDEWxkFO/DkqjLXIt9sUOnBbLXKVx8HyDdLh4SbeR59SlHj8z\n"
        "Md3r/0DDNUHLyGitPB8OSPuC357tH0EwcjyOFCWo6iv1iSQeErG6CAp+9H19SggG\n"
        "MX6yPwTOVG2ZB4wvwHLyzzUiRz8TSM8E30bNJSomDqjtOqwe5s7TqLMFEUgmGY7Z\n"
        "ne91XiQ9rLR4scl4+/g9TslbS8W/YfqytDQFrFt8u6EnPo/KHTQkcIrA0XuPaUCV\n"
        "bd7U329h/y6na2H4fgxNcZiqM4F4z9fn4ypFbB4FSVjVSBZXfCj6z+CdR4zjsrcj\n"
        "X4BrQTqdx0YcpPqeAMxbUMjki77WlbjBPHtkuSQgy5I+gxSX+n69ELbMWB9vpx+j\n"
        "I4068kf9cbwwYw8mKC9U3jf3wS8BqEtAUHwgzfoifqquLQjxCO7RHFKy9TGPIkQe\n"
        "C0+na2VtOtB6I4xoi47/vnuDpT5NVS6Yirjkq9X7VUtfmLbcRKO5CLFR8EmNcCGn\n"
        "4hO3tCy/T1PMtQ8XxRS3rCrBft+WyHRzrerA/HjAZvQ0+f3FKDHyNP7QTxjyiUuo\n"
        "zfeWkr2XZKZB9j0OwY7nmHtAw4007QeX3FZFZhORgF/sKEACPqSD2t4chViYcwna\n"
        "ygMa7/AuOBxGqB0ai3JeIUuPybLWUDbQIOu66mZ4pt6Df1aU48GY7kVEpz4F/+9B\n"
        "V+Z+s6zMh4FFEicUh6+bBLVdRPC7mv564oKNoCKmj4FCN9YnTSOqdVNvs58jvgf5\n"
        "9weIZnh1u226w8cG3cEFRTF8c4Sle5o6RxVpZd3WLAgcWX/oGYNCqPc7eU8hhfxL\n"
        "55/4nFEJImo2rMlAmYYhOVxrZZNv4TiRnimOaG19e/fobzaZoWtzd5vfYvrWz7KA\n"
        "ivr2ppqVadzsZB6rAanz3LEz/djJaePqvOx2DHgcoH3Gi24qS/XTpNgsC2i7jSw+\n"
        "g4qx0iSpWSzn4qf4YM/l2JmSA+ZTuaPm8EkFig1u5jErT268pjcqvqPBdvfcwSYX\n"
        "a+vDzxIZviB7LrKvuH/PWjaiUpe37Jc+kH92S90q/Bq4eXrm6d3BSjKsx+bl1mLP\n"
        "e/txbhAvG0uBc8CoX/PBcY/d5y4Pf+LjZbiU/5ocnOFkxY3ra64gpofWDCdp8t2V\n"
        "gts=\n"
        "-----END ENCRYPTED PRIVATE KEY-----\n";

static void test_encrypt_decrypt(const VirgilKeyPair& keyPair, const VirgilByteArray& keyPassword) {
    VirgilByteArray testData = str2bytes("this string will be encrypted");
    VirgilByteArray recipientId = str2bytes("2e8176ba-34db-4c65-b977-c5eac687c4ac");

    VirgilCipher cipher;
    cipher.addKeyRecipient(recipientId, keyPair.publicKey());

    SECTION("and embedded content info") {
        VirgilByteArray encryptedData = cipher.encrypt(testData, true);
        VirgilByteArray decryptedData;
        REQUIRE_THROWS(
                decryptedData = cipher.decryptWithKey(encryptedData, recipientId, keyPair.privateKey())
        );
        REQUIRE_NOTHROW(
                decryptedData = cipher.decryptWithKey(encryptedData, recipientId, keyPair.privateKey(), keyPassword)
        );
        REQUIRE(testData == decryptedData);
    }

    SECTION("and embedded content info with custom parameters") {
        VirgilByteArray intParamKey = str2bytes("int_parameter_key");
        const int intParamValue = 35777;
        VirgilByteArray strParamKey = str2bytes("string_parameter_key");
        VirgilByteArray strParamValue = str2bytes("string parameter");
        VirgilByteArray hexParamKey = str2bytes("data_param_value");
        VirgilByteArray hexParamValue = str2bytes("will be stored as octet string");

        cipher.customParams().setInteger(intParamKey, intParamValue);
        cipher.customParams().setString(strParamKey, strParamValue);
        cipher.customParams().setData(hexParamKey, hexParamValue);

        VirgilByteArray encryptedData = cipher.encrypt(testData, true);
        cipher.removeAllRecipients();
        cipher.customParams().clear();

        VirgilByteArray decryptedData;
        REQUIRE_NOTHROW(
                decryptedData = cipher.decryptWithKey(encryptedData, recipientId, keyPair.privateKey(), keyPassword)
        );
        REQUIRE(testData == decryptedData);

        REQUIRE(cipher.customParams().getInteger(intParamKey) == intParamValue);
        REQUIRE(cipher.customParams().getString(strParamKey) == strParamValue);
        REQUIRE(cipher.customParams().getData(hexParamKey) == hexParamValue);
    }

    SECTION("and separated content info") {
        VirgilByteArray encryptedData = cipher.encrypt(testData, false);
        VirgilByteArray contentInfo = cipher.getContentInfo();
        REQUIRE(contentInfo.size() > 0);

        REQUIRE_NOTHROW(
                cipher.setContentInfo(contentInfo)
        );

        VirgilByteArray decryptedData;
        REQUIRE_THROWS(
                decryptedData = cipher.decryptWithKey(encryptedData, recipientId, keyPair.privateKey())
        );
        REQUIRE_NOTHROW(
                decryptedData = cipher.decryptWithKey(encryptedData, recipientId, keyPair.privateKey(), keyPassword)
        );
        REQUIRE(testData == decryptedData);
    }

    SECTION("and separated content info with custom parameters") {
        VirgilByteArray intParamKey = str2bytes("int_parameter_key");
        const int intParamValue = 35777;
        VirgilByteArray strParamKey = str2bytes("string_parameter_key");
        VirgilByteArray strParamValue = str2bytes("string parameter");
        VirgilByteArray hexParamKey = str2bytes("data_param_value");
        VirgilByteArray hexParamValue = str2bytes("will be stored as octet string");

        cipher.customParams().setInteger(intParamKey, intParamValue);
        cipher.customParams().setString(strParamKey, strParamValue);
        cipher.customParams().setData(hexParamKey, hexParamValue);

        VirgilByteArray encryptedData = cipher.encrypt(testData, false);
        VirgilByteArray contentInfo = cipher.getContentInfo();
        REQUIRE(contentInfo.size() > 0);

        REQUIRE_NOTHROW(
                cipher.setContentInfo(contentInfo)
        );

        VirgilByteArray decryptedData;
        REQUIRE_NOTHROW(
                decryptedData = cipher.decryptWithKey(encryptedData, recipientId, keyPair.privateKey(), keyPassword)
        );
        REQUIRE(testData == decryptedData);

        REQUIRE(cipher.customParams().getInteger(intParamKey) == intParamValue);
        REQUIRE(cipher.customParams().getString(strParamKey) == strParamValue);
        REQUIRE(cipher.customParams().getData(hexParamKey) == hexParamValue);
    }
}

#define TEST_CASE_ENCRYPT_DECRYPT(KeyType) \
    TEST_CASE("VirgilCipher: encrypt and decrypt with " #KeyType "keys", "[cipher]") { \
        const VirgilByteArray keyPassword = VirgilByteArrayUtils::stringToBytes("key password"); \
        test_encrypt_decrypt(VirgilKeyPair::generate(VirgilKeyPair::Type::KeyType, keyPassword), keyPassword); \
    }

TEST_CASE_ENCRYPT_DECRYPT(Default)

TEST_CASE_ENCRYPT_DECRYPT(EC_SECP384R1)

TEST_CASE_ENCRYPT_DECRYPT(EC_BP384R1)

TEST_CASE_ENCRYPT_DECRYPT(EC_SECP256K1)

TEST_CASE_ENCRYPT_DECRYPT(EC_Curve25519)

TEST_CASE_ENCRYPT_DECRYPT(EC_Ed25519)

TEST_CASE_ENCRYPT_DECRYPT(RSA_2048)

TEST_CASE_ENCRYPT_DECRYPT(RSA_3072)

TEST_CASE_ENCRYPT_DECRYPT(RSA_4096)

#undef TEST_CASE_ENCRYPT_DECRYPT

TEST_CASE("VirgilCipher: encrypt and decrypt with RSA_8192 keys", "[cipher]") {
    const VirgilByteArray keyPassword = VirgilByteArrayUtils::stringToBytes("password");
    test_encrypt_decrypt(VirgilKeyPair(
            VirgilByteArrayUtils::stringToBytes(kRSA_8192_Public),
            VirgilByteArrayUtils::stringToBytes(kRSA_8192_Private)), keyPassword
    );
}

TEST_CASE("VirgilCipher: encrypt and decrypt for multiple recipients", "[cipher]") {
    VirgilByteArray testData = str2bytes("this string will be encrypted");
    VirgilByteArray bobId = str2bytes("2e8176ba-34db-4c65-b977-c5eac687c4ac");
    VirgilByteArray johnId = str2bytes("968dc52d-2045-4abe-ab51-0b04737cac76");
    VirgilKeyPair bobKeyPair;
    VirgilKeyPair johnKeyPair;
    VirgilByteArray alicePassword = str2bytes("alice secret");

    SECTION("encrypt for multiple recipients") {
        VirgilByteArray encryptedData;

        VirgilCipher cipher;
        cipher.addKeyRecipient(bobId, bobKeyPair.publicKey());
        cipher.addKeyRecipient(johnId, johnKeyPair.publicKey());
        cipher.addPasswordRecipient(alicePassword);
        encryptedData = cipher.encrypt(testData, true);

        SECTION("decrypt for Bob") {
            VirgilCipher decoder;
            VirgilByteArray decryptedData = decoder.decryptWithKey(encryptedData, bobId, bobKeyPair.privateKey());
            REQUIRE(testData == decryptedData);
        }

        SECTION("decrypt for John") {
            VirgilCipher decoder;
            VirgilByteArray decryptedData = decoder.decryptWithKey(encryptedData, johnId, johnKeyPair.privateKey());
            REQUIRE(testData == decryptedData);
        }

        SECTION("decrypt for Alice") {
            VirgilCipher decoder;
            VirgilByteArray decryptedData = decoder.decryptWithPassword(encryptedData, alicePassword);
            REQUIRE(testData == decryptedData);
        }
    }
}

TEST_CASE("VirgilCipher: encrypt and decrypt with password", "[cipher]") {
    VirgilByteArray password = str2bytes("password");
    VirgilByteArray wrongPassword = str2bytes("wrong password");
    VirgilByteArray testData = str2bytes("this string will be encrypted");

    VirgilCipher cipher;
    cipher.addPasswordRecipient(password);

    SECTION("and embedded content info") {
        VirgilByteArray encryptedData = cipher.encrypt(testData, true);
        VirgilByteArray decryptedData;
        REQUIRE_THROWS(
                decryptedData = cipher.decryptWithPassword(encryptedData, wrongPassword)
        );
        REQUIRE_NOTHROW(
                decryptedData = cipher.decryptWithPassword(encryptedData, password)
        );
        REQUIRE(testData == decryptedData);
    }
}

TEST_CASE("VirgilCipher: check recipient existence", "[cipher]") {
    VirgilByteArray bobId = str2bytes("2e8176ba-34db-4c65-b977-c5eac687c4ac");
    VirgilByteArray johnId = str2bytes("968dc52d-2045-4abe-ab51-0b04737cac76");
    VirgilByteArray aliceId = str2bytes("99e435e7-2527-4a5a-89bb-37927bdb337b");
    VirgilKeyPair bobKeyPair;
    VirgilKeyPair johnKeyPair;

    VirgilCipher cipher;
    cipher.addKeyRecipient(bobId, bobKeyPair.publicKey());
    cipher.addKeyRecipient(johnId, johnKeyPair.publicKey());

    SECTION("within local context") {
        REQUIRE(cipher.keyRecipientExists(bobId));
        REQUIRE(cipher.keyRecipientExists(johnId));
        REQUIRE_FALSE(cipher.keyRecipientExists(aliceId));
    }

    SECTION("ContentInfo context") {
        (void) cipher.encrypt(VirgilByteArray());

        VirgilCipher restoredCipher;
        restoredCipher.setContentInfo(cipher.getContentInfo());

        REQUIRE(restoredCipher.keyRecipientExists(bobId));
        REQUIRE(restoredCipher.keyRecipientExists(johnId));
        REQUIRE_FALSE(restoredCipher.keyRecipientExists(aliceId));
    }
}
