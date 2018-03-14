[![Build Status](https://travis-ci.org/VirgilSecurity/virgil-crypto.svg?branch=master)](https://travis-ci.org/VirgilSecurity/virgil-crypto)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://raw.githubusercontent.com/VirgilSecurity/virgil-crypto/master/LICENSE)
[![Documentation Developers](https://img.shields.io/badge/docs-developers-green.svg)](https://developer.virgilsecurity.com)
[![Documentation Doxygen](https://img.shields.io/badge/docs-doxygen-blue.svg)](http://VirgilSecurity.github.io/virgil-crypto)


# Library: Virgil Crypto

[Supported languages and platforms](#supported-languages-and-platforms) | [Library features](#library-features) | [Supported keys](#supported-algorithms) | [Build](#build) | [Docs](#docs)
| [Support](#support)

## Introduction
Welcome to Virgil!

Virgil is a stack of security libraries (ECIES with Crypto Agility wrapped in Virgil Cryptogram) and all the necessary infrastructure to enable seamless, end-to-end encryption for any application, platform or device. See below for currently available languages and platforms. Get in touch with us to get preview access to our key infrastructure.

Our library allows developers to add full end-to-end security to their existing digital solutions to become HIPAA and GDPR compliant and more.

Virgil Security, Inc., guides software developers into the forthcoming security world in which everything will be encrypted (and passwords will be eliminated).  In this world, the days of developers having to raise millions of dollars to build a secure chat, secure email, secure file-sharing, or a secure anything have come to an end.  Now developers can instead focus on building features that give them a competitive market advantage while end-users can enjoy the privacy and security they increasingly demand.

## Supported languages and platforms

Crypto Library is written in C++, suitable for mobile and server platforms and supports bindings with the following programming languages:

| Language | Supported OS, platforms               |
|----------|----------------------------|
| C++      | ANY                        |
| PHP      | Unix, Linux, OS X          |
| Python   | Unix, Linux, OS X          |
| Ruby     | Unix, Linux, OS X          |
| Java     | Unix, Linux, OS X, Windows, Android |
| C#       | .NET, Mono                 |
| AsmJS    | Unix, Linux, OS X, Windows |
| NodeJS   | Unix, Linux, OS X, Windows |
| GO       | ..                           |

If you develop in a **Swift/Objective_C** language you can use the Virgil Crypto Library directly, without any bind.

Virgil also has special wrappers for simplifying Crypto Library implementation in your digital solutions. We support wrappers for the following programming languages:
* [Go](https://github.com/VirgilSecurity/virgil-crypto-go)
* [Objective-C/Swift](https://github.com/VirgilSecurity/virgil-foundation-x)
* [C#/.NET](https://github.com/VirgilSecurity/virgil-sdk-crypto-net)



## Library Features

### With the Virgil Crypto Library you can:
* Generate keys;
* Encrypt data;
* Decrypt data;
* Sign data;
* Verify data.

Crypto Library can be used on the following platforms:
* Desktop;
* Mobile;
* Web Browser

## Supported algorithms

| Key Algorithm   | Description                    | Notes                  |
|-----------------|--------------------------------|------------------------|
| RSA_256         | RSA 256 bit                    | weak, not recommended  |
| RSA_512         | RSA 512 bit                    | weak, not recommended  |
| RSA_1024        | RSA 1024 bit                   | weak, not recommended  |
| RSA_2048        | RSA 2048 bit                   | weak, not recommended  |
| RSA_3072        | RSA 3072 bit                   |                        |
| RSA_4096        | RSA 4096 bit                   |                        |
| RSA_8192        | RSA 8192 bit                   |                        |
| EC_SECP192R1    | 192-bits NIST curve            |                        |
| EC_SECP224R1    | 224-bits NIST curve            |                        |
| EC_SECP256R1    | 256-bits NIST curve            |                        |
| EC_SECP384R1    | 384-bits NIST curve            |                        |
| EC_SECP521R1    | 521-bits NIST curve            |                        |
| EC_BP256R1      | 256-bits Brainpool curve       |                        |
| EC_BP384R1      | 384-bits Brainpool curve       |                        |
| EC_BP512R1      | 512-bits Brainpool curve       |                        |
| EC_SECP192K1    | 192-bits "Koblitz" curve       |                        |
| EC_SECP224K1    | 224-bits "Koblitz" curve       |                        |
| EC_SECP256K1    | 256-bits "Koblitz" curve       |                        |
| EC_CURVE25519   | Curve25519 (deprecated format) | deprecated             |
| FAST_EC_X25519  | Curve25519                     | only encrypt / decrypt |
| FAST_EC_ED25519 | Ed25519                        | recommended, default   |


## Build

### Prerequisites

The page lists the prerequisite packages which need to be installed on the different platforms to be able to configure and to build Virgil Crypto Library.

* Compiler:
  - ```g++``` (version >= 4.9), or
  - ```clang++``` (version >= 3.6), or
  - ```msvc++``` (version >= 14.0)
* Build tools:
  - ```cmake``` (version >= 3.10)
  - ```make```
* Other tools:
  - ```git```
  - ```swig``` (version >= 3.0.12), optional for C++ build
  - ```doxygen``` (optional)


### Build the Library

This section describes how to build Virgil Crypto Library for а particular OS.

#### Step 1 - Get source code

- Open Terminal.
- Get the source code:
```shell
> git clone https://github.com/VirgilSecurity/virgil-crypto.git
```


#### Step 2 - Run a build Script

Unix-like OS:

```shell
> cd virgil-crypto
> ./utils/build.sh
```

Windows OS:

```shell
> cd virgil-crypto
> ./utils/build.bat
```

## Support
Our developer support team is here to help you.

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://join.slack.com/t/VirgilSecurity/shared_invite/enQtMjg4MDE4ODM3ODA4LTc2OWQwOTQ3YjNhNTQ0ZjJiZDc2NjkzYjYxNTI0YzhmNTY2ZDliMGJjYWQ5YmZiOGU5ZWEzNmJiMWZhYWVmYTM).
