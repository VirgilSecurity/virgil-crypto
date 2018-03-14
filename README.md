[![Build Status](https://travis-ci.org/VirgilSecurity/virgil-crypto.svg?branch=master)](https://travis-ci.org/VirgilSecurity/virgil-crypto)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://raw.githubusercontent.com/VirgilSecurity/virgil-crypto/master/LICENSE)
[![Documentation Developers](https://img.shields.io/badge/docs-developers-green.svg)](https://developer.virgilsecurity.com)
[![Open source](https://img.shields.io/badge/open-source-green.svg)](http://virgilsecurity.github.io/virgil-crypto/)

# Library: Virgil Crypto

[Library features](#library-features) | [Supported algorithms](#supported-algorithms) | [Build](#build) | [Docs](#docs) | [Support](#support)

## Introduction
Welcome to Virgil!

Virgil is a stack of security libraries (ECIES with Crypto Agility wrapped in Virgil Cryptogram) and all the necessary infrastructure to enable seamless, end-to-end encryption for any application, platform or device. See below for currently available languages and platforms. Get in touch with us to get preview access to our key infrastructure.

Our library allows developers to add full end-to-end security to their existing digital solutions to become HIPAA and GDPR compliant and more.

Virgil Security, Inc., guides software developers into the forthcoming security world in which everything will be encrypted (and passwords will be eliminated).  In this world, the days of developers having to raise millions of dollars to build a secure chat, secure email, secure file-sharing, or a secure anything have come to an end.  Now developers can instead focus on building features that give them a competitive market advantage while end-users can enjoy the privacy and security they increasingly demand.

## Library Features

### Supported crypto operations
* Generate keys;
* Encrypt data;
* Decrypt data;
* Sign data;
* Verify data.

### Supported platforms
Crypto Library is suitable for the following platforms:
* Desktop (Windows, Linux, MacOS);
* Mobile (iOS, Android, WatchOS, TVOS);
* Web (WebAssembly, AsmJS) 

### Supported languages
Crypto Library is written in C++ and supports bindings for the following programming languages:
* Go
* PHP	
* Python
* Ruby
* Java
* C#
* AsmJS
* NodeJS
* WebAssembly

**Swift/Objective_C** language can use the Virgil Crypto Library directly, without any bind.

### Available Wrappers 
Virgil also has special wrappers for simplifying Crypto Library implementation in your digital solutions. We support wrappers for the following programming languages:
* [Go](https://github.com/VirgilSecurity/virgil-crypto-go)
* [Objective-C/Swift](https://github.com/VirgilSecurity/virgil-foundation-x)
* [C#/.NET](https://github.com/VirgilSecurity/virgil-sdk-crypto-net)
* [Ruby](https://github.com/VirgilSecurity/virgil-crypto-ruby)
* [Python](https://github.com/VirgilSecurity/virgil-crypto-python)
* [PHP](https://github.com/VirgilSecurity/virgil-sdk-crypto-php)
* [JS](https://github.com/VirgilSecurity/virgil-crypto-javascript)


## Supported algorithms


| Purpose              | Algorithm, Source                                                                                                                                                                                                                                                                                                                                                                   |
|----------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Key Generation, PRNG | [NIST SP 800-90A](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-90Ar1.pdf)                                                                                                                                                                                                                                                                                       |
| Key Derivation       | [KDF2\*](https://www.ietf.org/rfc/rfc2898),<br>  [HKDF](https://tools.ietf.org/html/rfc5869)                                                                                                                                                                                                                                                                                        |
| Key Exchange         | [X25519\*](https://tools.ietf.org/html/rfc7748),<br> [ECDH](http://csrc.nist.gov/groups/ST/toolkit/documents/SP800-56Arev1_3-8-07.pdf),<br> [RSA](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br1.pdf)                                                                                                                                                       |
| Hashing              | [SHA-2 (256\*/384\*/512)](https://tools.ietf.org/html/rfc4634),<br> [Blake2](https://tools.ietf.org/html/rfc7693)                                                                                                                                                                                                                                                                   |
| Digital Signature    | [Ed25519\*](https://tools.ietf.org/html/rfc8032),<br> [ECDSA](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf),<br> [RSASSA-PSS](https://tools.ietf.org/html/rfc4056)                                                                                                                                                                                                     |
| Entropy Source       | Linux [/dev/urandom](https://tls.mbed.org/module-level-design-rng),<br> Windows [CryptGenRandom()](https://tls.mbed.org/module-level-design-rng)                                                                                                                                                                                                                                    |
| Symmetric Algorithms | [AES GCM\*](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf),<br> [AES CBC](https://tools.ietf.org/html/rfc3602),<br> [Chacha20-Poly1305](https://tools.ietf.org/html/rfc7539)                                                                                                                                                                         |
| Elliptic Curves      | [X25519\*](https://tools.ietf.org/html/rfc7748),<br> [Ed25519](https://tools.ietf.org/html/rfc8032),<br> [Koblitz](https://www.ietf.org/rfc/rfc4492) (secp192k1, secp224k1, secp256k1),<br> [Brainpool](https://tools.ietf.org/html/rfc5639) (bp256r1, bp384r1, bp512r1), <br> [NIST](https://www.ietf.org/rfc/rfc5480.txt) (secp256r1, secp192r1, secp224r1, secp384r1, secp521r1) |

> **\*** - used by default.

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

#### Step 3 - Build the Library

Run the build script with the option `-h` to get help on how to build a library for a necessary OS, Platforms or languages. 

Build command has the following syntax:

```shell
 ./utils/build.sh [<target>] [<src_dir>] [<build_dir>] [<install_dir>]
```

where the command options are:

- &lt;target&gt; - (default = cpp) target to build wich contains two parts &lt;name&gt;[-&lt;version&gt;], where &ltname&gt;:
  
| &lt;name&gt;     | build information                                                                |
|------------------|----------------------------------------------------------------------------------|
| cpp              | build C++ library;                                                               |
| macos            | build framework for Apple macOSX, requirements: OS X, Xcode;                     |
| ios              | build framework for Apple iOS, requirements: OS X, Xcode;                        |
| watchos          | build framework for Apple WatchOS, requirements: OS X, Xcode;                    |
| tvos             | build framework for Apple TVOS, requirements: OS X, Xcode;                       |
| php              | build PHP library, requirements: php-dev;                                        |
| python           | build Python library;                                                            |
| ruby             | build Ruby library;                                                              |
| java             | build Java library, requirements: $JAVA_HOME;                                    |
| java_android     | build Java library under Android platform, requirements: $ANDROID_NDK;           |
| net              | build .NET library, requirements: .NET or Mono;                                  |
| net_macos        | build .NET library under Apple macOSX platform, requirements: Mono, OS X, Xcode; |
| net_ios          | build .NET library under Apple iOS platform, requirements: Mono, OS X, Xcode;    |
| net_applewatchos | build .NET library under WatchOS platform, requirements: Mono, OS X, Xcode;      |
| net_appletvos    | build .NET library under TVOS platform, requirements: Mono, OS X, Xcode;         |
| net_android      | build .NET library under Android platform, requirements: Mono, $ANDROID_NDK;     |
| asmjs            | build AsmJS library, requirements: $EMSDK_HOME;                                  |
| webasm           | build WebAssembly library, requirements: $EMSDK_HOME;                            |
| nodejs           | build NodeJS module;                                                             |
| go               | build Golang library.                                                            |  

> All avaliable Crypto Library versions you can find [here](http://virgilsecurity.github.io/virgil-crypto/).
- <src_dir>     - a path to the directory where a root CMakeLists.txt file is located (default = .).
- <build_dir>   - a path to the directory where temp files will be stored (default = build/&lt;target&gt;). 
- <install_dir> - a path to the directory where library files will be installed (default = install/&lt;target&gt;).



## Docs
We always try to make cryptography closer to the programmers, and the documentation below can get you started today.
* [Crypto Library API](http://virgilsecurity.github.io/virgil-crypto/)
* [Library usage examples](https://developer.virgilsecurity.com/docs/how-to#cryptography)
  * [Generate a key pair](https://developer.virgilsecurity.com/docs/cs/how-to/cryptography/generate-keypair)
  * [import and export keys](https://developer.virgilsecurity.com/docs/cs/how-to/cryptography/import-export-keys)
  * [generate and verify signature](https://developer.virgilsecurity.com/docs/cs/how-to/cryptography/generate-verify-signature)
  * [encrypt and decrypt data](https://developer.virgilsecurity.com/docs/cs/how-to/cryptography/encrypt-decrypt-data)
* [Virgil CLI for the Crypto Library](https://developer.virgilsecurity.com/docs/sdk-and-tools/virgil-cli/generate-keypair)



## Support
Our developer support team is here to help you.

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://join.slack.com/t/VirgilSecurity/shared_invite/enQtMjg4MDE4ODM3ODA4LTc2OWQwOTQ3YjNhNTQ0ZjJiZDc2NjkzYjYxNTI0YzhmNTY2ZDliMGJjYWQ5YmZiOGU5ZWEzNmJiMWZhYWVmYTM).
