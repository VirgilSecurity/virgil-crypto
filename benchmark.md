# Benchmark tests

This file contain benchmark of the Virgil Crypto library:

## Environment for tests

These tests were made on MacBook Pro with the next specifications:

| Property      | Specifications                            |
|---------------|-------------------------------------------|
| Model         | MacBook Pro (Retina, 13-inch, Early 2015) |
| Processor     | 3.1 GHz Intel Core i7                     |
| Memory        | 16 GB 1867 MHz DDR3                       |
| MacOS version | High Sierra (version 10.13.3)             |

## Tests

### Hashing

| algorithm | samples | ns/op |
|-----------|---------|-------|
| MD5       | 100000  | 19314 |
| SHA-256   | 50000   | 38695 |
| SHA-384   | 50000   | 25606 |
| SHA-512   | 50000   | 25438 |

### Key pair generation

| algorithm                | samples | ns/op      |
|--------------------------|---------|------------|
| RSA 2048                 | 5       | 202676085  |
| RSA 3072                 | 5       | 761719258  |
| RSA 4096                 | 1       | 4606853434 |
| curve25519               | 50000   | 20493      |
| ed25519                  | 100000  | 16226      |
| 224-bits NIST curve      | 1000    | 1344291    |
| 256-bits NIST curve      | 1000    | 1911181    |
| 384-bits NIST curve      | 500     | 2565290    |
| 521-bits NIST curve      | 500     | 3758969    |
| 256-bits Brainpool curve | 100     | 13363189   |
| 384-bits Brainpool curve | 50      | 24520962   |
| 512-bits Brainpool curve | 50      | 45844118   |
| 192-bits Koblitz curve   | 1000    | 1601368    |
| 224-bits Koblitz curve   | 1000    | 1935883    |
| 256-bits Koblitz curve   | 500     | 2119124    |

### Export

| operation                              | samples | ns/op    |
|----------------------------------------|---------|----------|
| Public Key to DER                      | 2000000 | 577      |
| Public Key to PEM                      | 1000000 | 1560     |
| Private Key to DER (no password)       | 5000000 | 336      |
| Private Key to PEM (no password)       | 2000000 | 879      |
| Private Key to DER (with password)     | 100     | 14168461 |
| Private Key to PEM (with password)     | 100     | 13862879 |
| Public Key DER to PEM                  | 500     | 4426590  |
| Public Key PEM to DER                  | 500     | 4461710  |
| Private Key PEM to DER (no password)   | 500     | 4451291  |
| Private Key DER to PEM (no password)   | 500     | 4408890  |
| Private Key DER to PEM (with password) | 50      | 25451292 |
| Private Key PEM to DER (with password) | 50      | 29305614 |

### Encryption

| algorithm                | samples | ns/op |
|--------------------------|---------|-------|
| RSA 2048                 | 200000  | 9458  |
| RSA 3072                 | 100000  | 10776 |
| RSA 4096                 | 100000  | 11220 |
| Curve25519 curve         | 200000  | 9672  |
| Ed25519 curve            | 100000  | 11692 |
| 224-bits NIST curve      | 100000  | 10114 |
| 256-bits NIST curve      | 100000  | 11664 |
| 384-bits NIST curve      | 100000  | 13421 |
| 521-bits NIST curve      | 100000  | 10327 |
| 256-bits Brainpool curve | 100000  | 10152 |
| 384-bits Brainpool curve | 100000  | 10485 |
| 512-bits Brainpool curve | 100000  | 11166 |
| 192-bits Koblitz curve   | 100000  | 11069 |
| 224-bits Koblitz curve   | 200000  | 9631  |
| 256-bits Koblitz curve   | 200000  | 9740  |

### Decryption

| algorithm                | samples | ns/op    |
|--------------------------|---------|----------|
| RSA 2048                 | 200     | 8709333  |
| RSA 3072                 | 100     | 14597898 |
| RSA 4096                 | 50      | 24189009 |
| curve25519               | 500     | 4603996  |
| ed25519                  | 500     | 4545415  |
| 224-bits NIST curve      | 200     | 6140846  |
| 256-bits NIST curve      | 200     | 7106018  |
| 384-bits NIST curve      | 200     | 7754033  |
| 521-bits NIST curve      | 200     | 9074803  |
| 256-bits Brainpool curve | 100     | 19708554 |
| 384-bits Brainpool curve | 50      | 32892030 |
| 512-bits Brainpool curve | 20      | 57748835 |
| 192-bits Koblitz curve   | 200     | 6485849  |
| 224-bits Koblitz curve   | 200     | 6944859  |
| 256-bits Koblitz curve   | 200     | 7362125  |

### Sign

| algorithm                | samples | ns/op    |
|--------------------------|---------|----------|
| RSA 2048                 | 500     | 4061518  |
| RSA 3072                 | 200     | 9937662  |
| RSA 4096                 | 100     | 19593122 |
| 224-bits NIST curve      | 1000    | 1397832  |
| 256-bits NIST curve      | 500     | 2040942  |
| 384-bits NIST curve      | 500     | 2732660  |
| 521-bits NIST curve      | 500     | 3897379  |
| 256-bits Brainpool curve | 100     | 13377896 |
| 384-bits Brainpool curve | 50      | 25024584 |
| 512-bits Brainpool curve | 50      | 47017466 |
| 192-bits Koblitz curve   | 1000    | 1708163  |
| 224-bits Koblitz curve   | 500     | 2083555  |
| 256-bits Koblitz curve   | 500     | 2247125  |
| Ed25519 curve            | 20000   | 52751    |

### Verify

| algorithm                | samples | ns/op    |
|--------------------------|---------|----------|
| RSA 2048                 | 20000   | 94365    |
| RSA 3072                 | 10000   | 186789   |
| RSA 4096                 | 5000    | 298092   |
| 224-bits NIST curve      | 500     | 2694377  |
| 256-bits NIST curve      | 500     | 3983349  |
| 384-bits NIST curve      | 200     | 5237961  |
| 521-bits NIST curve      | 200     | 7485531  |
| 256-bits Brainpool curve | 50      | 26543606 |
| 384-bits Brainpool curve | 50      | 48791525 |
| 512-bits Brainpool curve | 20      | 91268881 |
| 192-bits Koblitz curve   | 500     | 3233918  |
| 224-bits Koblitz curve   | 500     | 4083664  |
| 256-bits Koblitz curve   | 500     | 4345015  |
| Ed25519 curve            | 20000   | 59837    |
