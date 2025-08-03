# RaCrypt

A comprehensive cryptographic library written in C providing implementations of common cryptographic algorithms including block ciphers, hash functions, and public key cryptography.

## Features

### Block Ciphers
- **AES** (Advanced Encryption Standard) - 128/192/256-bit keys
- **DES/3DES** (Data Encryption Standard)
- **SEED** - Korean block cipher standard
- **ARIA** - Korean block cipher standard (128/192/256-bit)
- **Blowfish** - Variable key length cipher
- **RC4** - Stream cipher

### Hash Functions
- **MD2/MD4/MD5** - Message Digest algorithms
- **SHA-1** - Secure Hash Algorithm 1
- **SHA-2** - SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256
- **HAS-160** - Korean hash standard

### Public Key Cryptography
- **RSA** - Key generation, encryption/decryption, digital signatures
- **ASN.1** - DER encoding/decoding for key import/export

### Block Cipher Modes
- ECB (Electronic Codebook)
- CBC (Cipher Block Chaining)
- CFB (Cipher Feedback)
- OFB (Output Feedback)
- CTR (Counter)

### Padding Schemes
- None
- Zero padding
- PKCS#7

## Platform Support

RaCrypt supports multiple platforms with optimized implementations:

- **Windows** (MSVC x86/x64)
- **Linux/Unix** (GCC x86/x86_64)
- **ARM64** (with NEON/crypto extensions)
- **MinGW** cross-compilation

### Assembly Optimizations

The library includes platform-specific assembly optimizations:
- **x86_64**: MASM assembly for AES, SHA-1, SHA-2
- **x86**: MASM assembly for AES, SHA-1, SHA-2
- **GCC/MinGW**: C intrinsics fallback
- **ARM64**: NEON and crypto extensions

## Building

### Prerequisites

- CMake 3.10 or higher
- C compiler (MSVC, GCC, or MinGW)
- For MSVC: Visual Studio with MASM support

### CMake Build

```bash
# Generate build files
cmake -B build

# Build the library and test executable
cmake --build build

# Or use specific configuration
cmake --build build --config Release
```

### MSVC Project Files

Pre-configured Visual Studio project files are available:
- `msvc2022/racrypt.sln` - Hand-maintained projects

### Build Targets

- `racrypt` - Static library
- `racrypt_test` - Test executable with comprehensive test suite

## Usage Example

```c
#include <racrypt.h>

// AES encryption example
struct RaAesCtx ctx;
uint8_t key[RA_KEY_LEN_AES_128] = {0}; // 128-bit key
uint8_t input[] = "The quick brown fox jumps over the lazy dog";
// The length is a multiple of RA_BLOCK_LEN_AES(16) longer than the input length
uint8_t encrypted[64];      
uint8_t decrypted[64];

// Initialize AES-128 in CBC mode
RaAesInit(&ctx, key, RA_AES_128, RA_BLOCK_MODE_CBC);

// Encrypt with PKCS7 padding
int encLen = RaAesEncryptFinal(&ctx, input, sizeof(input), encrypted, RA_BLOCK_PADDING_PKCS7);

// Decrypt
int decLen = RaAesDecryptFinal(&ctx, encrypted, encLen, decrypted, RA_BLOCK_PADDING_PKCS7);
```

## Testing

The library includes a comprehensive test suite (`racrypt_test`) that validates:

- Algorithm correctness with known test vectors
- Cross-platform compatibility
- Performance benchmarks (1GB throughput tests)
- RSA key generation and cryptographic operations
- Random data encryption/decryption stress tests

Run tests:
```bash
# After building
./build/racrypt_test              # Linux/Unix
```

## Performance

The library is optimized for high performance:
- Hardware-accelerated implementations where available
- Assembly optimizations for x86/x64 platforms
- ARM64 NEON/crypto extensions support

## Architecture

### Core Components

- `src/cipher/` - Block cipher implementations
- `src/digest/` - Hash function implementations  
- `src/pk/` - Public key cryptography (RSA, ASN.1)
- `src/com/` - Common utilities (big numbers, GCD, prime generation)
- `src/include/` - Public API headers

### Big Number Arithmetic

All public key operations use the built-in big number library:
- Automatic word size adaptation (32/64-bit)
- Montgomery multiplication for modular exponentiation
- Prime number generation with Miller-Rabin testing

## License

Copyright 2017, Keonwoo Kim. Licensed under the BSD 2-clause license.

## Contributing

When contributing:
1. Maintain cross-platform compatibility
2. Add test vectors for new algorithms
3. Update both C and assembly implementations
4. Verify endianness compatibility
