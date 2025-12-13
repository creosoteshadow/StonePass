# StonePass

    Offline Deterministic Password Generator

    No cloud. No storage. No back-doors. Based on a memorizable master password.
    Gives full control to the user.

    All C++, primarily header files.
    
## Also Included

    StonePass required several elements that could be used as a part of other
    projects. The key ones are listed here.
    
    - StoneHash - Secure hash function, based on ChaCha permutation function.

    - StoneRNG - Secure random number, based on ChaCha keystream.

    - StoneKey - Memory-hard password hashing function.
    
## Purpose and Intended Use
    StonePass is a pure C++, header-only, fully offline deterministic password generator
    designed for individual users who want strong, reproducible passwords without storing
    any secrets, syncing to the cloud, or trusting third-party services.

    It derives high-entropy, site-specific passwords from a single memorized master
    passphrase using cryptographically sound primitives (ChaCha20 stream cipher,
    custom memory-hard KDF, and domain-separated hashing). The implementation follows
    modern cryptographic best practices while remaining simple, auditable, and
    dependency-free.

    StonePass is intended for personal security-conscious users seeking a trustworthy
    alternative to cloud-based password managers (Google, LastPass, etc.). It gives
    you complete control: no storage, no transmission, no telemetry, no backdoors.
    
## Installation

    Open Visual Studio, create an empty console project.
    Add all .cpp and .h files to the project.
    Compile.
    
## Customization
    Character sets can be easily customized by defining STONEPASS_UPPERCASE,
    STONEPASS_LOWERCASE, STONEPASS_DIGITS, and/or STONEPASS_SYMBOLS before
    including this header. See the "Password Character Set Defaults" section
    near the top of this file for details and examples.

## Target Audience
    • Individuals managing their own passwords
    • Privacy-focused users
    • Security enthusiasts wanting transparent, auditable tools
    • Anyone preferring offline, deterministic password generation

## Not Intended For
    • Organizations or applications requiring formal certification
      (e.g., FIPS 140, Common Criteria, NIST approval, NSA Suite B)
    • Regulated industries with compliance mandates
      (banking, healthcare/HIPAA, government, defense/DoD, finance, critical infrastructure)
    • High-value institutional targets where nation-state attackers are a primary threat
    • Environments requiring third-party cryptographic module validation

## Security Notes
    The cryptographic constructions (ChaCha20 core, custom sponge hash, memory-hard KDF)
    are conservative and based on well-studied primitives, but they are personal
    designs without independent third-party cryptanalysis or formal security proofs.

    They are believed to provide more than adequate security for individual offline
    use against realistic threats (brute-force, dictionary attacks, local malware),
    especially when paired with a strong, high-entropy master passphrase.

    For mission-critical or regulated applications, use standardized, widely vetted
    libraries (libsodium, OpenSSL, Bouncy Castle) and formally validated implementations.

## License
    MIT License — free to use, modify, and distribute.

## Disclaimer
    Use at your own risk. The author provides no warranties. Test thoroughly in your
    environment. Always verify generated passwords meet site-specific requirements.
