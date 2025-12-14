# StonePass

    Offline Deterministic Password Generator

    No cloud. No storage. No back-doors. Based on a memorizable master password.
    Gives full control to the user.

    All C++, primarily header files.

    My goal it to make the world a better place, one password at a time.
    
    Reviews, analysis, testing, corrections and suggestions are welcome.
    
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
    
## Building and Running

### Windows (Fully Supported - Interactive UI)
    
    The macro in StonePass.cpp should be like this:
    
        #define USE_NONPORTABLE_WINDOWS_INTERFACE
        #include "StonePass.h"
        
        int main() {
        	generate_password_interactive();
        	return EXIT_SUCCESS;
        }

    1. Open Visual Studio (2022+ recommended, Community edition is free).
    2. Create a new **Empty C++ Console Project**.
    3. Add all `.h` files (and any `.cpp` if you add a main) to the project.
    4. Build and run.

### Linux MinGW/Clang / macOS (Fully Portable Interactive UI)

The interactive text-based UI is now fully portable and works on Linux and macOS without Windows-specific dependencies.
The macro in StonePass.cpp should be like this:
    
        //#define USE_NONPORTABLE_WINDOWS_INTERFACE
        #include "StonePass.h"
        
        int main() {
        	generate_password_interactive();
        	return EXIT_SUCCESS;
        }

Compile with:

        g++ -std=c++20 -O2 main.cpp -o stonepass
        ./stonepass

## Example Output
    
    === StonePass - Offline Deterministic Password Generator ===
    
    Username / Email               : John_Doe@gmail.com
    
    Master Password                : John::Doe's::Master::Password
    
    Site / Domain                  : example.com
    
    Version (counter) [1-999999]   :  [1-999999]: 1
    Length [8-64]                  :  [8-64]: 16
    
    Please wait -- generating password:
    *** PASSWORD GENERATOR ***
    Input data
            Username = John_Doe@gmail.com
            Master Password = John::Doe's::Master::Password
            site_name = example.com
            password length = 16
            password version = 1
    Generated Password
            8@svX9.kYP2Zd3vE
    
    
    Copy and use this password immediately. This program will not store this password.
    Do not store it on a digital device. If you need this password again, simply run
    this program again.
    
    Press <Enter> to clear the screen :

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
