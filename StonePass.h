#pragma once
#define _CRT_DECLARE_NONSTDC_NAMES 1

#include <iostream>
#include <string>
#include <string_view>
#include <cstdint>
#include <stdexcept>

#include "StoneHash.h"
#include "StoneKey.h"
#include "StoneRNG.h"


#ifdef USE_NONPORTABLE_WINDOWS_INTERFACE
    // User explicitly requested Windows-specific version — allow only on MSVC
    #if !defined(_MSC_VER)
        #error "Windows-specific non-portable interface can only be used with MSVC"
    #endif
    #define USE_PORTABLE_INTERFACE 0
    #include "ui.h"
#else
    // Default: portable everywhere
    #define USE_PORTABLE_INTERFACE 1
#endif


/*
==============================================================================
Password Character Set Defaults — Easily Customizable
==============================================================================

StonePass excludes visually ambiguous characters by default (I/l/1, O/o/0) to
reduce entry errors and improve usability. The symbol set focuses on characters
accepted by nearly all websites.

You can override any of these defaults simply by #defining them *before*
including this header (or in your build settings). This lets you tailor the
generator to strict corporate policies, legacy systems, or personal preferences.

Example (before #include "StonePass.h"):
    #define STONEPASS_UPPERCASE   "ABCDEFGHIJKLMNOPQRSTUVWXYZ"  // include I,O
    #define STONEPASS_SYMBOLS     "!@#$%^&*()-_=+[]{}|;:',.<>?"

If not overridden, the safe, high-compatibility defaults below are used.

Customization Example:
    To support sites with unusual password policies, include lines like these
    immediately after this comment block.

        #define STONEPASS_UPPERCASE "ABCDWXYZ" // example overrides
        #define STONEPASS_LOWERCASE "abcdwxyz"
        #define STONEPASS_DIGITS "0123456789"
        #define STONEPASS_SYMBOLS "@#$%&*()[]!"
==============================================================================
*/


#ifndef STONEPASS_UPPERCASE
#define STONEPASS_UPPERCASE   "ABCDEFGHJKLMNPQRSTUVWXYZ"  // excludes I, O
#endif

#ifndef STONEPASS_LOWERCASE
#define STONEPASS_LOWERCASE   "abcdefghijkmnpqrstuvwxyz"  // excludes l, o
#endif

#ifndef STONEPASS_DIGITS
#define STONEPASS_DIGITS      "23456789"                  // excludes 0, 1
#endif

#ifndef STONEPASS_SYMBOLS
#define STONEPASS_SYMBOLS     "@#$%&*()[]{};:,.?"         // widely accepted symbols
#endif

/*
StonePass — Offline Deterministic Password Generator

Purpose and Intended Use
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

Customization
    Character sets can be easily customized by defining STONEPASS_UPPERCASE,
    STONEPASS_LOWERCASE, STONEPASS_DIGITS, and/or STONEPASS_SYMBOLS before
    including this header. See the "Password Character Set Defaults" section
    near the top of this file for details and examples.

Target Audience
    • Individuals managing their own passwords
    • Privacy-focused users
    • Security enthusiasts wanting transparent, auditable tools
    • Anyone preferring offline, deterministic password generation

Not Intended For
    • Organizations or applications requiring formal certification
      (e.g., FIPS 140, Common Criteria, NIST approval, NSA Suite B)
    • Regulated industries with compliance mandates
      (banking, healthcare/HIPAA, government, defense/DoD, finance, critical infrastructure)
    • High-value institutional targets where nation-state attackers are a primary threat
    • Environments requiring third-party cryptographic module validation

Security Notes
    The cryptographic constructions (ChaCha20 core, custom sponge hash, memory-hard KDF)
    are conservative and based on well-studied primitives, but they are personal
    designs without independent third-party cryptanalysis or formal security proofs.

    They are believed to provide more than adequate security for individual offline
    use against realistic threats (brute-force, dictionary attacks, local malware),
    especially when paired with a strong, high-entropy master passphrase.

    For mission-critical or regulated applications, use standardized, widely vetted
    libraries (libsodium, OpenSSL, Bouncy Castle) and formally validated implementations.

License
    MIT License — free to use, modify, and distribute.

Disclaimer
    Use at your own risk. The author provides no warranties. Test thoroughly in your
    environment. Always verify generated passwords meet site-specific requirements.
*/

/*
StonePass

Introduction

    The only deterministic, offline password generator in pure C++ — no storage, ChaCha20 crypto, MIT - licensed.

    Offline Deterministic Password Generator.No storage.No cloud.No telemetry.No backdoors.

    One master password.Every site.Nothing stored-- - ever.

    StonePass is a fast, secure, fully offline deterministic password generator.

    You type your master password once — StonePass derives a strong, unique password for every website, every time, 
    with perfect reproducibility and zero persistence.

    StonePass is the only password tool that contains zero bytes of secret material when it is not running.

    No storage. No cloud. No transmission. No database. No sync. Just cryptography and you.

Master Password Guidance

    IMPORTANT — Your master password is the ONLY secret

    StonePass never saves anything — not even a hash. If you forget your master password, every single generated 
    password is lost forever. There is no recovery.

    • Memorize it — this is the gold standard. 
    • Second-best: write it on paper or engrave it on metal and lock it in a safe, safety-deposit box, or with 
      a trusted person. 
    • Never store it digitally on your phone, computer, cloud notes, or “encrypted” password manager. 
    • Never take a photo or screenshot of it. 
    • Never write it in an email, chat, or text file.

    A strong master password (or better: a full passphrase) of 20–40 characters is trivial to remember with a 
    little practice and gives you decades of security even against nation-state attackers.

    Treat it like the master key to your entire digital life — because that’s exactly what it is.

*/

inline std::string generate_password(
    const std::string& username,
    const std::string& master_password,
    const std::string& site_name,
    int password_length,
    int password_version = 1,

    // === Character Sets ===
    // ───── High-readability, no look-alikes (recommended defaults) ─────
    std::string_view uppercase_chars = STONEPASS_UPPERCASE,  
    std::string_view lowercase_chars = STONEPASS_LOWERCASE,  
    std::string_view digit_chars = STONEPASS_DIGITS,         
    std::string_view symbol_chars = STONEPASS_SYMBOLS,       

    // === Policy Flags ===
    bool require_uppercase = true,
    bool require_lowercase = true,
    bool require_digits = true,
    bool require_symbols = true
){
    // === Input Validation ===
    // Empty inputs break determinism and security
    if (username.empty())
        throw std::invalid_argument("Username cannot be empty");
    if (master_password.empty())
        throw std::invalid_argument("Master password cannot be empty");
    if (site_name.empty())
        throw std::invalid_argument("Site name cannot be empty");
    if (password_length < 6 || password_length > 128)
        throw std::invalid_argument("password_length must be 6–128");
    if (password_version < 1)
        throw std::invalid_argument("Password version must be >= 1");

    if ((require_uppercase && uppercase_chars.empty()))
        throw std::invalid_argument("Invalid config: cannot require uppercase letters if none are supplied.");
    if ((require_lowercase && lowercase_chars.empty()))
        throw std::invalid_argument("Invalid config: cannot require lowercase letters if none are supplied.");
    if ((require_digits && digit_chars.empty()))
        throw std::invalid_argument("Invalid config: cannot require digits if none are supplied.");
    if ((require_symbols && symbol_chars.empty()))
        throw std::invalid_argument("Invalid config: cannot require symbols if none are supplied.");

    // Count required categories
    int required_count = 0;
    if (require_uppercase) ++required_count;
    if (require_lowercase) ++required_count;
    if (require_digits)    ++required_count;
    if (require_symbols)   ++required_count;

    if (password_length < required_count) {
        throw std::invalid_argument("password_length too short for required categories");
    }

    // === Create random number generator ===

    const std::string context =
        std::string("StonePassword_v1.0\0")
        + std::to_string(password_version) + '\0'
        + username + '\0' + site_name + '\0'
        + "len:" + std::to_string(password_length)
        + "\0upper:" + (require_uppercase ? "1" : "0")
        + "\0lower:" + (require_lowercase ? "1" : "0")
        + "\0digits:" + (require_digits ? "1" : "0")
        + "\0symbols:" + (require_symbols ? "1" : "0");

    st::Block32 hash1 = st::StoneKey(master_password, context); // memory hard password hasher

    // Create random number generator
    st::StoneRNG rng(hash1);

    // === Define Character Pools ===
    const std::string uppercase(uppercase_chars);
    const std::string lowercase(lowercase_chars);
    const std::string digits(digit_chars);
    const std::string symbols(symbol_chars);
    std::string all_chars;
    if (require_uppercase) all_chars += uppercase;
    if (require_lowercase) all_chars += lowercase;
    if (require_digits)    all_chars += digits;
    if (require_symbols)   all_chars += symbols;

    // === Build Password with Guaranteed Diversity ===
    std::string password;
    password.reserve(password_length);  // Avoid reallocations

    // lambda to draw a character from a character set.
    auto draw = [](std::string_view characters, st::StoneRNG& rng) -> char {
        // rng.unbiased(0, N) returns values in [0, N] inclusive → perfect for indexing
        const std::size_t max_index = characters.size() - 1;
        return characters[rng.unbiased(0, max_index)];
        };

    // Enforce policy: at least one from each required category
    if (require_uppercase) password += draw(uppercase, rng);
    if (require_lowercase) password += draw(lowercase, rng);
    if (require_digits) password += draw(digits, rng);
    if (require_symbols) password += draw(symbols, rng);

    // Fill remaining positions randomly from full set
    while (password.size() < password_length) {
        password += draw(all_chars, rng);
    }

    // === Fisher-Yates Shuffle for Uniformity ===
    // Shuffling ensures no bias from forced prefix positions
    for (size_t i = password_length - 1; i > 0; --i) {
        const size_t j = rng.unbiased(0, i);
        std::swap(password[i], password[j]);
    }

    return password;
}

// By default, use the portable interface on all platforms.
// 
// To enable the Windows-specific non-portable interface (which uses windows.h, _getch, etc.),
// define USE_NONPORTABLE_WINDOWS_INTERFACE before including this header, e.g.:
//   - Via compiler flag: /DUSE_NONPORTABLE_WINDOWS_INTERFACE or -DUSE_NONPORTABLE_WINDOWS_INTERFACE
//   - Or temporarily uncomment the line below for testing.
//
// This option is only available on Windows (MSVC).



#if !USE_PORTABLE_INTERFACE
// NON-PORTABLE interface. Requires windows.h
inline void generate_password_interactive()
{
    std::vector<ui::InputField> fields;
    int active = 0;

    fields.push_back({ 1, 5,  "=== StonePass - Offline Deterministic Password Generator ===", ui::DISPLAY });
    fields.push_back({ 3, 0,  "", ui::DISPLAY }); // blank line
    fields.push_back({ 5, 5,  "Username / Email    : ", ui::STRING_INPUT, "", 0, 60 });
    fields.push_back({ 7, 5,  "Master Password     : ", ui::STRING_INPUT, "", 0, 80 });
    fields.push_back({ 9, 5,  "Site / Domain       : ", ui::STRING_INPUT, "", 0, 80 });
    fields.push_back({ 11, 5,  "Version (counter)   : ", ui::INT_INPUT, "1", 1, 8 });     // default 1
    fields.push_back({ 13, 5,  "Length (8-64)       : ", ui::INT_INPUT, "20", 20, 3 });
    fields.push_back({ 16, 0,  "Tab/Arrows = navigate • Enter = button • Esc = quit", ui::DISPLAY });
    fields.push_back({ 18, 12, "", ui::BUTTON, "", 0, 0, "Generate" });
    fields.push_back({ 18, 32, "", ui::BUTTON, "", 0, 0, "Exit" });

    active = ui::run_ui(fields);

    if(fields[active].button_text=="Generate"){
        std::string username = fields[2].value_str;
        std::string master_password = fields[3].value_str;
        std::string site_name = fields[4].value_str;
        int password_version = fields[5].value_int;
        int password_length = fields[6].value_int;

        ui::cls();
        std::cout << "Please wait -- generating password: ";
        std::string result = generate_password(
            username,
            master_password,
            site_name,
            password_length,
            password_version = 1,
            "ABCDEFGHJKLMNPQRSTUVWXYZ",  // no I,O
            "abcdefghijkmnpqrstuvwxyz",  // no l,o
            "23456789",                  // no 0,1
            "@#$%&*()[]{};:,.?",         // widely accepted
            true, // require uppercase
            true, // require lowercase
            true, // require digits
            true  // require symbols
        );

        ui::cls();
        if (active != 9) { // all cases except the 'exit' button
            std::cout << "*** PASSWORD GENERATOR ***\n";
            std::cout << "Input data\n";
            std::cout << "\tUsername = " << username << "\n";
            std::cout << "\tMaster Password = " << master_password << "\n";
            std::cout << "\tsite_name = " << site_name << "\n";
            std::cout << "\tpassword length = " << password_length << "\n";
            std::cout << "\tpassword version = " << password_version << "\n";
            std::cout << "Generated Password\n";
            std::cout << "\t" << result << "\n";
            std::cout << "\n\n";
            std::cout << "Copy and use this password immediately. This program will not store this password.\n";
            std::cout << "Do not store it on a digital device. If you need this password again, simply run\n";
            std::cout << "this program again.\n";
            std::cout << "\n";
            std::cout << "Press any key to clear the screen.";
            uint8_t key = _getch();
            ui::cls();
        }
    }
}// generate_password_interactive
#else
#include <string>
#include <iostream>
#include <limits>

#include <algorithm>
#include <cctype>

// Helper to trim whitespace
std::string trim(const std::string& str) {
    auto start = std::find_if(str.begin(), str.end(), [](unsigned char c) { return !std::isspace(c); });
    auto end = std::find_if(str.rbegin(), str.rend(), [](unsigned char c) { return !std::isspace(c); }).base();
    return (start < end) ? std::string(start, end) : std::string();
}

std::string prompt_gets(const std::string& prompt) {
    std::cout << prompt;
    std::cout.flush();

    std::string s;
    std::getline(std::cin, s);
    std::cout << std::endl;  // forces clean separation

    return trim(s);
}

int prompt_geti(const std::string& prompt, int min_val, int max_val = INT_MAX)
{
    if (!prompt.empty()) {
        std::cout << prompt;
        if (max_val != INT_MAX)
            std::cout << " [" << min_val << "-" << max_val << "]";
        std::cout << ": ";
        std::cout.flush();
    }

    int value;
    while (true) {
        if (std::cin >> value && value >= min_val && value <= max_val) {
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            return value;
        }

        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cout << "Please enter a number between " << min_val << " and " << max_val << ": ";
        std::cout.flush();
    }
}

// PORTABLE interface
inline void generate_password_interactive() {
    std::cout << "=== StonePass - Offline Deterministic Password Generator ===\n";
    std::cout << "\n";
    std::string username        = prompt_gets("Username / Email               : ");
    std::string master_password = prompt_gets("Master Password                : ");
    std::string site_name       = prompt_gets("Site / Domain                  : ");
    int password_version        = prompt_geti("Version (counter) [1-999999]   : ", 1, 999999);
    int password_length         = prompt_geti("Length [8-64]                  : ", 8, 64);
    std::cout << "\n";
    std::cout << "Please wait -- generating password: ";
    std::cout << "\n";

    std::string result = generate_password(
        username,
        master_password,
        site_name,
        password_length,
        password_version = 1,
        "ABCDEFGHJKLMNPQRSTUVWXYZ",  // no I,O
        "abcdefghijkmnpqrstuvwxyz",  // no l,o
        "23456789",                  // no 0,1
        "@#$%&*()[]{};:,.?",         // widely accepted
        true, // require uppercase
        true, // require lowercase
        true, // require digits
        true  // require symbols
    );

    std::cout << "*** PASSWORD GENERATOR ***\n";
    std::cout << "Input data\n";
    std::cout << "\tUsername = " << username << "\n";
    std::cout << "\tMaster Password = " << master_password << "\n";
    std::cout << "\tsite_name = " << site_name << "\n";
    std::cout << "\tpassword length = " << password_length << "\n";
    std::cout << "\tpassword version = " << password_version << "\n";
    std::cout << "Generated Password\n";
    std::cout << "\t" << result << "\n";
    std::cout << "\n\n";
    std::cout << "Copy and use this password immediately. This program will not store this password.\n";
    std::cout << "Do not store it on a digital device. If you need this password again, simply run\n";
    std::cout << "this program again.\n";
    std::cout << "\n";
    std::cout << "";
    
    std::string dummy = prompt_gets("Press <Enter> to clear the screen : ");

    for(int i=0;i<60;i++)
        std::cout << "\n";
}
#endif
