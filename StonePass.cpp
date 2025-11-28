#define _CRT_SECURE_NO_WARNINGS
// file StonePass.cpp

/*
    StonePass — Offline Deterministic Password Generator
    Copyright © 2025 James E. Staley
    Licensed under the MIT License — see LICENSE.txt

    Goal
    ───────
        Generate strong, unique, reproducible passwords for every website using only:
          • A username (or email)
          • A single strong master password
          • The site name
          • A version number (for forced changes)

        No storage. No cloud. No telemetry. No backdoors.
        You remember one password — StonePass remembers the rest.

    Security Design Principles
    ──────────────────────────
        • Fully deterministic — same inputs always produce the same password
        • Cryptographic-grade primitives only (ChaCha20 stream + custom ChaCha-based hash)
        • Fixed-cost expensive KDF (1 000 000 iterations) — GPU-resistant, reproducible across decades
        • Memory-hardened: sensitive data is explicitly zeroed with anti-optimization barriers
        • High-entropy output with enforced character class policy and Fisher–Yates shuffle
        • Default character sets exclude ambiguous look-alikes (0/O, 1/l/I, etc.)
        • 99+ bits of entropy for a 16-character password

    Master Password Guidance
    ────────────────────────
        IMPORTANT — Your master password is the ONLY secret.
        StonePass never saves anything — not even a hash.
        If you forget your master password, every single generated password is lost forever.
        There is no recovery.

        • Memorize it — this is the gold standard.
        • Second-best: write it on paper or engrave it on metal and lock it in a safe, safety-deposit box, or with a 
          trusted person.
        • Never store it digitally on your phone, computer, cloud notes, or “encrypted” password manager.
        • Never take a photo or screenshot of it.
        • Never write it in an email, chat, or text file.

        A strong master password (or better: a full passphrase) of 20–40 characters is trivial to remember with a 
        little practice and gives you decades of security even against nation-state attackers.

        Treat it like the master key to your entire digital life — because that’s exactly what it is.

    Configuration File Support
    ──────────────────────────
        StonePass supports optional configuration files to enforce organization-wide
        password policies without requiring long command lines.

        Search Order (first match wins):
          1. File specified via --file / -f
          2. /etc/stonepass.conf
          3. /usr/local/etc/stonepass.conf
          4. ~/.stonepassrc                  (user-specific)
          5. ./stonepass.conf                 (current directory)

        Format: Simple key = value (INI-style), one per line
        Lines beginning with # or ; are comments
        Whitespace around keys and values is trimmed
        Values may be quoted (but quotes are stripped)

        Example: /etc/stonepass/bank-policy.conf

            # Corporate banking policy — very strict
            uppercase = ABCDEFGHJKLMNPQRSTUVWXYZ
            lowercase = abcdefghjkmnpqrstuvwxyz
            digits    = 23456789
            symbols   = !@#$

            require_uppercase = true
            require_lowercase = true
            require_digits    = true
            require_symbols   = true

            length  = 24
            version = 1

        Example: ~/.stonepassrc (personal defaults)

            # My personal preferences — allow 0 and 1, but still avoid look-alikes
            digits = 0123456789

            # Most sites don't need symbols — reduce copy-paste pain
            symbols = !@#$%
            require_symbols = false

            length = 20

        Supported Keys
        ──────────────
        uppercase           String  Allowed uppercase letters
        lowercase           String  Allowed lowercase letters
        digits              String  Allowed digits
        symbols             String  Allowed symbols (empty string = none)

        require_uppercase   true/false  Enforce at least one uppercase
        require_lowercase   true/false  Enforce at least one lowercase
        require_digits      true/false  Enforce at least one digit
        require_symbols     true/false  Enforce at least one symbol

        length              integer     Default password length (8–128)
        version             integer     Default version number (>=1)

        Command-line arguments override config file settings.
        This allows temporary one-off changes without editing the config.

        Pro tip for sysadmins:
          Deploy /etc/stonepass.conf with restrictive policy
          Let users override only length/version in ~/.stonepassrc
          Use --file for per-client or per-project policies

    Core Function
    ─────────────
        std::string generate_password(
            const std::string& username,
            const std::string& master_password,
            const std::string& site_name,
            int password_length,
            int password_version = 1,
            std::string_view uppercase_chars = "ABCDEFGHJKLMNPQRSTUVWXYZ",
            std::string_view lowercase_chars = "abcdefghijkmnpqrstuvwxyz",
            std::string_view digit_chars     = "23456789",
            std::string_view symbol_chars    = "@#$%&*()[]{};:,.?",
            bool require_uppercase = true,
            bool require_lowercase = true,
            bool require_digits     = true,
            bool require_symbols    = true
        );

    Interactive console version: generate_password_interactive()
    Build with any modern C++20 compiler (g++/clang++/MSVC).
*/

#include <array>
#include <atomic>
#include <conio.h>
#include <cstdint>
#include <cstdlib>
#include <iostream>
#include <fstream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <stdexcept>
#include <vector>


 // ====================================================================
 // Portable rotl / rotr — works on GCC, Clang, MSVC, even ancient ones
 // ====================================================================
#if defined(__has_include) && __has_include(<bit>)
    // Best option: <bit> header from C++20
    #include <bit>
    using std::rotl;
    using std::rotr;
#elif defined(_MSC_VER) && (_MSC_VER >= 1920) && (_MSVC_LANG >= 202002L)
    // MSVC 2019 16.8+ with /std:c++20 or later has <bit>
    #include <bit>
    using std::rotl;
    using std::rotr;
#elif defined(__GNUC__) || defined(__clang__)
    // GCC/Clang builtin — works since forever
    inline constexpr uint32_t rotl(uint32_t x, int n) noexcept { return (x << n) | (x >> (32 - n)); }
    inline constexpr uint32_t rotr(uint32_t x, int n) noexcept { return (x >> n) | (x << (32 - n)); }
    inline constexpr uint64_t rotl(uint64_t x, int n) noexcept { return (x << n) | (x >> (64 - n)); }
    inline constexpr uint64_t rotr(uint64_t x, int n) noexcept { return (x >> n) | (x << (64 - n)); }
#else
    // Pure portable fallback — works on literally everything
    inline constexpr uint32_t rotl(uint32_t x, int n) noexcept {
        return (x << (n & 31)) | (x >> ((32 - (n & 31)) & 31));
    }
    inline constexpr uint32_t rotr(uint32_t x, int n) noexcept {
        return (x >> (n & 31)) | (x << ((32 - (n & 31)) & 31));
    }
    inline constexpr uint64_t rotl(uint64_t x, int n) noexcept {
        return (x << (n & 63)) | (x >> ((64 - (n & 63)) & 63));
    }
    inline constexpr uint64_t rotr(uint64_t x, int n) noexcept {
        return (x >> (n & 63)) | (x << ((64 - (n & 63)) & 63));
    }
#endif

// alias types for fixed-size unsigned integers
using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;

// ====================================================================
// namespace Utilities: miscellaneous helper functions
// ====================================================================
namespace Utilities {
    // secure_zero: securely zero out memory, for sensitive data.
    inline void secure_zero(void* data, size_t size) noexcept
    {
        if (!data || size == 0) return;

        volatile std::byte* p = static_cast<volatile std::byte*>(data);

        // Write zeros
        for (size_t i = 0; i < size; ++i)
            p[i] = std::byte{ 0 };

        // Verify the write actually stuck
        for (size_t i = 0; i < size; ++i) {
            if (p[i] != std::byte{ 0 }) {
                std::abort();  // RAM is broken, ECC corrected it away, or kernel is malicious
            }
        }

        // Full barrier – prevents compiler from eliminating the entire function
        std::atomic_thread_fence(std::memory_order_seq_cst);
    }

    // get_masked_input: get input from console with masking, for use with passwords
    inline std::string get_masked_input(std::string_view prompt)
    {
        std::string result;

#ifdef _MSC_VER
        // ───── Windows ─────
        std::cout << prompt << std::flush;  // ensure prompt appears immediately

        while (true) {
            int ch = _getch();

            if (ch == '\r' || ch == '\n') {        // Enter
                std::cout << '\n';
                break;
            }
            else if (ch == 3) {                        // Ctrl+C → abort gracefully
                std::cout << "^C\n";
                throw std::runtime_error("Input aborted by user");
            }
            else if (ch == 8 || ch == 127) {           // Backspace / DEL
                if (!result.empty()) {
                    result.pop_back();
                    std::cout << "\b \b" << std::flush;
                }
            }
            else if (ch < 32 || ch == 127)             // Ignore other control chars
                ;
            else {
                result += static_cast<char>(ch);
                std::cout << '*' << std::flush;
            }
        }

#else
        // ───── Unix (Linux/macOS/BSD) ─────
        if (tcgetattr(STDIN_FILENO, nullptr) == -1) {
            // Not a terminal → fall back to visible input (safe default)
            std::cout << prompt;
            std::getline(std::cin, result);
            return result;
        }

        termios oldt{}, newt{};
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        new.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &new);

        std::cout << prompt << std::flush;
        if (!std::getline(std::cin, result)) {
            // Handle EOF/Ctrl+D gracefully
            std::cout << '\n';
            tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
            throw std::runtime_error("Input interrupted");
        }

        tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        std::cout << '\n';
#endif

        return result;
    }

    // get_unmasked input: get input from console without masking.
    inline std::string get_unmasked_input(std::string_view prompt)
    {
        std::cout << prompt << std::flush;  // ensure prompt appears immediately
        std::string result;

        std::getline(std::cin, result);

        return result;
    }

    // cls: clear console screen
    inline void cls() noexcept
    {
        // ANSI escape codes — work everywhere modern
        std::cout << "\033[2J\033[3J\033[H" << std::flush;
        // Optional: spam newlines to defeat scrollback snooping
        //for (int i = 0; i < 50; ++i) std::cout << '\n';
    }
}// namespace Utilities


// ====================================================================
// namespace ChaCha: ChaCha20-based RNG and SecureHash
// ====================================================================
namespace ChaCha {

    using BLOCK64 = std::array<u32, 16>;  // 64-byte block
    using KEY = std::array<u32, 8>;// 256-bit key

    // 96-bit nonce, but when we are using a 64 bit counter instead of the standard 32 bit counter,
    // we only use the first 64 bits of the nonce.
    // Standard RFC 8439 ChaCha20: 32-bit counter + 96-bit nonce → 128 bits total
    // Our design: design : 64 - bit counter + first 64 bits of nonce → still 128 bits total, no security loss
    using NONCE = std::array<u32, 3>;

    static_assert(sizeof(BLOCK64) == 64, "BLOCK64 must be exactly 64 bytes");
    static_assert(sizeof(KEY) == 32, "KEY must be 256 bits");
    static_assert(sizeof(NONCE) == 12, "NONCE must be 96 bits");

    namespace ChaCha20_constants {
        inline constexpr std::array<u32, 4> sigma{
            0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u
        };
    }

    // -----------------------------------------------------------------
    // Core ChaCha20 primitives (20 rounds, RFC 8439 compatible)
    // -----------------------------------------------------------------
    inline constexpr void chacha_quarter_round(u32& a, u32& b, u32& c, u32& d) noexcept
    {
        a += b; d ^= a; d = std::rotl(d, 16u);
        c += d; b ^= c; b = std::rotl(b, 12u);
        a += b; d ^= a; d = std::rotl(d, 8u);
        c += d; b ^= c; b = std::rotl(b, 7u);
    }

    // chacha20_permute_block — RFC 8439 §2.3 "The ChaCha block function"
    // Applies the 20-round ChaCha permutation and final addition.
    // Input:  512-bit block (constants || key || counter || nonce)
    // Output: permuted 512-bit block (used as keystream when XORed with plaintext)
    inline constexpr void chacha20_permute_block(BLOCK64& out, const BLOCK64& in) noexcept
    {
        BLOCK64 x = in; // perform operations on a local copy of 'in'

        for (int i = 0; i < 10; ++i) {
            // column rounds
            chacha_quarter_round(x[0], x[4], x[8], x[12]);
            chacha_quarter_round(x[1], x[5], x[9], x[13]);
            chacha_quarter_round(x[2], x[6], x[10], x[14]);
            chacha_quarter_round(x[3], x[7], x[11], x[15]);
            // diagonal rounds
            chacha_quarter_round(x[0], x[5], x[10], x[15]);
            chacha_quarter_round(x[1], x[6], x[11], x[12]);
            chacha_quarter_round(x[2], x[7], x[8], x[13]);
            chacha_quarter_round(x[3], x[4], x[9], x[14]);
        }

        for (size_t i = 0; i < 16; ++i)
            out[i] = x[i] + in[i];
    }

    [[nodiscard]] inline constexpr BLOCK64 build_state(
        const KEY& key,
        const NONCE& nonce,
        u64 block_counter = 0
    ) noexcept
    {
        BLOCK64 state{};

        // 0–3: constants
        std::copy(ChaCha20_constants::sigma.begin(),
            ChaCha20_constants::sigma.end(),
            state.begin());

        // 4–11: key
        std::copy(key.begin(), key.end(), state.begin() + 4);

        // 12–13: 64-bit block counter (little-endian)
        state[12] = static_cast<u32>(block_counter);
        state[13] = static_cast<u32>(block_counter >> 32);

        // 14–15: first 64 bits of nonce only
        state[14] = nonce[0];
        state[15] = nonce[1];
        // nonce[2] intentionally ignored — we trade 32 bits of nonce space
        // for 32 extra bits of counter (2^64 blocks instead of 2^32)

        return state;
    }

    // Random Number Generator based on ChaCha20 keystream
    class RNG {
    public:
        using u64 = uint64_t;
        using u32 = uint32_t;
        using u8 = uint8_t;

        static constexpr uint64_t version = 1;
        using result_type = uint64_t;

        // -----------------------------------------------------------------
        // Public interface
        // -----------------------------------------------------------------
        // Strong, deterministic seeding (cryptographic)
        explicit RNG(const KEY& _key, const NONCE& _nonce = NONCE{})
            : key(_key), nonce(_nonce), buffer{}, counter(0), buffer_index_(0)
        {
            refill_if_needed();  // first block is generated immediately
        }


        // -----------------------------------------------------------------
        // Copy Constructor (Enables State Saving)
        // -----------------------------------------------------------------
        RNG(const RNG& other) = default;

        // -----------------------------------------------------------------
        // Uniform random integer in [min(), max()]
        // -----------------------------------------------------------------
        result_type operator()()
        {
            // ChaCha20 produces 64 bytes per block → two 32-bit words → one u64
            const u32 lo = next32();
            const u32 hi = next32();
            return (static_cast<u64>(hi) << 32) | lo;
        }

        // -----------------------------------------------------------------
        // Uniform random integer in [lo, hi]
        // -----------------------------------------------------------------
        std::uint64_t unbiased(std::uint64_t lo, std::uint64_t hi) // inclusive
        {
            if (lo > hi) std::swap(lo, hi);
            if (lo == hi) return lo;

            const std::uint64_t range = hi - lo + 1;
            const std::uint64_t limit = std::numeric_limits<std::uint64_t>::max() -
                (std::numeric_limits<std::uint64_t>::max() % range);

            std::uint64_t value;
            do {
                value = (*this)();
            } while (value > limit);

            return lo + (value % range);
        }

        static constexpr result_type min() { return 0; }
        static constexpr result_type max() { return UINT64_MAX; }

        // -----------------------------------------------------------------
        // std::uniform_int_distribution / std::discard compatible
        // Skip forward in the RNG sequence, equivalent to n_values calls to operator().
        // -----------------------------------------------------------------
        void discard(const size_t n) {
            if (n == 0)return;
            size_t nwords = n * 2;  // 2 × 32-bit words per u64

            // Step 1: consume buffered words
            if (nwords < static_cast<size_t>(buffer_index_)) {
                buffer_index_ -= static_cast<int>(nwords);
                return;
            }
            nwords -= buffer_index_;
            buffer_index_ = 0;
            counter++;

            // Step 2: skip full blocks
            const size_t words_per_block = 16; // 16 4-byte words in a block
            size_t full_blocks = nwords / words_per_block;
            size_t remainder = nwords % words_per_block;

            // update the block counter
            if (full_blocks != 0) {
                counter += full_blocks;
            }

            // Step 3: consume remainder by refilling once and discarding
            if (remainder != 0) {
                refill_if_needed();                  // generate next block
                buffer_index_ = static_cast<int>(words_per_block - remainder);
            }
        }

    private:
        // -----------------------------------------------------------------
        // Internal state
        // -----------------------------------------------------------------
        KEY     key;
        NONCE   nonce;
        BLOCK64 buffer;
        u64     counter;
        int     buffer_index_;   // 0 → buffer empty, 1-16 → valid words left

        // -----------------------------------------------------------------
        // Helper predicates
        // -----------------------------------------------------------------
        [[nodiscard]] bool buffer_empty() const noexcept { return buffer_index_ == 0; }


        // -----------------------------------------------------------------
        // Buffer management
        // -----------------------------------------------------------------
        void refill_if_needed() noexcept
        {
            if (!buffer_empty()) return;

            // ----- build the input block (same layout as RFC 8439) -----
            u64 block_counter = counter;
            BLOCK64 state = build_state(key, nonce, block_counter);

            chacha20_permute_block(buffer, state);     // serialize output into buffer_
            increment_counter();                // Prep the counter for the next buffer refill
            buffer_index_ = 16;                 // 16 valid 32-bit words
        }

        u32 next32() noexcept
        {
            refill_if_needed();
            --buffer_index_;
            return buffer[15 - buffer_index_];   // return the *oldest* word first
        }

        void increment_counter() noexcept
        {
            ++counter;
        }

        // -----------------------------------------------------------------
        // Helper: reset counter + clear buffer
        // -----------------------------------------------------------------
        void reset_state() noexcept
        {
            counter = 0;
            buffer_index_ = 0;
            refill_if_needed();   // generate first block
        }
    };

    // Hash function based on ChaCha20 permutation
    class SecureHash {
        private:

        // Helper class - BlockHash hashes only full blocks
        class BlockHash {
            BLOCK64 state = {};

        public:
            ~BlockHash() {
                wipe();
            }

            void update(const BLOCK64& block) {
                for (int i = 0; i < 16; ++i) state[i] ^= block[i];
                chacha20_permute_block(state, state); // perform 10 ChaCha double-rounds
            }

            [[nodiscard]] BLOCK64 finalize(uint64_t total_bytes) const {
                BLOCK64 h = state;
                h[0] ^= 0x01;
                h[14] ^= static_cast<u32>(total_bytes);
                h[15] ^= static_cast<u32>(total_bytes >> 32);
                chacha20_permute_block(h, h); // perform 10 ChaCha double-rounds

                return h;
            }

            void wipe() {
                Utilities::secure_zero(state.data(), 64);
            }
        };

    private:
        BlockHash bh;
        BLOCK64 buffer{};
        size_t pos;
        uint8_t* p_buffer;
        uint64_t total_len;

    public:
        /// Returns the size of the recommended cryptographic digest in bytes
        static constexpr std::size_t DIGEST_SIZE = 32; // 256 bit. 
        static constexpr std::size_t MAXIMUM_DIGEST_SIZE = 64; // 512 bit. 

        /// Returns the internal block size in bytes
        static constexpr std::size_t BLOCK_SIZE = 64;

        /// Returns the key size in bytes (256-bit)
        static constexpr std::size_t KEY_SIZE = 32;

        // Keyed constructor (256-bit recommended)
        // Default argument (all zeroes) can be used like an unkeyed hash.
        explicit SecureHash(std::array<uint64_t, 4> key = {}) noexcept
            : p_buffer(reinterpret_cast<uint8_t*>(buffer.data()))
            , total_len(0)
            , pos(0)
        {
            BLOCK64 init{}; // 16 × uint32_t = 64-byte ChaCha20 state block

            // Domain separation constants (positions 0-3) — prevent key confusion attacks
            init[0] = (uint32_t)0x9e3779b97f4a7c15ULL;  // derived from golden ratio
            init[1] = (uint32_t)0x6a09e667f3bcc908ULL;  // BLAKE2/ChaCha constant
            init[2] = (uint32_t)0xbb67ae8584caa73bULL;  // BLAKE2 constant
            init[3] = (uint32_t)0x3c6ef372fe94f82bULL;  // BLAKE2 constant

            // Expand 256-bit key → little-endian 32-bit words (positions 4–11 in state)
            init[4] = static_cast<u32>(key[0]);
            init[5] = static_cast<u32>(key[0] >> 32);
            init[6] = static_cast<u32>(key[1]);
            init[7] = static_cast<u32>(key[1] >> 32);
            init[8] = static_cast<u32>(key[2]);
            init[9] = static_cast<u32>(key[2] >> 32);
            init[10] = static_cast<u32>(key[3]);
            init[11] = static_cast<u32>(key[3] >> 32);

            // init[12-15] intentionally 0

            bh.update(init);
        }

        ~SecureHash() {
            wipe();
        }

        // Inputting data
        //      update(uint8_t*,size_t) ... raw bytes
        //      update(std::string)
        //      update(std::string_view)
        //      update(value) ... trivially copyable values
        //      update(std::array)
        //      update(std::vector)

        SecureHash& update(const uint8_t* data, size_t len) {
            if (len == 0) return *this;
            if (data == nullptr)
                throw std::invalid_argument("SecureHash::update: null data with len > 0");

            total_len += len;
            const uint8_t* p = data;

            // If there are any bytes in the buffer, handle them first.
            if (pos) {
                uint8_t* pb = reinterpret_cast<uint8_t*>(buffer.data());
                size_t take = std::min(len, 64 - pos);
                std::memcpy(pb + pos, p, take);
                pos += take; p += take; len -= take;
                if (pos == 64) { bh.update(buffer); pos = 0; }
            }

            // handle 64 byte chunks
            while (len >= 64) {
                std::memcpy(buffer.data(), p, 64);
                bh.update(buffer);
                p += 64; len -= 64;
            }

            // handle tail
            if (len) {
                uint8_t* pb = reinterpret_cast<uint8_t*>(buffer.data());
                std::memcpy(pb, p, len);
                pos = len;
            }

            return *this;
        }

        // ───── Convenience overloads ─────────────────────────────────────
        // string, string_view
        SecureHash& update(const std::string& s) noexcept {
            return update(reinterpret_cast<const uint8_t*>(s.data()), s.size());
        }

        SecureHash& update(const std::string_view sv) noexcept {
            return update(reinterpret_cast<const uint8_t*>(sv.data()), sv.size());
        }

        // integer types, float, double
        template <class T>
            requires std::is_trivially_copyable_v<T>
        SecureHash& update(const T value) noexcept {
            return update(reinterpret_cast<const uint8_t*>(&value), sizeof(T));
        }

        // arrays of integer types, float, double. Assumes contiguous memory usage.
        template <class T, size_t size>
            requires std::is_trivially_copyable_v<T>
        SecureHash& update(const std::array<T, size> arr) noexcept {
            return update(reinterpret_cast<const uint8_t*>(arr.data()), sizeof(T) * arr.size());
        }

        // vectors of integer types, float, double. Assumes contiguous memory usage.
        template <class T>
            requires std::is_trivially_copyable_v<T>
        SecureHash& update(const std::vector<T> arr) noexcept {
            return update(reinterpret_cast<const uint8_t*>(arr.data()), sizeof(T) * arr.size());
        }

        //
        // Finalizing / return fixed length hashes.
        //

        BLOCK64 finalize() noexcept
        {
            // Append the standard Merkle–Damgård padding: 0x80 followed by zeros
            add_byte(0x80);

            // Zero-pad until exactly 8 bytes remain — this ensures the 64-bit length
            // is always encoded at the same position (bytes 56–63 of a block).
            // This injection prevents classical length-extension attacks.
            // 
            // Note: add_byte will process the buffer if buffer gets full, so this
            // handles the case where not enough space is available to insert the length.
            while (pos != 56)
                add_byte(0x00);

            // Encode total message length in little-endian at the fixed position.
            for (int i = 0; i < 8; ++i)
                add_byte(static_cast<uint8_t>(total_len >> (i * 8)));

            // The final compression (triggered automatically by the last add_byte calls)
            // also injects the length again plus a final-block flag inside BlockHash::finalize().
            // This second injection eliminates fixed-point attacks and strengthens
            // multi-block collision resistance — exactly the conservative double-injection
            // strategy used in BLAKE2b.

            return bh.finalize(total_len);
        }

        // Convenience functions
        // hash512, hash256, hash128, hash64

        // Full 512-bit (64-byte) output. 
        std::array<uint64_t, 8> hash512() const noexcept {
            SecureHash other(*this);
            BLOCK64 h = other.finalize();
            std::array<uint64_t, 8> out;
            memcpy(out.data(), h.data(), sizeof(out));
            return out;
        }

        // 256-bit output — recommended for cryptographic use.
        std::array<uint64_t, 4> hash256() const noexcept {
            SecureHash other(*this);
            BLOCK64 h = other.finalize();
            std::array<uint64_t, 4> out;
            memcpy(out.data(), h.data(), sizeof(out));
            return out;
        }

        // 128-bit output — for legacy apps only. Avoid for new cryptographic use.
        std::array<uint64_t, 2> hash128() const noexcept {
            SecureHash other(*this);
            BLOCK64 h = other.finalize();
            std::array<uint64_t, 2> out;
            memcpy(out.data(), h.data(), sizeof(out));
            return out;
        }

        // Convenience for hash tables, etc. Not for cryptographic use.
        uint64_t hash64() const noexcept {
            SecureHash other(*this);
            BLOCK64 h = other.finalize();
            return static_cast<uint64_t>(h[0]) | (static_cast<uint64_t>(h[1]) << 32);
        }

    private:
        /* add_byte
        *  Inserts the byte 'x' onto the buffer, increments the buffer position,
        *  and optionally processes the buffer if it is full. */
        void add_byte(const uint8_t x) {
            p_buffer[pos++] = x;
            if (pos == 64) {
                bh.update(buffer);
                pos = 0;
            }
        }
        /* wipe
        *  Clears the memory of all information.
        */
        void wipe() {
            bh.wipe();
            Utilities::secure_zero(buffer.data(), 64);
            p_buffer = nullptr;
            total_len = 0;
            pos = 0;
        }
    }; //cs::Hash::Secure

}// namespace ChaCha



inline std::string generate_password(
    const std::string& username,
    const std::string& master_password,
    const std::string& site_name,
    int password_length,
    int password_version = 1,

    // === Character Sets ===
    // ───── High-readability, no look-alikes (recommended defaults) ─────
    std::string_view uppercase_chars = "ABCDEFGHJKLMNPQRSTUVWXYZ",     // no I,O
    std::string_view lowercase_chars = "abcdefghijkmnpqrstuvwxyz",  // no l,o
    std::string_view digit_chars = "23456789",                    // no 0,1
    std::string_view symbol_chars = "@#$%&*()[]{};:,.?",           // widely accepted

    // === Policy Flags ===
    bool require_uppercase = true,
    bool require_lowercase = true,
    bool require_digits = true,
    bool require_symbols = true
) 
{
    // forward declaration of helper function
    //inline std::array<uint64_t, 8> derive_rng_seed_material(
    //    const std::string & username,
    //    const std::string & master_password);

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


    // === Step 1: Derive Key & Nonce for the step 2 hasher (Iterative KDF) ===
    ChaCha::SecureHash hasher({}); // unkeyed is fine here
    hasher.update("derive_key_material.salt.v001");  // versioned domain salt
    hasher.update(username);
    hasher.update(master_password);
    std::array<uint64_t, 4> key_material = hasher.hash256();

    // === Step 2: Second Hash ( we use 2 for domain separation + avalanche) ===
    // This hasher will be used to fill a key and nonce for the random number generator.
    ChaCha::SecureHash hasher2(key_material);
    hasher2.update("random-number-generator-key-derivation-salt-v1");
    hasher2.update(username);
    hasher2.update(master_password);
    hasher2.update(site_name);
    hasher2.update(password_length);
    hasher2.update(password_version);

    std::array<uint64_t, 8> rng_material
        = hasher2.hash512();

    // Iteratively rehash the hash result to burn some time. We don't want a fast hash.
    int nits = 1'000'000;  // ~150–500 ms depending on hardware (2020–2035 era)
    // This is deliberately fixed — never calibrate. 
    // Reproducibility across machines and decades is the entire point of a deterministic generator.
    // 1 000 000 iterations gives >10⁶× slowdown vs raw SHA-512 → GPU cracking cost becomes astronomical
    // while still feeling instantaneous to a human.
    for (int it = 0; it < nits; ++it) {
        hasher2.update(rng_material);
        rng_material = hasher2.hash512();
    }

    // === Step 3: Extract RNG Seed Material from Final Hash ===
    // Now we need a key and nonce to use in the random number generator.
    // We will fill them with the bytes in final_hash.
    constexpr size_t KEY_SIZE = sizeof(ChaCha::KEY); // 32 bytes, 256 bits
    constexpr size_t NONCE_SIZE = sizeof(ChaCha::NONCE); // 12 bytes, 96 bits
    ChaCha::KEY rng_key{};
    ChaCha::NONCE rng_nonce{};
    // This shouldn't fail. Expected sizes: KEY_SIZE=32, NONCE_SIZE=12, sizeof(final_hash)=64 
    if (KEY_SIZE + NONCE_SIZE > rng_material.size() * sizeof(uint64_t))
        throw std::runtime_error("Final hash too small for RNG seed");
    const uint8_t* bytes = reinterpret_cast<const uint8_t*>(rng_material.data());
    std::memcpy(rng_key.data(), bytes, KEY_SIZE);
    std::memcpy(rng_nonce.data(), bytes + KEY_SIZE, NONCE_SIZE);

    // === Step 4: Initialize Deterministic RNG ===
    ChaCha::RNG rng(rng_key, rng_nonce); // RNG is a ChaCha20 keystream-based rng.

    // === Step 5: Define Character Pools ===
    const std::string uppercase(uppercase_chars);
    const std::string lowercase(lowercase_chars);
    const std::string digits(digit_chars);
    const std::string symbols(symbol_chars);
    std::string all_chars;
    if (require_uppercase) all_chars += uppercase;
    if (require_lowercase) all_chars += lowercase;
    if (require_digits)    all_chars += digits;
    if (require_symbols)   all_chars += symbols;

    // === Step 6: Build Password with Guaranteed Diversity ===
    std::string password;
    password.reserve(password_length);  // Avoid reallocations

    // lambda to draw a character from a character set.
    auto draw = [](std::string_view characters, ChaCha::RNG& rng) -> char {
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

    // === Step 7: Fisher-Yates Shuffle for Uniformity ===
    // Shuffling ensures no bias from forced prefix positions
    for (size_t i = password_length - 1; i > 0; --i) {
        const size_t j = rng.unbiased(0, i);
        std::swap(password[i], password[j]);
    }

    // === Step 8: Securely Erase Sensitive Data from Stack ===
    // Overwrite all derived secrets to reduce memory exposure window
    Utilities::secure_zero(key_material.data(), sizeof(key_material));
    Utilities::secure_zero(rng_material.data(), sizeof(rng_material));
    Utilities::secure_zero(rng_key.data(), sizeof(rng_key));
    Utilities::secure_zero(rng_nonce.data(), sizeof(rng_nonce));

    return password;
}



void generate_password_interactive()
{
    std::string username, master_password, site_name;
    int length = 16, version = 1;

    std::cout << "=== Offline Deterministic Password Generator ===\n"
        "(no cloud, no storage, no telemetry)\n";

    // === Username ===
    while (true) {
        std::cout << "Username (e.g. email): ";
        std::cout.flush();
        if (std::getline(std::cin, username) && !username.empty())
            break;
        std::cout << "Error: Username cannot be empty.\n\n";
    }


    // === Master Password (masked + strength feedback) ===
    std::cout << "\n";
    std::cout << "Why your master password matters:\n";
    std::cout << "---------------------------------\n";
    std::cout << " - Clean 73-character set: ~6.19 bits per character\n";
    std::cout << " - A 16-character generated password approx 99 bits of entropy\n";
    std::cout << " - Your master password is the ONLY thing protecting all sites\n";
    std::cout << "\n";

    std::cout << "Mask master password? (y/n) : ";
    char ch = 0;
    // Use a standard C++ loop to safely read a single character
    while (true) {
        // Read the character
        if (std::cin >> ch) {
            ch = std::tolower(static_cast<unsigned char>(ch));

            if (ch == 'y' || ch == 'n') {
                break; // Exit the loop if input is valid
            }
        }

        // Clear error flags and discard remaining input (like the Enter key)
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        std::cout << "Invalid input. Please enter 'y' or 'n': ";
    }
    bool mask;
    if (ch == 'y')
        mask = true;
    else
        mask = false;

    while (true) { // Master password loop
        if (mask)
            master_password = Utilities::get_masked_input("Master Password: ");
        else
            master_password = Utilities::get_unmasked_input("Master Password: ");

        if (master_password.empty()) {
            std::cerr << "Error: Master password cannot be empty.\n\n";
            continue;
        }

        std::cout << "Current length: " << master_password.size() << " character"
            << (master_password.size() == 1 ? "" : "s") << "\n";

        if (master_password.size() >= 18) {
            std::cout << "Excellent -- extremely strong!\n";
            break;
        }
        else if (master_password.size() >= 14) {
            std::cout << "Good strength.\n";
            std::cout << "Press Enter to accept, or type anything and Enter to retry: ";
        }
        else {
            std::cout << "Warning: Weak for a master password.\n";
            std::cout << "Recommended: 16–30+ characters or a full unique sentence.\n";
            std::cout << "Press Enter to accept anyway, or type anything to retry: ";
        }

        std::cout.flush();

        std::string response;
        if (!std::getline(std::cin, response) || response.empty()) {
            // User just pressed Enter → accept current password
            break;
        }

        // Any non-empty input → loop again
        std::cout << "Okay, let's try again...\n\n";
    }
    // Clear the input buffer just in case
    // Probably not strictly necessary if the "master password loop" structure is tight.
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');


    // === Site Name ===
    while (true) {
        std::cout << "Site/Service Name (example.com) : ";
        std::cout.flush();
        if (std::getline(std::cin, site_name) && !site_name.empty())
            break;
        std::cout << "Error: Site name cannot be empty.\n\n";
    }

    // === Length ===
    while (true) {
        std::cout << "Password Length (8-128) [" << length << "]: ";
        std::cout.flush();
        std::string input;
        if (!std::getline(std::cin, input) || input.empty()) break;
        try {
            int v = std::stoi(input);
            if (v >= 8 && v <= 128) { length = v; break; }
        }
        catch (...) {}
        std::cout << "Please enter a number between 8 and 128.\n";
    }

    // === Version / Counter ===
    while (true) {
        std::cout << "Version/Counter [1]: ";
        std::cout.flush();
        std::string input;
        if (!std::getline(std::cin, input) || input.empty()) break;
        try {
            int v = std::stoi(input);
            if (v >= 1) { version = v; break; }
        }
        catch (...) {}
        std::cout << "Please enter a positive integer.\n";
    }

    std::cout << "\nGenerating password...\n\n";

    try {
        std::string password = generate_password(
            username, master_password, site_name, length, version);

        std::cout << "Your password is:\n\n";
        std::cout << "    " << password << "\n\n";
        std::cout << "Copy it now - it will be cleared from screen in a moment.\n";
        std::cout << "\nPress Enter to clear screen and exit...";
        std::cout.flush();

        std::cin.get();  // wait

        // Final wipe
        Utilities::cls();

    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << '\n';
        std::cin.get();
    }

    // Zero sensitive memory before exit
    Utilities::secure_zero(master_password.data(), master_password.size());
}



void test_generate_password() {
    /*
    Expected Output:
        password   = *U]A8DX*]u@c:ZzK
        password_u = [F;i4rLh;pSyua3t
        password_m = 5t:e]MsiVtmaeT6N
        password_s = M#q:3TK9)bdi,AFG
        password_l = yuVK$MCDX4,cp*z
        password_v = R.g&E%DJVN:FD6X4
    */
    std::string username = "JohnDoe@gmail.com";
    std::string master_password = "This is probably my strongest password ever!";
    std::string site_name = "example.com";
    int length = 16;
    int version = 1;
    std::string password = generate_password(username, master_password, site_name, length, version);
    std::string password_u = generate_password(username + "a", master_password, site_name, length, version);
    std::string password_m = generate_password(username, master_password + "a", site_name, length, version);
    std::string password_s = generate_password(username, master_password, site_name + "a", length, version);
    std::string password_l = generate_password(username, master_password, site_name, length - 1, version);
    std::string password_v = generate_password(username, master_password, site_name, length, version + 1);
    std::cout << "password   = " << password << "\n";
    std::cout << "password_u = " << password_u << "\n";
    std::cout << "password_m = " << password_m << "\n";
    std::cout << "password_s = " << password_s << "\n";
    std::cout << "password_l = " << password_l << "\n";
    std::cout << "password_v = " << password_v << "\n";
}



struct PasswordInputData {
    bool use_interactive_mode = false;

    // Owned strings (we need to store them)
    std::string username;
    std::string master_password;
    std::string site_name;

    int password_length = 16;
    int password_version = 1;

    // Character sets as string_view (pointing into string literals or custom input)
    // Note: no look-alikes by default
    std::string_view uppercase_chars = "ABCDEFGHJKLMNPQRSTUVWXYZ"; // no I, O
    std::string_view lowercase_chars = "abcdefghijkmnpqrstuvwxyz"; // no l, 0
    std::string_view digit_chars = "23456789"; // no 1, 0
    std::string_view symbol_chars = "@#$%&*()[]{};:,.?";

    // Requirements
    bool require_uppercase = true;
    bool require_lowercase = true;
    bool require_digits = true;
    bool require_symbols = true;
};

// Helper to create default instance
PasswordInputData make_default_input_data() {
    return PasswordInputData{};
}

void load_config_file(const std::string& path, PasswordInputData& data) {
    std::ifstream file(path);
    if (!file.is_open()) return; // silently skip if missing

    std::cout << "Loaded config: " << path << "\n";

    std::string line;
    int line_num = 0;
    while (std::getline(file, line)) {
        ++line_num;

        // Skip comments and empty lines
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;

        // Trim whitespace
        line.erase(0, line.find_first_not_of(" \t"));
        line.erase(line.find_last_not_of(" \t") + 1);

        auto eq_pos = line.find('=');
        if (eq_pos == std::string::npos) continue; // invalid line

        std::string key = line.substr(0, eq_pos);
        std::string value = line.substr(eq_pos + 1);

        // Trim key and value
        key.erase(0, key.find_first_not_of(" \t"));
        key.erase(key.find_last_not_of(" \t") + 1);
        value.erase(0, value.find_first_not_of(" \t\"'"));  // allow quotes
        value.erase(value.find_last_not_of(" \t\"'") + 1);

        // Now apply the setting
        if (key == "uppercase")          data.uppercase_chars = value;
        else if (key == "lowercase")     data.lowercase_chars = value;
        else if (key == "digits")        data.digit_chars = value;
        else if (key == "symbols")       data.symbol_chars = value;
        else if (key == "length")        data.password_length = std::stoi(value);
        else if (key == "version")       data.password_version = std::stoi(value);
        else if (key == "require_uppercase")  data.require_uppercase = (value == "true" || value == "1");
        else if (key == "require_lowercase")  data.require_lowercase = (value == "true" || value == "1");
        else if (key == "require_digits")     data.require_digits = (value == "true" || value == "1");
        else if (key == "require_symbols")    data.require_symbols = (value == "true" || value == "1");
        else {
            std::cerr << "Warning: Unknown key in " << path
                << ":" << line_num << " -> " << key << "\n";
        }
    }
}

PasswordInputData parse_args(int argc, char const* argv[]) {
    PasswordInputData data = make_default_input_data();

    /*
    # Option 1: Double quotes (most common)
    StonePass --username "John Doe" --master-password "Tree dog horse mountain" --site-name github.com

    # Option 2: Single quotes (also fine)
    StonePass --username 'John Doe' --master-password 'Tree dog horse mountain' --site-name github.com

    */

    if (argc == 1) {
        data.use_interactive_mode = true;
        return data;
    }

    // Auto-load config (before CLI args, so CLI overrides win)
    std::vector<std::string> auto_paths = {
        "/etc/stonepass.conf",
        "/usr/local/etc/stonepass.conf",
        getenv("HOME") ? std::string(getenv("HOME")) + "/.stonepassrc" : "",
        "./stonepass.conf"
    };

    for (const auto& path : auto_paths) {
        if (!path.empty()) {
            load_config_file(path, data);
        }
    }

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--username" || arg == "-u") {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << arg << " requires an argument\n";
                std::exit(1);
            }
            data.username = argv[++i];
        }
        else if (arg == "--master-password" || arg == "-p") {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << arg << " requires an argument\n";
                std::exit(1);
            }
            data.master_password = argv[++i];
        }
        else if (arg == "--file" || arg == "-f") {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << arg << " requires a config file path\n";
                std::exit(1);
            }
            const std::string config_path = argv[++i];

            std::ifstream file(config_path);
            if (!file.is_open()) {
                std::cerr << "Error: Cannot open config file: " << config_path << "\n";
                std::exit(1);
            }

            std::string line;
            int line_num = 0;
            while (std::getline(file, line)) {
                ++line_num;

                // Skip comments and empty lines
                if (line.empty() || line[0] == '#' || line[0] == ';') continue;

                // Trim whitespace
                line.erase(0, line.find_first_not_of(" \t"));
                line.erase(line.find_last_not_of(" \t") + 1);

                auto eq_pos = line.find('=');
                if (eq_pos == std::string::npos) continue; // invalid line

                std::string key = line.substr(0, eq_pos);
                std::string value = line.substr(eq_pos + 1);

                // Trim key and value
                key.erase(0, key.find_first_not_of(" \t"));
                key.erase(key.find_last_not_of(" \t") + 1);
                value.erase(0, value.find_first_not_of(" \t\"'"));  // allow quotes
                value.erase(value.find_last_not_of(" \t\"'") + 1);

                // Now apply the setting
                if (key == "uppercase")          data.uppercase_chars = value;
                else if (key == "lowercase")     data.lowercase_chars = value;
                else if (key == "digits")        data.digit_chars = value;
                else if (key == "symbols")       data.symbol_chars = value;
                else if (key == "length")        data.password_length = std::stoi(value);
                else if (key == "version")       data.password_version = std::stoi(value);
                else if (key == "require_uppercase")  data.require_uppercase = (value == "true" || value == "1");
                else if (key == "require_lowercase")  data.require_lowercase = (value == "true" || value == "1");
                else if (key == "require_digits")     data.require_digits = (value == "true" || value == "1");
                else if (key == "require_symbols")    data.require_symbols = (value == "true" || value == "1");
                else {
                    std::cerr << "Warning: Unknown key in " << config_path
                        << ":" << line_num << " -> " << key << "\n";
                }
            }
        }
        else if (arg == "--site-name" || arg == "-s") {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << arg << " requires an argument\n";
                std::exit(1);
            }
            data.site_name = argv[++i];
        }
        else if (arg == "--length" || arg == "-l") {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << arg << " requires an argument\n";
                std::exit(1);
            }
            data.password_length = std::stoi(argv[++i]);
        }
        else if (arg == "--version" || arg == "-v") {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << arg << " requires an argument\n";
                std::exit(1);
            }
            data.password_version = std::stoi(argv[++i]);
        }
        else if (arg == "--no-uppercase"|| arg == "--nu") {
            data.require_uppercase = false;
        }
        else if (arg == "--no-lowercase"|| arg == "--nl") {
            data.require_lowercase = false;
        }
        else if (arg == "--no-digits"|| arg == "--nd") {
            data.require_digits = false;
        }
        else if (arg == "--no-symbols"|| arg == "--ns") {
            data.require_symbols = false;
        }
        else if (arg == "--uppercase" || arg == "--uc") {
            if (i + 1 >= argc) { 
                std::cerr << "Error: " << arg << " requires an argument: list of acceptable uppercase characters.\n";
                std::exit(1);
            }
            data.uppercase_chars = argv[++i];
        }
        else if (arg == "--lowercase" || arg == "--lc") {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << arg << " requires an argument: list of acceptable lowercase characters.\n";
                std::exit(1);
            }
            data.lowercase_chars = argv[++i];
        }
        else if (arg == "--digits" || arg == "--d") {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << arg << " requires an argument: list of acceptable digits.\n";
                std::exit(1);
            }
            data.digit_chars = argv[++i];
        }
        else if (arg == "--symbols" || arg == "--sym") {
            if (i + 1 >= argc) {
                std::cerr << "Error: " << arg << " requires an argument: list of acceptable symbols.\n";
                std::exit(1);
            }
            data.symbol_chars = argv[++i];
        }
        else if (arg == "--help" || arg == "-h") {
            std::cout << R"(Usage: pwgen [options]
                Options:
                  --username <name>          Your username/email
                  --master-password <pw>     Master password (use carefully!)
                  --site-name <site>         Website/domain name
                  --length <n>               Password length (default: 16)
                  --version <n>              Password version (default: 1)
                  --no-uppercase             Don't require uppercase letters
                  --no-lowercase             Don't require lowercase letters
                  --no-digits                Don't require digits
                  --no-symbols               Don't require symbols
                  --uppercase <chars>        Custom uppercase letters (e.g. "ABCDEFGHJKLMNPQRSTUVWXYZ")
                  --lowercase <chars>        Custom lowercase letters
                  --digits <chars>           Custom digits (e.g. "0123456789" to allow 0 and 1)
                  --symbols <chars>          Custom symbols (e.g. "+-_=" or "")
                  --help                     Show this help

                If no arguments are given, interactive mode starts.
                )";
            std::exit(0);
        }
        else {
            std::cerr << "Unknown or incomplete argument: " << arg << "\n";
            std::cerr << "Use --help for usage information.\n";
            std::exit(1);
        }
    }

    // Basic validation
    if (!data.use_interactive_mode) {
        if (data.username.empty()) {
            std::cerr << "Error: --username is required in non-interactive mode\n";
            std::exit(1);
        }
        if (data.master_password.empty()) {
            std::cerr << "Error: --master-password is required in non-interactive mode\n";
            std::exit(1);
        }
        if (data.site_name.empty()) {
            std::cerr << "Error: --site-name is required in non-interactive mode\n";
            std::exit(1);
        }
    }

    return data;
}



int main(int argc, char const* argv[]) {
    PasswordInputData CL = parse_args(argc, argv);
    if(CL.use_interactive_mode)
        generate_password_interactive();
    else {
        try {
            std::string password = generate_password(
                CL.username,
                CL.master_password,
                CL.site_name,
                CL.password_length,
                CL.password_version,

                // === Character Sets ===
                CL.uppercase_chars,
                CL.lowercase_chars,
                CL.digit_chars,
                CL.symbol_chars,

                // === Policy Flags ===
                CL.require_uppercase,
                CL.require_lowercase,
                CL.require_digits,
                CL.require_symbols
            );

            std::cout << "Your password is:\n\n";
            std::cout << "    " << password << "\n\n";
            std::cout << "Copy it now - it will be cleared from screen in a moment.\n";
            std::cout << "\nPress Enter to clear screen and exit...";
            std::cout.flush();

            std::cin.get();  // wait

            // Final wipe
            Utilities::cls();
        }
        catch (const std::exception& e) {
            std::cerr << "Error: " << e.what() << '\n';
            std::cin.get();
        }
        // Securely wipe master password from memory
        Utilities::secure_zero(
            const_cast<void*>(static_cast<const void*>(CL.master_password.data())),
            CL.master_password.size()
        );
    }
    return 0;
}
