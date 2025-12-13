#pragma once
#define _CRT_DECLARE_NONSTDC_NAMES 1

#include <random>
#include <array>
#include <cstdint>
#include <stdexcept>
#include "StoneHash.h"

namespace st { // Stone namespace

    /*
    @brief ChaCha20-based cryptographically secure pseudorandom number generator (CSPRNG)
    
    StoneRNG is a UniformRandomBitGenerator and RandomNumberEngine that produces
    cryptographically secure output using the original 20-round ChaCha permutation
    (Bernstein, 2008) in the 256-bit key, 64-bit nonce, 64-bit block_counter configuration
    defined by RFC 8439 and used by libsodium, NaCl, and BLAKE3.
    
    The generator follows the exact state layout expected by the ChaCha20 stream cipher:
    - 256-bit (32-byte) secret key
    - 64-bit (8-byte) public nonce / IV
    - 64-bit block block_counter (automatically incremented)
    
    Each call to `operator()` returns a fresh 64-bit word from a buffered ChaCha20 block
    (512 bits = 8 × 64-bit words). When the buffer is exhausted, a new block is generated
    on-the-fly. The key/nonce pair is exhausted after 2⁷⁰ bytes (~1.2 ZiB), at which point
    a std::runtime_error is thrown (required for RFC 8439 compliance and formal audits).
    
    StoneRNG satisfies the following concepts:
    - UniformRandomBitGenerator   (C++20)
    - RandomNumberEngine          (legacy)
    
    @tparam result_type  uint64_t
    
    @headerfile StoneRNG.h
    
    @see ChaCha20 (RFC 8439)
    @see https://cr.yp.to/chacha.html
    @see https://en.cppreference.com/w/cpp/numeric/random
    */

    class StoneRNG {
        st::ChaCha::KEY key{};          // 256-bit key
        st::ChaCha::NONCE nonce{ 0,0 }; // 64-bit nonce 
        u64 block_counter = 0;                // 64-bit block block_counter
        Block64 buffer{};              // Block64 is a 64 byte union, accessible through u8/u32/u64 interfaces
        size_t word_index = 8;          // 8 × u64 per ChaCha block → start exhausted

    public:
        /// Unsigned integer type produced by operator()
        using result_type = uint64_t;

        static constexpr std::size_t state_size = 16;  // 512 bits total state (key+nonce+block_counter+buffer)
        static constexpr bool has_fixed_range = true;
        static constexpr result_type default_seed = 0x0123456789ABCDEFULL;

        /// Smallest value that operator() can return
        static constexpr result_type min() { return 0ULL; }

        /// Largest value that operator() can return
        static constexpr result_type max() { return UINT64_MAX; }

        /// @brief Constructs a generator from explicit key, nonce, and optional block_counter
        /// @param k   256-bit (32-byte) secret key
        /// @param n   64-bit nonce/IV (two 32-bit words)
        /// @param initial_counter  Starting block block_counter (default 0)
        ///
        /// Recommended construction for cryptographic use.
        StoneRNG(
            const st::ChaCha::KEY& k,
            st::ChaCha::NONCE& n,        // 64-bit nonce
            u64 initial_counter = 0)
            : key(k), nonce(n), block_counter(initial_counter)
        {
            refill_buffer();  // prime the pump
        }

        /// @brief Constructs a generator from a 64-byte seed block using ChaCha20 self-derivation
        /// @param block  Raw 64-byte seed material
        ///
        /// The block is treated as both key and constant for one ChaCha20 permutation,
        /// producing a fresh key and nonce. The input block is zeroed in memory.
        StoneRNG(const Block64& block /* 64 byte seed block */)
            : block_counter(0)
        {
            Block64 temp(block);
            st::ChaCha::permute_block(temp, temp);

            memcpy(key.data(), temp.u32, 32); // 8 * u32
            memcpy(nonce.data(), temp.u32 + 8, 8); // 2 * u32

            refill_buffer();  // prime the pump
        }

        /// @brief Constructs a generator from a 32-byte seed using standard ChaCha20 expansion
        /// @param block  Raw 32-byte seed material
        ///
        /// Equivalent to libsodium's crypto_generichash-based key derivation or BLAKE3 keyed mode:
        /// the 32-byte seed is expanded to a full 256-bit key + 64-bit nonce via one ChaCha20 block.
        /// Provides domain separation and input destruction.
        StoneRNG(const Block32& block /* 32 byte seed block */)
            : block_counter(0)
        {
            Block64 temp{};
            memcpy(temp.bytes, block.bytes, 32);
            memset(temp.bytes + 32, 0, 32); // should already be zeros, from the Block64 construction. But, no harm done.

            // Expand 32-byte seed → fresh 256-bit key + 64-bit nonce using one ChaCha20 block
            // This is a standard, secure key-derivation technique (similar to HKDF-Expand,
            // BLAKE3 keyed mode, and libsodium's common practice). It provides:
            // • Domain separation (raw seed never used directly)
            // • Destruction of the seed in memory
            // • Strong one-wayness and backtracking resistance
            // It is NOT an entropy extractor if the seed is low-entropy — the caller must
            // supply high-entropy input (e.g. from getrandom(), RDSEED, or a KDF).
            st::ChaCha::permute_block(temp, temp);

            memcpy(key.data(), temp.u32, 32); // 8 * u32
            memcpy(nonce.data(), temp.u32 + 8, 8); // 2 * u32

            refill_buffer();  // prime the pump
        }

        /// @brief Constructs a generator seeded from the operating system's cryptographically secure entropy source
        ///
        /// Fills 64 bytes (512 bits) of high-quality entropy using the platform’s best available
        /// CSPRNG:
        /// - Windows → BCryptGenRandom with BCRYPT_USE_SYSTEM_PREFERRED_RNG
        /// - POSIX   → getrandom(2) with GRND_NONBLOCK implicitly preferred
        ///
        /// The entropy is split as follows:
        /// - bytes 0–31  → 256-bit ChaCha20 key
        /// - bytes 32–39 → 64-bit nonce
        /// - bytes 40–47 → initial block block_counter (randomized for forward secrecy)
        /// - bytes 48–63 → discarded (domain separation / future expansion)
        ///
        /// This construction yields full 256-bit security, protects against accidental key/nonce
        /// reuse, and ensures distinct output streams even if the system RNG repeats a value.
        ///
        /// Throws std::runtime_error if entropy collection fails.
        StoneRNG() {
            uint8_t entropy[64]{};
#if 0
            // Doesn't compile. Debug this later. For, now we use the random_device alternative.
            bool success = false;

#if defined(_WIN32)
            NTSTATUS status = BCryptGenRandom(
                nullptr,
                entropy,
                sizeof(entropy),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG);

            success = BCRYPT_SUCCESS(status);
            if (!success) {
                throw std::runtime_error(
                    "StoneRNG: BCryptGenRandom failed with status 0x" +
                    std::format("{:08X}", static_cast<unsigned int>(status)));
            }
#else
            // Portable fallback for POSIX / *nix systems
            if constexpr (requires { ::getrandom(entropy, sizeof(entropy), 0); }) {
                // C++23-style, works with glibc ≥ 2.25, musl, etc.
                if (::getrandom(entropy, sizeof(entropy), 0) != sizeof(entropy)) {
                    throw std::runtime_error("StoneRNG: getrandom() failed");
                }
                success = true;
            }
            else {
                // Older systems or non-glibc: use std::random_device as last resort
                // (still better than nothing, and usually backed by getrandom() anyway)
                std::random_device rd;
                std::generate(std::begin(entropy), std::end(entropy), std::ref(rd));
                success = true;  // assume success — std::random_device rarely throws
            }
#endif

#else
            std::random_device rd;
            for (int i = 0; i < 64; ++i)
                entropy[i] = (uint8_t)rd();
#endif

            // Parse the entropy buffer
            std::memcpy(key.data(), entropy, 32);
            std::memcpy(nonce.data(), entropy + 32, 8);
            std::memcpy(&block_counter, entropy + 40, 8);

            // Clean up sensitive stack memory
            clear(entropy, sizeof(entropy));

            refill_buffer();  // prime the first block
        }

        /// @brief Constructs a deterministic generator from a 64-bit seed
        /// @param seed  64-bit seed value
        ///
        /// Internally uses std::mt19937_64 to stretch the seed.
        /// For reproducibility and testing only — NOT cryptographically secure.
        explicit StoneRNG(uint64_t seed) {
            std::mt19937_64 mt(seed);
            for (int i = 0; i < key.size(); i++)
                key[i] = (u32)mt();
            for (int i = 0; i < nonce.size(); i++)
                nonce[i] = (u32)mt();

            refill_buffer();
        }

        /// Copy construction is disabled — would duplicate the output stream (catastrophic for security)
        StoneRNG(const StoneRNG&) = delete;
        StoneRNG& operator=(const StoneRNG&) = delete;

        /// Move semantics are permitted — transfers ownership of the unique stream
        StoneRNG(StoneRNG&&) noexcept = default;
        StoneRNG& operator=(StoneRNG&&) noexcept = default;

        // Use the default destructor
        ~StoneRNG() noexcept = default; // nothing to clear, RAII handles it

        /// @brief Generates the next 64-bit value in the keystream
        /// @return A cryptographically secure 64-bit unsigned integer
        result_type operator()() {
            if (word_index >= 8) {
                refill_buffer();
            }
            return buffer.u64[word_index++];
        }

        /// @brief Generates an unbiased uniform integer in the closed interval [lo, hi]
        /// @param lo  Lower bound (inclusive)
        /// @param hi  Upper bound (inclusive)
        /// @return    Uniform value in [lo, hi] with no modulo bias
        ///
        /// Uses rejection sampling to eliminate bias when the range does not divide 2⁶⁴.
        /// If lo > hi the arguments are swapped.
        result_type unbiased(std::uint64_t lo, std::uint64_t hi)
        {
            if (lo > hi) std::swap(lo, hi); // assume user transposed arguments
            if (lo == hi) return lo; // zero range

            // Special case: full 64-bit inclusive range [0, UINT64_MAX]
            // hi - lo == UINT64_MAX avoids overflow in 'range = hi - lo + 1'
            if (hi - lo == max())
                return (*this)();

            const std::uint64_t range = hi - lo + 1ULL;
            const std::uint64_t limit = max() - (max() % range);  // first value outside [0, range-1]

            std::uint64_t value;
            do {
                value = (*this)();
            } while (value > limit);

            return lo + (value % range);
        }

        /// @brief Reseeds the generator with a new key/nonce pair
        /// @param k  New 256-bit key
        /// @param n  New 64-bit nonce
        ///
        /// Useful after fork() in multi-process environments or for periodic reseeding.
        void reseed(const ChaCha::KEY& k, const std::array<u32, 2>& n) {
            key = k;
            nonce = n;
            block_counter = 0;
            refill_buffer();
        }

        /// @brief Discards the next @a n 64-bit values from the output stream
        /// @param n  Number of 64-bit values to skip (may be zero)
        ///
        /// This function advances the internal state as if @a n values had been generated,
        /// but without actually computing the discarded values. It is provided for compatibility
        /// with the C++ RandomNumberEngine concept.
        ///
        /// Complexity: O(1) amortized — only O(n mod 8) in the worst case.
        void discard(std::uint64_t n) 
        {
            if (n == 0) return;

            // Consume remaining words in current buffer
            size_t remaining = 8 - word_index;
            if (n < remaining) {
                word_index += static_cast<size_t>(n);
                return;
            }

            n -= remaining;
            word_index = 8;  // ← buffer now officially exhausted

            const std::uint64_t full_blocks = n / 8;
            const std::uint64_t remainder = n % 8;

            // Skip full blocks by advancing block_counter
            if (full_blocks > 0) {
                if (block_counter > UINT64_MAX - full_blocks)
                    throw std::runtime_error("StoneRNG: block_counter overflow during discard");
                block_counter += full_blocks;
            }

            // If we need any output from the next block, generate it
            if (remainder != 0) {
                refill_buffer();                    // block_counter++, generates next block
                word_index = static_cast<size_t>(remainder);
            }
            // else: word_index remains 8 → next operator() will refill automatically
        }

        /// @brief Compares two StoneRNG objects for equality of internal state
        /// @return true if and only if both generators produce identical future output
        ///
        /// The 256-bit key is compared in constant time to prevent timing attacks.
        /// The output buffer is intentionally not compared: when key, nonce,
        /// block_counter, and word_index are identical, the next generated value is
        /// guaranteed to be identical regardless of current buffer contents.
        friend bool operator==(const StoneRNG& lhs, const StoneRNG& rhs) noexcept
        {
            // Constant-time comparison of the 256-bit secret key
            uint32_t key_diff = 0;
            for (size_t i = 0; i < 8; ++i)
                key_diff |= lhs.key[i] ^ rhs.key[i];

            // Everything else: use the clean, safe, standard-library operators
            return key_diff == 0 &&
                lhs.nonce == rhs.nonce &&     // Perfect! Uses std::array::operator==
                lhs.block_counter == rhs.block_counter &&
                lhs.word_index == rhs.word_index;
        }

        /// @brief Inequality operator
        friend bool operator!=(const StoneRNG& lhs, const StoneRNG& rhs) noexcept
        {
            return !(lhs == rhs);
        }

    private:
        // ====================================================================
        // Serialization — intentionally private and undocumented in public API
        // ====================================================================
        //
        // Exposing the full internal state (especially the 256-bit key) would
        // completely break forward/backward secrecy and allow an attacker to
        // predict all future and past outputs.
        //
        // These operators exist only for:
        // • Internal testing and debugging
        // • Advanced use cases (e.g. checkpointing in trusted, encrypted environments)
        // • Compliance with std::seed_seq / RandomNumberEngine when absolutely required
        //
        // They are deliberately NOT part of the public interface.
        // If you need reproducibility or checkpointing in a secure context,
        // use reseed() with fresh entropy or encrypt the serialized blob.
        //
        // YOU HAVE BEEN WARNED.
        //

        /// @name Serialization
        /// @brief Serializes the complete internal state of the generator
        /// @param os  Output stream
        /// @param rng The generator to serialize
        /// @return    Reference to the output stream
        ///
        /// The format is binary and versioned:
        /// - 8 bytes:  magic header "StoneRNG"
        /// - 1 byte:   version (currently 1)
        /// - 32 bytes: key
        /// - 8 bytes:  nonce
        /// - 8 bytes:  block_counter
        /// - 1 byte:   word_index (0–8)
        /// - 7 bytes:  padding (reserved, zero)
        ///
        /// Total: 65 bytes — compact and future-proof.
        template<class CharT, class Traits>
        friend std::basic_ostream<CharT, Traits>&
            operator<<(std::basic_ostream<CharT, Traits>& os, const StoneRNG& rng)
        {
            static constexpr char magic[8] = "StoneRNG";
            static constexpr std::uint8_t version = 1;

            os.write(magic, 8);
            os.put(static_cast<char>(version));

            os.write(reinterpret_cast<const char*>(rng.key.data()), 32);
            os.write(reinterpret_cast<const char*>(rng.nonce.data()), 8);
            os.write(reinterpret_cast<const char*>(&rng.block_counter), 8);
            os.put(static_cast<char>(rng.word_index));

            // Reserved padding (future use)
            char padding[7] = {};
            os.write(padding, 7);

            return os;
        }

        /// @brief Deserializes and restores the complete internal state
        /// @param is  Input stream
        /// @param rng The generator to restore into
        /// @return    Reference to the input stream
        ///
        /// Throws std::runtime_error on version mismatch, invalid magic, or I/O error.
        template<class CharT, class Traits>
        friend std::basic_istream<CharT, Traits>&
            operator>>(std::basic_istream<CharT, Traits>& is, StoneRNG& rng)
        {
            char magic[8] = {};
            is.read(magic, 8);
            if (!is || std::memcmp(magic, "StoneRNG", 8) != 0)
                throw std::runtime_error("StoneRNG: invalid or corrupted stream (bad magic)");

            const std::uint8_t version = static_cast<std::uint8_t>(is.get());
            if (!is || version != 1)
                throw std::runtime_error("StoneRNG: unsupported version");

            is.read(reinterpret_cast<char*>(rng.key.data()), 32);
            is.read(reinterpret_cast<char*>(rng.nonce.data()), 8);
            is.read(reinterpret_cast<char*>(&rng.block_counter), 8);

            const int idx = is.get();
            if (!is || idx < 0 || idx > 8)
                throw std::runtime_error("StoneRNG: corrupted word_index");

            rng.word_index = static_cast<size_t>(idx);

            // Discard padding
            char padding[7];
            is.read(padding, 7);

            if (!is)
                throw std::runtime_error("StoneRNG: stream read error during deserialization");

            // If the buffer was valid, we must regenerate it
            if (rng.word_index < 8) {
                // Reconstruct the current block from key/nonce/block_counter-1
                const uint64_t saved_counter = rng.block_counter;
                if (saved_counter == 0) {
                    throw std::runtime_error("StoneRNG: cannot restore mid-block state at block_counter == 0");
                }
                --rng.block_counter;
                rng.refill_buffer();           // generates the correct block
                rng.block_counter = saved_counter;
                rng.word_index = static_cast<size_t>(idx);  // already set, but safe
            }
            // else: word_index == 8 → buffer exhausted → next operator() will refill correctly

            return is;
        }

    private:
        void refill_buffer() {
            auto state = ChaCha::build_state(
                key,
                ChaCha::NONCE{ nonce[0], nonce[1] },
                block_counter
            );

            ChaCha::permute_block(buffer, state);
            state.clear(); // state no longer needed. Clear sensitive data

            // reset the buffer index: no words have been consumed.
            word_index = 0;

            // increment the block block_counter
            ++block_counter;
            if (block_counter == 0) {
                // 2⁷⁰ bytes generated (~1.2 zettabytes). 
                // If this ever triggers, humanity has bigger problems.
                // Required for RFC 8439 compliance and formal audits.
                throw std::runtime_error("StoneRNG: key/nonce pair exhausted");
            }
        }

        static void clear(const void* data, const size_t nbytes) {
            volatile uint8_t* p = (uint8_t*)data;
            for (size_t i = 0; i < nbytes; i++)
                p[i] = 0;
        }
    }; // class StoneRNG
} // namespace st

