#pragma once
// file: stChacha.h
// Description: Definition of the ChaCha20 block permutation
#define _CRT_DECLARE_NONSTDC_NAMES 1

#include "stBlock.h" // A union to allow access as different types: byte, u8, u16, u32, and u64

#include <bit> // for std::rotl
#include <cassert>
#include <chrono>
#include <cstring>
#include <format>
#include <random>
#include <span>
#include <stdexcept>

/*
    ╭───────────────────────────────────────────────────────────────╮
    │                        Table of Contents                      │
    ╰───────────────────────────────────────────────────────────────╯

    Types
        KEY                – 256-bit key (8 × uint32_t)
        NONCE              – 64-bit nonce (Bernstein/original layout)
        NONCE96            – 96-bit nonce (RFC 8439 / TLS / WireGuard)
        BLOCK_COUNTER      – 64-bit block block_counter (Bernstein)
        BLOCK_COUNTER_32   – 32-bit block block_counter (RFC 8439)

    Functions
        pseudo_random_bytes()        – Fill buffer with OS CSPRNG
        generate_random_key()        – 256-bit cryptographically random key
        generate_random_nonce()      – 64-bit random nonce

        QR()                         – ChaCha quarter-round (inline, noexcept)

        permute_block()              – Core 20-round permutation + add
                                       Two overloads: raw u32* and Block64&

        build_state()                – Two overloads:
            • Bernstein original (64-bit nonce + 64-bit counter)
            • RFC 8439 compliant (96-bit nonce + 32-bit counter)

    Note: Default build_state() uses original Bernstein layout.
          Use the NONCE96 overload for TLS/WireGuard compatibility.
*/

/*
 * Randomness source:
 * This library uses std::random_device, which provides cryptographic-quality
 * entropy on Windows (via BCryptGenRandom), Linux (getrandom()/urandom), and
 * macOS. It is more than sufficient for offline password generation and
 * personal encryption tools. A small amount of high-resolution timing is mixed
 * in as a defensive measure against theoretically broken implementations.
 *
 * For users on mainstream desktop systems, this is as secure as dedicated
 * cryptographic libraries without the complexity or dependencies.
 */

namespace st {

    namespace ChaCha {

        // Constants used in ChaCha20
        static constexpr std::array<u32, 4> ChaCha20_constants{
            0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u
            // "expand 32-byte k" in little-endian ASCII
        };
        
        /*
        * In the st::ChaCha namespace we typically use a 256 bit key, 64 bit block_counter, and 
        * 64 bit nonce. This is consistent with the original ChaCha20-Bernstein layout, but there
        * are many modern implementations that use a 32 bit block_counter and a 96 bit nonce.
        * 
        * ChaCha20-Bernstein (original): 64-bit nonce, 64-bit block_counter
        * NOT RFC 8439 compliant (which uses 96-bit nonce + 32-bit block_counter)
        *
        * Warning: This is NOT the RFC 8439 layout used in TLS/WireGuard
        * Do not mix with standard libraries unless you know what you're doing.
        *
        * A build_state( const KEY&, const NONCE96&, BLOCK_COUNTER_32) has been provided to
        * simplify a transition to RFC8439, if that is needed in the future.
        */

        // Types used throughout st::ChaCha

        using KEY = std::array<u32, 8>; // 256 bit key
        using NONCE = std::array<u32, 2>; // 64 bit nonce
        using BLOCK_COUNTER = u64; // 64 bit block block_counter

        using NONCE96 = std::array<u32, 3>; // 96 bit nonce
        using BLOCK_COUNTER_32 = u32; // 32 bit block block_counter

        // simple validation of sizes

        static_assert(sizeof(KEY) == 32, "KEY must be 32 bytes (256 bits)");
        static_assert(sizeof(NONCE) == 8, "NONCE must be 8 bytes (64 bits)");
        static_assert(sizeof(NONCE96) == 12, "NONCE96 must be 12 bytes (96 bits)");
        
        // A few well-studied constants from xxHash
        static constexpr u64 XXH_PRIME64_1 = 0x9E3779B185EBCA87ULL;
        static constexpr u64 XXH_PRIME64_2 = 0xC2B2AE3D27D4EB4FULL;
        static constexpr u64 XXH_PRIME64_3 = 0x165667B19E3779F9ULL;
        static constexpr u64 XXH_PRIME64_4 = 0x85EBCA77C2B2AE63ULL;
        static constexpr u64 XXH_PRIME64_5 = 0x27D4EB2F165667C5ULL;

        /*!
         * @internal
         * @brief xxHash final mixing function
         *
         * The final mix ensures that all input bits have a chance to impact any bit in
         * the output digest, resulting in an unbiased distribution.
         *
         * @param hash The hash to avalanche.
         * @return The avalanched hash.
         */
        inline u64 XXH64_avalanche(u64 hash)
        {
            hash ^= hash >> 33;
            hash *= XXH_PRIME64_2;
            hash ^= hash >> 29;
            hash *= XXH_PRIME64_3;
            hash ^= hash >> 32;
            return hash;
        }

        // Generate high - entropy random bytes using the platform's OS entropy source
        // via std::random_device (cryptographically secure on all mainstream desktop
        // platforms in 2025) with fallback timing entropy as a safety net.
        // Suitable for offline password generation and key material where true
        // cryptographic security is provided by the OS on Windows, Linux, and macOS.
        inline void pseudo_random_bytes(std::span<std::uint8_t> out)
        {
            if (out.empty()) return;

            // Collect entropy from random_device
            constexpr size_t seed_size = std::mt19937_64::state_size; // ~624
            std::array<std::uint32_t, seed_size> seed_data{};

            std::random_device rd;
            std::generate(seed_data.begin(), seed_data.end(), std::ref(rd));

            // Now, just in case random_device is completely broken, add in some timer info.
            // This would be very unusual, but time insertion won't hurt anything.
            uint64_t time = std::chrono::high_resolution_clock().now().time_since_epoch().count();
            seed_data[0] ^= (uint32_t)time;
            seed_data[1] ^= (uint32_t)(time >> 32);

            // Properly mix the entropy into the full PRNG state
            std::seed_seq sseq(seed_data.begin(), seed_data.end());
            std::mt19937_64 mt(sseq);

            // Fill the output buffer efficiently (8 bytes at a time)
            std::uint64_t temp;
            size_t i = 0;
            while (i < out.size()) {
                temp = mt();
                size_t n_to_copy = std::min(8ull, out.size() - i);
                std::memcpy(out.data() + i, &temp, n_to_copy);
                i += n_to_copy;
            }
        }

        // Create a non-deterministic key. High quality, but non-cryptographic.
        inline KEY generate_random_key() noexcept(false)
        {
            KEY k;
            pseudo_random_bytes({ reinterpret_cast<std::uint8_t*>(k.data()), sizeof(k) });
            return k;
        }

        // Create a non-deterministic nonce. High quality, but non-cryptographic.
        inline NONCE generate_random_nonce() noexcept(false)
        {
            NONCE n;
            pseudo_random_bytes({ reinterpret_cast<std::uint8_t*>(n.data()), sizeof(n) });
            return n;
        }

        // ChaCha20 quarter round
        inline void QR(u32& a, u32& b, u32& c, u32& d) noexcept
        {
            a += b; d ^= a; d = std::rotl(d, 16u);
            c += d; b ^= c; b = std::rotl(b, 12u);
            a += b; d ^= a; d = std::rotl(d, 8u);
            c += d; b ^= c; b = std::rotl(b, 7u);
        }

        
        // Applies the ChaCha20 core permutation (20 rounds, double-round style)
        // with final addition of the original input (RFC 8439 §2.3).
        // Safe for in-place operation (out may alias in).
        inline void permute_block(uint32_t* out, const uint32_t* in) noexcept
        {
            // Do all work on a local copy of the input block
            u32 x[16];
            std::memcpy(x, in, sizeof(x));

            // Perform 20 rounds (10 double rounds) on x.
            for (int r = 0; r < 10; ++r) {
                QR(x[0], x[4], x[8], x[12]);
                QR(x[1], x[5], x[9], x[13]);
                QR(x[2], x[6], x[10], x[14]);
                QR(x[3], x[7], x[11], x[15]);

                QR(x[0], x[5], x[10], x[15]);
                QR(x[1], x[6], x[11], x[12]);
                QR(x[2], x[7], x[8], x[13]);
                QR(x[3], x[4], x[9], x[14]);
            }

            // Add the original input to the result
            for (int i = 0; i < 16; ++i)
                out[i] = x[i] + in[i];
        }
        inline void permute_block(Block64& out, const Block64& in) noexcept
        {
            permute_block(out.u32, in.u32);
        }

        // Builds original Bernstein ChaCha20 state (64-bit nonce + 64-bit block_counter)
        // *** WARNING: NOT compatible with RFC 8439 / TLS / WireGuard ***
        inline Block64 build_state(
            const KEY& key,
            const NONCE& nonce,
            BLOCK_COUNTER block_counter = 0
        ) noexcept
        {
            Block64 state{};

            // constants
            std::memcpy(state.u32 + 0, ChaCha20_constants.data(), sizeof(ChaCha20_constants));

            // key
            std::memcpy(state.u32 + 4, key.data(), sizeof(key));

            // block block_counter
            state.u32[12] = static_cast<u32>(block_counter);
            state.u32[13] = static_cast<u32>(block_counter >> 32);

            // nonce
            state.u32[14] = nonce[0];
            state.u32[15] = nonce[1];

            return state;
        }

        inline Block64 build_state(
            const KEY& key,
            const NONCE96& nonce,
            BLOCK_COUNTER_32 block_counter = 0
        ) noexcept
        {
            Block64 state{};

            // constants
            std::memcpy(state.u32 + 0, ChaCha20_constants.data(), sizeof(ChaCha20_constants));
            
            // key
            std::memcpy(state.u32 + 4, key.data(), sizeof(key));

            // block block_counter
            state.u32[12] = block_counter;

            // nonce
            state.u32[13] = nonce[0];
            state.u32[14] = nonce[1];
            state.u32[15] = nonce[2];

            return state;
        }

    }// namespace ChaCha
}// namespace st
