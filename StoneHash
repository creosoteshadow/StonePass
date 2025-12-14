#pragma once

// file StoneHash.h
// 
// StoneHash — a simple, fast, conservative cryptographic hash function
//
// • Header-only
// • Constant-time
// • Domain-separated
// • Length-strengthened
// • No heap allocation
// • No exceptions
//
// Built entirely on the ChaCha20 core permutation (20 rounds, full diffusion,
// extensively analyzed for >15 years) using a clean, domain-separated,
// length-strengthened sponge construction with the BLAKE3 IV and fixed-point
// countermeasures.
//
// This design deliberately contains no novel primitives or unstudied constants.
// Statistical tests (PractRand 16 GiB) show no anomalies.
//
// That said: StoneHash is a personal/educational project and has not undergone
// dedicated third-party cryptanalysis. Treat it as a high-assurance experimental
// construction, not as a drop-in replacement for BLAKE3 or SHA-3.

#define _CRT_DECLARE_NONSTDC_NAMES 1

#include <array>
#include <bit>
#include <cassert>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <stdexcept>
#include <vector>

#include "stCompressor.h" // ChaCha20-based compressor.

namespace st {

    class StoneHash {
    public:
        static constexpr std::size_t BLOCK_SIZE_BYTES = 64;

        // ================================================================
        // Constructors
        // ================================================================

        // Unkeyed constructor.
        StoneHash() noexcept
        {
            init_with_key(Block32{});  // zero key = unkeyed mode
        }

        // Keyed constructor.
        StoneHash(Block32 key) noexcept
        {
            init_with_key(key);
        }

        // Password-based constructor. For much better security, use StoneKey().
        // StoneKey is a memory-hard, cpu-hard password hasher. 
        // 
        // Example:
        //      StoneHash hasher(Block32 StoneKey(password,context));
        // 
        // The primary disadvantage: StoneKey with default args takes
        // approximately 1.5 sec, whereas StoneHash(pwd,context,0) is near instantaneous.
        StoneHash(
            std::string_view password,
            std::string_view context = "",
            std::size_t      cost_iterations = 2'000'000)
        {
            StoneHash H;
            H.update(password);
            if (context.size() > 0)
                H.update(context);
            auto material = H.finalize();
            for (size_t i = 0; i < cost_iterations; i++) {
                H.update(material);
                material = H.finalize();
            }
            Block32 key((const std::byte*)material.bytes);
            init_with_key(key);
        }

        // Delete copying operations, allow moves.
        StoneHash(const StoneHash&) = delete;
        StoneHash& operator=(const StoneHash&) = delete;
        StoneHash(StoneHash&&) noexcept = default;
        StoneHash& operator=(StoneHash&&) noexcept = default;

        // ================================================================
        // Input
        // ================================================================

        StoneHash& update(std::span<const std::byte> data) noexcept
        {
            const std::byte* p = data.data();
            std::size_t      len = data.size();

            if (pos_ > 0) {
                std::size_t take = std::min<size_t>(len, BLOCK_SIZE_BYTES - pos_);
                std::memcpy(buffer_.bytes + pos_, p, take);
                pos_ += take; p += take; len -= take;

                if (pos_ == BLOCK_SIZE_BYTES) {
                    comp_.update(buffer_);
                    pos_ = 0;
                    buffer_.clear();
                }
            }

            while (len >= BLOCK_SIZE_BYTES) {
                Block64 block(p);
                comp_.update(block);
                p += BLOCK_SIZE_BYTES;
                len -= BLOCK_SIZE_BYTES;
            }

            if (len > 0) {
                std::memcpy(buffer_.bytes, p, len);
                pos_ = len;
            }

            total_bits_ += data.size() * 8;
            return *this;
        }
        StoneHash& update(Block64& block)noexcept
        {
            return update(std::span<const std::byte>(block.bytes, block.size_in_u8()));
        }

        // Legacy overloads for convenience
        StoneHash& update(const void* data, std::size_t len) noexcept
        {
            return update({ static_cast<const std::byte*>(data), len });
        }

        StoneHash& update(std::string_view sv) noexcept
        {
            return update({ reinterpret_cast<const std::byte*>(sv.data()), sv.size() });
        }

        template<class T>
            requires std::is_trivially_copyable_v<T>
        StoneHash& update(const T& value) noexcept
        {
            return update(std::as_bytes(std::span(&value, 1)));
        }

        template<class T, std::size_t N>
            requires std::is_trivially_copyable_v<T>
        StoneHash& update(const std::array<T, N>& arr) noexcept
        {
            return update(std::as_bytes(std::span(arr)));
        }

        template<class T>
            requires std::is_trivially_copyable_v<T>
        StoneHash& update(const std::vector<T>& vec) noexcept
        {
            return update(std::as_bytes(std::span(vec)));
        }

        // ================================================================
        // Output
        // ================================================================

        // Finalize the hash and return the full 512-bit (64-byte) internal state.
        // This is the strongest output mode — suitable for cryptographic use,
        // key derivation, commitments, or when you need maximum collision resistance.
        Block64 finalize() const noexcept
        {
            Compressor comp = comp_;       // copy compressor state
            Block64    buffer = buffer_;   // copy partial input buffer
            std::size_t pos = pos_;
            u64 total_bits = total_bits_;

            // Padding: single 0x80 bit + zero padding + 64-bit little-endian length
            buffer.bytes[pos++] = std::byte{ 0x80 };
            if (pos > BLOCK_SIZE_BYTES - 8) {
                std::memset(buffer.bytes + pos, 0, BLOCK_SIZE_BYTES - pos);
                comp.update(buffer);
                pos = 0;
            }
            std::memset(buffer.bytes + pos, 0, (BLOCK_SIZE_BYTES - 8) - pos);
            pos = BLOCK_SIZE_BYTES - 8;

            for (int i = 0; i < 8; ++i)
                buffer.bytes[pos + i] = std::byte(total_bits >> (i * 8));

            comp.update(buffer);
            return comp.finalize(total_bits);
        }

        // Return a 256-bit (32-byte) hash.
        // Security: ~128-bit collision resistance, >128-bit preimage resistance.
        // Recommended for nearly all cryptographic applications.
        [[nodiscard]] Block32 hash256() const noexcept
        {
            Block64 full = finalize();
            Block32 out;
            std::memcpy(out.bytes, full.bytes, 32);
            return out;
        }

        // Return a 128-bit (four 32-bit words) hash.
        // Security: ~64-bit collision resistance.
        // Suitable for hash tables, checksumming, or legacy protocols only.
        [[nodiscard]] std::array<u32, 4> hash128() const noexcept
        {
            const auto h = hash256().u32;
            return { h[0], h[1], h[2], h[3] };
        }

        // Return a single 64-bit hash value.
        // Security: ~32-bit collision resistance.
        // For non-cryptographic use only (e.g. PRNG seeding, bloom filters).
        [[nodiscard]] u64 hash64() const noexcept
        {
            return hash256().u64[0];
        }

        // One-shot convenience
        static Block32 hash(std::span<const std::byte> data,
            Block32 key = {}) noexcept
        {
            return StoneHash(key).update(data).hash256();
        }

        // ================================================================
        // Cleanup
        // ================================================================

        void wipe() noexcept
        {
            comp_.wipe();
            buffer_.clear();
            pos_ = total_bits_ = 0;
        }

    private:
        Compressor  comp_;
        Block64     buffer_{};
        std::size_t pos_ = 0;
        u64         total_bits_ = 0;

        // ----------------------------------------------------------------
        // Key setup — BLAKE3 IV + key + optional second block to kill fixed points
        // ----------------------------------------------------------------
        void init_with_key(Block32 key) noexcept
        {
            Block64 init{};

            // BLAKE3 initialization vector (best known constants for ChaCha-like hashes)
            init.u32[0] = 0x6a09e667u;
            init.u32[1] = 0xbb67ae85u;
            init.u32[2] = 0x3c6ef372u;
            init.u32[3] = 0xa54ff53au;
            init.u32[4] = 0x510e527fu;
            init.u32[5] = 0x9b05688cu;
            init.u32[6] = 0x1f83d9abu;
            init.u32[7] = 0x5be0cd19u;

            std::memcpy(init.u32 + 8, key.bytes, 32);
            comp_.update(init);

            if (key.is_zero()) {
                // Second initialization block eliminates fixed points
                comp_.update(comp_.finalize(64));
            }
        }
    };//class StoneHash


} // namespace st
