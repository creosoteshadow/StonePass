#pragma once
// File: stBlock.h
// Description: Definition of a Block union for safe type punning.
#define _CRT_DECLARE_NONSTDC_NAMES 1

#include <cstdint>      // std::uint8_t, std::uint32_t, etc.
#include <cstddef>      // std::byte, std::size_t
#include <cstring>      // std::memcpy, std::memset
#include <array>        // std::array
#include <bit>          // std::rotl (future-proof + ChaCha dependency)
#include <type_traits>  // std::is_trivially_copyable_v
#include <cstring>

/*
    CONTENTS
    ┌─────────────────────────────────────────────────────────────────────┐
    │  Type aliases                                                       │
    │      u8, u16, u32, u64  – fixed-width unsigned integers             │
    ├─────────────────────────────────────────────────────────────────────┤
    │  Template union                                                     │
    │                                                                     │
    │  Block<NBytes>                                                      │
    │      • Raw views: bytes[], u8[], u16[], u32[], u64[]                │
    │      • Construction from arrays, pointers, std::array<T,N>          │
    │      • Assignment, equality, zero-check, clear()                    │
    │      • Global operators ^ and ^= (XOR)                              │
    ├─────────────────────────────────────────────────────────────────────┤
    │  Common instantiations                                              │
    │                                                                     │
    │      Block64 – 64-byte block (ChaCha20, SHA-512, etc.)              │
    │      Block32 – 32-byte block (SHA-256, BLAKE2s, etc.)               │
    └─────────────────────────────────────────────────────────────────────┘
*/

namespace st {
    // alias types for fixed sized unsigned integers    
    using u8 = std::uint8_t;
    using u16 = std::uint16_t;
    using u32 = std::uint32_t;
    using u64 = std::uint64_t;

    // Block union for safe type punning.
    template <std::size_t NBytes> // NBytes is frequently 64, but that is not required
    union Block
    {
        std::byte   bytes[NBytes]{};    // raw byte view
        uint8_t     u8[NBytes];         // One byte at a time
        uint16_t    u16[NBytes / 2];    // 
        uint32_t    u32[NBytes / 4];    // unsigned long: main view for ChaCha20
        uint64_t    u64[NBytes / 8];    // unsigned long long

        // ------------ 
        // CONSTRUCTORS
        // ------------ 

        // Construct from a std::array of trivially copyable objects
        template <class T, std::size_t N> requires (N * sizeof(T) == NBytes) && std::is_trivially_copyable_v<T>
        Block(const std::array<T, N>& src) noexcept
        {
            std::memcpy(bytes, src.data(), NBytes);
        }

        // Construct from an array of trivially copyable objects
        template <class T, std::size_t N> requires (N * sizeof(T) == NBytes) && std::is_trivially_copyable_v<T>
        Block(const T (&src)[N]) noexcept
        {
            std::memcpy(bytes, src, NBytes);
        }

        // Construct from a byte pointer
        explicit Block(const std::byte* p) noexcept
        {
            std::memcpy(bytes, p, NBytes);
        }

        // default constructor
        Block() noexcept = default;

        ~Block() { clear(); }

        // copy operator
        Block& operator= (const Block& other) noexcept {
            if (this != &other)
                std::memcpy(bytes, other.bytes, NBytes);
            return *this;
        }

        // ----------------- 
        // UTILITY FUNCTIONS
        // ----------------- 
        
        // Number of complete elements of each type that fit in the block.
        // If NBytes is not divisible by the element size, the result is truncated
        // (e.g., a 68-byte block has 17 complete uint32_t elements).
        static constexpr std::size_t size_in_u8()  noexcept { return NBytes; }  // = NBytes / 1
        static constexpr std::size_t size_in_u16() noexcept { return NBytes >> 1; }  // = NBytes / 2
        static constexpr std::size_t size_in_u32() noexcept { return NBytes >> 2; }  // = NBytes / 4
        static constexpr std::size_t size_in_u64() noexcept { return NBytes >> 3; }  // = NBytes / 8

        // Convenience aliases used extremely frequently in cryptographic code
        static constexpr std::size_t size_in_dwords() noexcept { return size_in_u32(); }  // ChaCha20, SHA-2, etc.
        static constexpr std::size_t size_in_qwords() noexcept { return size_in_u64(); }  // KECCAK, BLAKE, etc.


        inline void clear() noexcept
        {
            // wipe 64-bit chunks
            volatile uint64_t* v64 = reinterpret_cast<volatile uint64_t*>(u64);
            for (std::size_t i = 0; i < size_in_u64(); ++i) {
                v64[i] = 0;
            }

            // wipe tail bytes
            volatile std::byte* v8 =
                reinterpret_cast<volatile std::byte*>(bytes);
            for (std::size_t i = 8 * size_in_u64(); i < NBytes; ++i) {
                v8[i] = std::byte{ 0 };
            }
        }

        // equality operator
        inline bool operator==(const Block& other) const noexcept
        {
            if (this == &other) return true;

            // u64 comparisons
            for (std::size_t i = 0; i < size_in_u64(); ++i) {
                if (u64[i] != other.u64[i])
                    return false;
            }

            // byte comparisons
            for (std::size_t i = 8 * size_in_u64(); i < NBytes; ++i) {
                if (bytes[i] != other.bytes[i])
                    return false;
            }

            return true;
        }

        // checks if the Block is all zeros
        inline bool is_zero() const noexcept {
            // check 8 bytes at a time
            for (std::size_t i = 0; i < size_in_u64(); ++i) {
                if (u64[i] != 0ull)
                    return false;
            }

            // check remaining bytes
            for (std::size_t i = 8 * size_in_u64(); i < NBytes; ++i) {
                if (bytes[i] != std::byte{ 0 })
                    return false;
            }

            return true;
        }

    };// class Block<NBytes>

    // We put the ^ and ^= operators after the Block definition, still inside namespace st

    // ^ operator: bitwise XOR of two Blocks
    template <std::size_t NBytes>
    Block<NBytes> operator^(const Block<NBytes>& a, const Block<NBytes>& b) noexcept
    {
        Block<NBytes> result;
        std::size_t qwords = Block<NBytes>::size_in_u64();
        std::size_t tail = NBytes - 8 * qwords;

        for (std::size_t i = 0; i < qwords; ++i)
            result.u64[i] = a.u64[i] ^ b.u64[i];

        for (std::size_t i = 0; i < tail; ++i)
            result.bytes[8 * qwords + i] = a.bytes[8 * qwords + i] ^ b.bytes[8 * qwords + i];

        return result;
    }

    // ^= operator: in-place bitwise XOR of two Blocks
    template <std::size_t NBytes>
    Block<NBytes>& operator^=(Block<NBytes>& a, const Block<NBytes>& b) noexcept
    {
        std::size_t qwords = Block<NBytes>::size_in_u64();
        std::size_t tail = NBytes - 8 * qwords;

        for (std::size_t i = 0; i < qwords; ++i)
            a.u64[i] ^= b.u64[i];

        for (std::size_t i = 0; i < tail; ++i)
            a.bytes[8 * qwords + i] ^= b.bytes[8 * qwords + i];

        return a;
    }

    using Block64 = Block<64>; // a union that allows us to view 64 bytes as std::bytes, u8, u32, or u64
    using Block32 = Block<32>;
}
