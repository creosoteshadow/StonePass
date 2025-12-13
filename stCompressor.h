#pragma once
// file stCompressor.h - Compressor class definition
#define _CRT_DECLARE_NONSTDC_NAMES 1

#include "stBlock.h" // for Block64
#include "stChaCha.h" // for ChaCha permutation

/*
    CONTENTS
    ┌─────────────────────────────────────────────────────────────────────┐
    │ class Compressor                                                    │
    │ • Accumulates 64-byte blocks via ChaCha20-based compression         │
    │ • Used as the core of st::Hash::Secure (BLAKE-style construction)   │
    │                                                                     │
    │ Interface                                                           │
    │   update(Block64&)      – absorb one full block                     │
    │   finalize(uint64_t)    – finalize with message length (in bytes)   │
    │   wipe()                – zeroize internal state                    │
    └─────────────────────────────────────────────────────────────────────┘
*/

namespace st {
    // Compressor — compresses full 64-byte blocks using ChaCha20 permutation.
    // This is used as a building-block for st::Hash::Secure
    class Compressor {
        Block64 state{}; // a union

    public:

        void update(const Block64& block) noexcept {
            state ^= block;
            ChaCha::permute_block(state, state);
        }

        Block64 finalize(uint64_t total_bytes) const noexcept {
            Block64 h = state;

            // Final block flag
            h.u32[0] ^= 0x01u;

            // Inject message length in bits using rotate-left-by-3 instead of multiply-by-8
            // This preserves all 64 bits of the length field even if total_bytes * 8 would overflow
            // Result is equivalent to bit length for messages < 2^61 bytes, and remains
            // injective and high-entropy for all larger messages.
            const uint64_t bit_len = std::rotl(total_bytes, 3);  // total_bytes × 8, wraparound-safe

            h.u32[12] ^= static_cast<u32>(bit_len);
            h.u32[13] ^= static_cast<u32>(bit_len >> 32);

            ChaCha::permute_block(h, h);
            return h;
        }

        void wipe() noexcept { state.clear(); }
    };
}//namespace st

