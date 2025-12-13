#pragma once
// File StoneKey.h -- memory-hard password hasher

#include "StoneHash.h"

namespace st {

    //
    // StoneKey(password, context = {})
    // ---------------------------------------------------------------------
    // Memory-hard, data-independent (side-channel-friendly) password-to-256-bit-key
    // derivation. (Side-channel resistance assumes constant-time ChaCha, constant-time
    // updates, and no compiler-introduced data-dependent branches or speculative leaks.)
    //
    // Default: 64 MiB, ~1 second (2025–2030 hardware) — actual runtime varies with
    // CPU memory bandwidth, cores, and system configuration; benchmark for target HW.
    // ---------------------------------------------------------------------
    //
    // This function turns an *already high-entropy* passphrase into a uniform 256-bit
    // key in a deterministic, domain-separated, memory-hard way. It is NOT an entropy
    // stretcher: weak passwords are still susceptible to offline brute-force attacks;
    // StoneHash only increases attacker cost.
    //
    // If your input password is weak (dictionary word, short, etc.), an offline attacker
    // can and will brute-force it. Recommended minimum: ≥100 bits of entropy (e.g. long
    // human-memorable passphrases or 12+ random Diceware words). Entropy estimates
    // assume uniformly drawn passphrases.
    //
    // With a properly strong password, brute-forcing is considered infeasible for
    // personal use. For government, banking, or other high-security applications,
    // prefer well-vetted, standardized KDFs and cryptographic software approved by
    // relevant standards bodies (e.g., NIST).
    //
    // Important implementation notes:
    //  - Lock memory to avoid paging (mlock / VirtualLock or a secure allocator).
    //  - Securely zero all sensitive buffers (memory, acc, etc.) before release.
    //  - Ensure ChaCha implementation is constant-time and free of data-dependent branches.
    //  - This construction is heuristic with respect to TMTO resistance; it is inspired
    //    by the same TMTO-resistance principles as Balloon and Lyra2, but it is not
    //    accompanied by a formal TMTO proof.
    //  - The m_cost upper bound enforces a safe maximum (2^26 * 64 B = 4 GiB) to avoid
    //    unreasonable memory usage on common systems.
    // ---------------------------------------------------------------------

    // Recommended real-world default (2025–2030)
    constexpr uint32_t STONEKEY_V2_M_COST = 20;        // 2²⁰ × 64 B = 64 MiB
    constexpr uint32_t STONEKEY_V2_T_COST = 3;         // ~1 second on fast 2025–2030 CPUs when M_COST is 20

    [[nodiscard]] inline Block32 StoneKey(
        std::string_view password,
        std::string_view context = {},
        uint32_t         m_cost = STONEKEY_V2_M_COST,
        uint32_t         t_cost = STONEKEY_V2_T_COST)
    {
        if (m_cost > 26) throw std::invalid_argument("StoneKey: m_cost too high (max 26: 4 GiB)");
        if (t_cost == 0) throw std::invalid_argument("StoneKey: t_cost must be >= 1");
        if (password.size() == 0)throw std::invalid_argument("StoneKey: password is empty");

        const size_t n_blocks = 1ull << m_cost; // default 1048576
        using mblock = std::array<uint32_t, 16>; // 64 bytes
        std::vector<mblock> memory(n_blocks); // 64 * (1<<m_cost) bytes, default 64 MiB

        // === Phase 1: Fill (password only in block 0, context in all) ===
        for (size_t i = 0; i < n_blocks; ++i) {
            StoneHash h;
            h.update("StoneHash::v2::fill");
            if (context.size() > 0)
                h.update(context);
            h.update((const void*)&i, sizeof(i));
            if (i == 0)
                h.update(password);
            Block64 blk = h.finalize();
            std::memcpy(memory[i].data(), blk.bytes, 64);
        }

        // === Phase 2: Butterfly mixing (the magic) ===
        /*
        Please note: this is NOT an FFT.

        It’s a butterfly mixing network with irreversible operations at every stage. The indexing
        scheme was inspired by the indexing in a Fast Fourier Transform, but the operations performed
        at each step are not the simple multiply, add, and subtract found in a FFT.

        In a real FFT you do reversible additions/subtractions and multiplications by roots of unity.
        Here, at every butterfly step we do:

        y ^= x ^ (data-dependent mix value) → irreversible XOR
        Four ChaCha quarter-rounds on y → non-linear, irreversible diffusion
        x ^= y → another irreversible step

        That’s three layers of irreversibility per butterfly.

        The full butterfly step is computationally infeasible to invert because recovering pre-images
        requires undoing data-dependent XORs combined with ChaCha diffusion; this reduces to breaking
        ChaCha.

        The butterfly topology is Inspired by the same TMTO-resistance principles as Balloon
        and Lyra2, but our structure is not accompanied by formal proofs.

        The structure is inspired by FFTs.
        The operations are not.

        My guess: it’s about as reversible as scrypt’s Salsa20/8 or Argon2’s BLAKE2b round function.
        */
        constexpr uint64_t GOLDEN_GAMMA = 0x9e3779b97f4a7c15ULL; // ≈ 2³²/φ

        uint64_t counter = GOLDEN_GAMMA;
        {
            // Determine initial value of 'block_counter'
            StoneHash tmp;
            tmp.update("StoneHash::v2::counter_seed");
            tmp.update(password);
            counter ^= tmp.finalize().u64[0];
        }

        for (uint32_t round = 0; round < t_cost; ++round) { // time hard loop
            counter += GOLDEN_GAMMA;

            // fft butterfly section
            for (size_t span = 1; span < n_blocks; span *= 2) {
                for (size_t start = 0; start < n_blocks; start += 2 * span) {
                    for (size_t k = 0; k < span; ++k) {
                        size_t a = start + k;
                        size_t b = a + span;

                        uint32_t* x = memory[a].data();
                        uint32_t* y = memory[b].data();

                        uint64_t mix = counter ^ (uint64_t(a) << 32 | b);

                        for (int i = 0; i < 16; ++i)
                            y[i] ^= x[i] ^ uint32_t(mix >> (i * 4));

                        ChaCha::QR(y[0], y[4], y[8], y[12]);
                        ChaCha::QR(y[1], y[5], y[9], y[13]);
                        ChaCha::QR(y[2], y[6], y[10], y[14]);
                        ChaCha::QR(y[3], y[7], y[11], y[15]);

                        for (int i = 0; i < 16; ++i)
                            x[i] ^= y[i];
                    }
                }
            }
        }

        // === Final compression: compress 'memory' down to 64 bytes ===
        // Note: Since accumulated XORs lose information, the whole compression remains one - way.
        Block64 acc{};
        for (size_t i = 0; i < n_blocks; ++i) {
            for (int j = 0; j < 16; ++j)
                acc.u32[j] ^= memory[i][j];

            // index mixing
            acc.u64[0] ^= i;
            acc.u64[1] ^= i << 32;
            acc.u64[2] ^= i * GOLDEN_GAMMA;
            acc.u64[3] ^= i * (GOLDEN_GAMMA >> 13);

            ChaCha::permute_block(acc, acc); // full diffusion
        }
        ChaCha::permute_block(acc, acc); // Final mixing round

        // === Securely erase the memory-hard workspace ===
        // This prevents secrets from lingering in RAM after derivation.
        for (size_t i = 0; i < n_blocks; ++i) {
            volatile uint32_t* p = memory[i].data();
            for (size_t j = 0; j < memory[i].size(); ++j)
                p[j] = 0;
        }

        // === Final extraction: extract uniform 256-bit key ===
        //
        // The accumulator `acc` already contains the full entropy of the memory-hard
        // computation, but compression via repeated XOR+permute is not guaranteed to
        // be a perfect randomness extractor (i.e., could have some entropy loss).
        //
        // To guarantee a uniform, high-entropy output (even if the memory-hard phase
        // somehow produced slightly biased the distribution), we perform one final
        // domain-separated StoneHash compression of:
        //   • password (original entropy source)
        //   • context (domain separation)
        //   • acc (all mixed memory-hard state)
        //
        // This is a standard, conservative "extract-then-expand" technique used in
        // virtually all serious KDFs (HKDF, Argon2, scrypt, etc.).
        //
        StoneHash out;
        out.update("StoneKey::v2::final");  // domain separation ("salt" for this step)
        out.update(password);               // re-inject original entropy
        out.update(context);                // per-application isolation
        out.update(acc);                    // all memory-hard work
        return out.hash256();
    }// StoneKey

}// namespace st
