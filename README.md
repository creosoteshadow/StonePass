# StonePass
**The only deterministic, offline password generator in pure C++ — no storage, ChaCha20 crypto, MIT-licensed.**
### Offline Deterministic Password Generator. No storage. No cloud. No telemetry. No backdoors.
### One master password. Every site. Nothing stored --- ever.

**StonePass** is a fast, secure, fully offline deterministic password generator.  
You type your master password once — StonePass derives a strong, unique password for every website, every time, with perfect reproducibility and zero persistence.

StonePass is the only password tool that contains zero bytes of secret material when it is not running. 

No storage. No cloud. No transmission. No database. No sync. Just cryptography and you.

### Why StonePass?

| Feature                          | StonePass                     | Traditional Password Manager |
|----------------------------------|-------------------------------|------------------------------|
| Nothing stored on disk           | Yes                           | No                           |
| Works offline forever            | Yes                           | Yes (but needs backup)       |
| Survives device loss/theft       | Yes (just remember master)    | No                           |
| Immune to cloud breaches         | Yes                           | No                           |
| Cryptographic entropy            | 99+ bits @ 16 chars           | Varies                       |
| Resistant to GPU cracking        | Yes (1M fixed-cost iterations)| Usually                      |
| Look-alike characters excluded   | Yes                           | Sometimes                    |
| Open source & auditable          | Yes (MIT)                     | Sometimes                    |

Perfect for journalists, activists, security engineers, and anyone who values true sovereignty over their credentials.

### Master Password Guidance

IMPORTANT — Your master password is the ONLY secret
──────────────────────────────────────────────────
StonePass never saves anything — not even a hash.
If you forget your master password, every single generated password is lost forever.
There is no recovery.

• Memorize it — this is the gold standard.
• Second-best: write it on paper or engrave it on metal and lock it in a safe, safety-deposit box, or with a trusted person.
• Never store it digitally on your phone, computer, cloud notes, or “encrypted” password manager.
• Never take a photo or screenshot of it.
• Never write it in an email, chat, or text file.

A strong master password (or better: a full passphrase) of 20–40 characters is trivial to remember with a little practice and gives you decades of security even against nation-state attackers.

Treat it like the master key to your entire digital life — because that’s exactly what it is.

### Quick Example

Username:        alice@example.com
Master Password: correct horse battery staple 2025
Site:            github.com
Length:          20
Version:         1

→ Your password:  K7m]vP3$xQ9zT2cN8j!w

Change any input → completely different password.
Same inputs 20 years from now → identical password.

### Installation

StonePass is a single-file C++20 app — no dependencies.

**Compile from source:**

*Unix/Linux/macOS:*

# Download and build
curl -O https://raw.githubusercontent.com/creosoteshadow/StonePass/main/StonePass.cpp
c++ -std=c++20 -O2 -march=native StonePass.cpp -o stonepass

# Or with Makefile (included in repo)
make stonepass

*Windows (MSVC):*

Download StonePass.cpp.
Open Visual Studio.
Create a new Console App project named "StonePass".
Add StonePass.cpp to the project.
Build (Ctrl+Shift+B).

Then: create passwords!

Supported compilers: g++ 11+, clang++ 14+, MSVC 2022+.

### Security Highlights

ChaCha20 (20 rounds) used both as stream cipher and hash permutation
Custom 256-bit ChaCha-based hash (Merkle–Damgård strengthened, double length injection)
1 000 000 fixed iterations in KDF — deliberately slow and reproducible
All sensitive RAM explicitly zeroed with compiler barriers
Fisher–Yates shuffle eliminates policy-induced bias
Default charset removes ambiguous characters (0/O, 1/l/I, etc.)

Auditable single-file core (~1500 LOC). No external dependencies.

## Compiling

Linux (x86_64) — GCC 14.2 & Clang 18: Bash# GCC 14.2: g++ -std=c++20 -O2 -Wall -Wextra -pedantic -march=native -o stonepass stonepass.cpp

Clang 18: clang++ -std=c++20 -O2 -Wall -Wextra -pedantic -march=native -o stonepass stonepass.cpp

macOS (Apple Silicon M2) — Clang 16 (Apple): Bashclang++ -std=c++20 -O2 -Wall -Wextra -pedantic -o stonepass stonepass.cpp

Windows — MinGW-w64 (GCC 13.2) via MSYS2: Bashg++ -std=c++20 -O2 -static -o stonepass.exe stonepass.cpp

Windows — MSVC: Insert the source code into a new c++ console project / Compile / Generate Passwords!

# Contributing to StonePass

StonePass is minimalist by design — bug fixes and security audits welcome.

1. Fork the repo.
2. Create a feature branch (`git checkout -b feature/awesome-feature`).
3. Commit changes (`git commit -m 'Add some feature'`).
4. Push (`git push origin feature/awesome-feature`).
5. Open a Pull Request.

Tests: Run `c++ -std=c++20 StonePass.cpp && ./stonepass` with your inputs.
Security: Audit ChaCha impl before merging.

### License

MIT License — fork, modify, embed, sell, whatever.
Just keep the copyright notice.
