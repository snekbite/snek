# Snek

**Bytecode-level Python obfuscation. Not source renaming — actual encryption.**

Snek encrypts your Python bytecode with ChaCha20-Poly1305 and compiles it into a native binary. Decompilers like `uncompyle6`, `pycdc`, and `decompyle3` cannot recover your source code.

→ **[snekbite.com](https://snekbite.com)**

---

## How it works

The Snek toolchain has two parts:

| Part | Status | What it does |
|------|--------|--------------|
| **Obfuscator** | Closed source | Parses your `.py` files, compiles to bytecode, encrypts each code object with a per-binary ChaCha20-Poly1305 key, and generates a native C++ binary |
| **Runtime** | [Open source](https://github.com/snekbite/runtime) | The C++ code that lives inside every protected binary — hooks CPython's frame evaluation API to decrypt and execute bytecode on demand |

The runtime is open-source so you can audit exactly what runs on your machine. The obfuscator stays closed because it contains the encryption and key-generation logic that makes the protection work.

## Repositories

- [`snekbite/snek`](https://github.com/snekbite/snek) — Open-source C++ runtime (CPython frame eval hook + ChaCha20 decryptor)

## Supported platforms

| Platform | Python 3.12 | Python 3.14 |
|----------|-------------|-------------|
| Linux x64 | ✅ | ✅ |
| Windows x64 | ✅ | ✅ |

## Try it

Upload a Python script at **[snekbite.com](https://snekbite.com)** — no account needed for the free tier.
