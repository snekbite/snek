#include "decryptor.hpp"
#include <sodium.h>
#include <cstring>
#include <vector>
#include <array>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif
#include <cstdio>
#include <mutex>

static PyObject* (*PyMarshal_ReadObjectFromString_ptr)(const char*, Py_ssize_t) = nullptr;
static std::once_flag marshal_once_flag;

static void resolve_marshal() {
    // PyMarshal_ReadObjectFromString is part of the stable CPython ABI but is
    // not declared in any public header we can easily include here, so we
    // resolve it at runtime. call_once ensures this is thread-safe and happens
    // exactly once regardless of how many code objects are decrypted in parallel.
    std::call_once(marshal_once_flag, []() {
#ifdef _WIN32
        HMODULE handle = GetModuleHandleA(NULL);
        if (!handle) {
            _exit(1);
        }

        PyMarshal_ReadObjectFromString_ptr = (PyObject* (*)(const char*, Py_ssize_t))
            GetProcAddress(handle, "PyMarshal_ReadObjectFromString");
#else
        // RTLD_DEFAULT resolves against the already-linked libpython, so no
        // hardcoded version path is needed and no second copy is loaded.
        void* handle = RTLD_DEFAULT;

        PyMarshal_ReadObjectFromString_ptr = (PyObject* (*)(const char*, Py_ssize_t))
            dlsym(handle, "PyMarshal_ReadObjectFromString");
#endif

        if (!PyMarshal_ReadObjectFromString_ptr) {
            _exit(1);
        }
    });
}

// Decrypt one encrypted code-object blob and return a live PyCodeObject*.
//
// Blob layout (matches the output of Encryptor::encrypt in the obfuscator):
//   [0..11]  nonce  — 12-byte random value, unique per code object per build
//   [12..27] tag    — 16-byte Poly1305 authentication tag
//   [28..]   ciphertext — ChaCha20-encrypted marshal'd PyCodeObject
//
// Returns nullptr on any failure (wrong key, corrupt blob, or non-code object).
// The caller owns the returned reference and must Py_DECREF when done.
PyCodeObject* decrypt_code_object(const std::vector<uint8_t>& blob, const uint8_t* key) {
    resolve_marshal();

    // 28 = 12 (nonce) + 16 (tag); anything shorter can't be a valid blob.
    if (blob.empty() || blob.size() < 28) {
        return nullptr;
    }

    unsigned char nonce[12];
    memcpy(nonce, blob.data(), 12);
    unsigned char tag[16];
    memcpy(tag, blob.data() + 12, 16);
    const unsigned char* ciphertext = blob.data() + 28;
    unsigned long long ciphertext_len = blob.size() - 28;

    std::vector<unsigned char> plaintext(ciphertext_len);

    // _detached variant takes the tag separately, matching how the obfuscator
    // splits and stores it. Returns non-zero if authentication fails (wrong key
    // or tampered ciphertext) — in that case we bail out silently.
    int ret = crypto_aead_chacha20poly1305_decrypt_detached(
        plaintext.data(), nullptr,
        ciphertext, ciphertext_len,
        tag,
        nullptr, 0,
        nonce,
        key
    );

    if (ret != 0) {
        return nullptr;
    }

    // The plaintext is a standard marshal'd code object, identical to what
    // Python would write into a .pyc file. Feed it back through the marshal
    // reader to get a live PyCodeObject*.
    PyObject* code = PyMarshal_ReadObjectFromString_ptr(
        reinterpret_cast<const char*>(plaintext.data()),
        plaintext.size()
    );

    if (!code || !PyCode_Check(code)) {
        if (code) Py_DECREF(code);
        return nullptr;
    }

    return (PyCodeObject*)code;
}
