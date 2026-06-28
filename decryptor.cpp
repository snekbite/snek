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
    std::call_once(marshal_once_flag, []() {
#ifdef _WIN32
        // Windows: Get handle to current executable/DLL
        HMODULE handle = GetModuleHandleA(NULL);
        if (!handle) {
            _exit(1);
        }

        PyMarshal_ReadObjectFromString_ptr = (PyObject* (*)(const char*, Py_ssize_t))
            GetProcAddress(handle, "PyMarshal_ReadObjectFromString");
#else
        // Linux: Use RTLD_DEFAULT to resolve from the already-linked Python library
        // This avoids hardcoding any specific Python version path
        void* handle = RTLD_DEFAULT;

        PyMarshal_ReadObjectFromString_ptr = (PyObject* (*)(const char*, Py_ssize_t))
            dlsym(handle, "PyMarshal_ReadObjectFromString");
#endif

        if (!PyMarshal_ReadObjectFromString_ptr) {
            _exit(1);  // Silent exit on fatal error
        }
    });
}

PyCodeObject* decrypt_code_object(const std::vector<uint8_t>& blob, const uint8_t* key) {
    resolve_marshal();

    if (blob.empty() || blob.size() < 28) {
        return nullptr;
    }

    // Extract components: nonce (12) + tag (16) + ciphertext
    unsigned char nonce[12];
    memcpy(nonce, blob.data(), 12);
    unsigned char tag[16];
    memcpy(tag, blob.data() + 12, 16);
    const unsigned char* ciphertext = blob.data() + 28;
    unsigned long long ciphertext_len = blob.size() - 28;

    // Decrypt
    std::vector<unsigned char> plaintext(ciphertext_len);

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

    // Unmarshal bytecode
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
