#pragma once
#include <Python.h>
#include <vector>
#include <cstdint>

// NOT extern "C" – this is a C++ function with C++ types
PyCodeObject* decrypt_code_object(const std::vector<uint8_t>& encrypted_blob, const uint8_t* key);
