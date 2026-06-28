#pragma once
#include <Python.h>

struct _PyInterpreterFrame;

extern "C" {
    void install_frame_hook();
    void register_encrypted_blob(PyCodeObject* code, const uint8_t* data, size_t size);
}
