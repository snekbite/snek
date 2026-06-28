#include "runtime.hpp"
#include "decryptor.hpp"
#include <frameobject.h>
#include <sodium.h>
#include <vector>
#include <array>
#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif
#include <unordered_map>
#include <shared_mutex>
#include <mutex>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <fstream>

// ============================================================================
// ANTI-DEBUGGING PROTECTION (Safe version - runs before Python init)
// ============================================================================

#ifdef _WIN32
// Windows anti-debugging checks
static bool check_tracer_pid() {
    return IsDebuggerPresent();
}

static bool check_debug_env() {
    // Check for common Windows debugger environment variables
    if (getenv("_NT_SYMBOL_PATH") || getenv("_NT_ALT_SYMBOL_PATH")) {
        return true;
    }
    return false;
}
#else
// Linux anti-debugging checks
// Check /proc/self/status for TracerPid (safest method)
static bool check_tracer_pid() {
    std::ifstream status("/proc/self/status");
    if (!status.is_open()) return false;

    std::string line;
    while (std::getline(status, line)) {
        if (line.rfind("TracerPid:", 0) == 0) {
            size_t pos = line.find_first_of("0123456789");
            if (pos != std::string::npos) {
                int tracer_pid = std::stoi(line.substr(pos));
                return tracer_pid != 0;
            }
            break;
        }
    }
    return false;
}

// Check for debugger launch via environment
static bool check_debug_env() {
    const char* launcher = getenv("_");
    if (launcher) {
        if (strstr(launcher, "gdb") || strstr(launcher, "lldb") ||
            strstr(launcher, "strace") || strstr(launcher, "ltrace") ||
            strstr(launcher, "valgrind")) {
            return true;
        }
    }
    return false;
}
#endif

// Safe anti-debug check - call BEFORE Py_Initialize()
// Returns true if debugger detected
static bool safe_anti_debug_check() {
    if (check_tracer_pid()) return true;
    if (check_debug_env()) return true;
    return false;
}

// Public function to run anti-debug check from main()
extern "C" int snek_check_environment() {
    if (safe_anti_debug_check()) {
        return 1;  // Debugger detected
    }
    return 0;  // OK
}

// ---------- Data structures ----------
struct CodeObjectCache {
    std::vector<uint8_t> encrypted_blob;
    PyCodeObject* decrypted_code;
    bool is_decrypted;
};

static std::unordered_map<PyCodeObject*, CodeObjectCache> code_cache;
static std::shared_mutex cache_mutex;

static std::unordered_map<PyCodeObject*, bool> seen_codes;
static std::mutex seen_mutex;

// ---------- Frame eval hook symbols (version-specific) ----------
#if PY_VERSION_HEX >= 0x030B0000  // Python 3.11+
static _PyFrameEvalFunction (*_PyInterpreterState_GetEvalFrameFunc_ptr)(PyInterpreterState*) = nullptr;
static void (*_PyInterpreterState_SetEvalFrameFunc_ptr)(PyInterpreterState*, _PyFrameEvalFunction) = nullptr;
static PyObject* (*_PyEval_EvalFrameDefault_ptr)(PyThreadState*, struct _PyInterpreterFrame*, int) = nullptr;
#else  // Python 3.10 and earlier
static _PyFrameEvalFunction (*_PyInterpreterState_GetEvalFrameFunc_ptr)(PyInterpreterState*) = nullptr;
static void (*_PyInterpreterState_SetEvalFrameFunc_ptr)(PyInterpreterState*, _PyFrameEvalFunction) = nullptr;
static PyObject* (*_PyEval_EvalFrameDefault_ptr)(PyThreadState*, PyFrameObject*, int) = nullptr;
#endif

static void resolve_frame_symbols() {
    static bool done = false;
    if (done) return;

#ifdef _WIN32
    // Windows: Use GetProcAddress to get symbols from the Python DLL
    HMODULE handle = GetModuleHandleA(NULL);  // Get handle to current executable
    if (!handle) { exit(1); }

#define RESOLVE(sym) do { \
    *(void**)(&sym##_ptr) = (void*)GetProcAddress(handle, #sym); \
    if (!sym##_ptr) { exit(1); } \
} while(0)
#else
    // Linux: Use dlsym to get symbols from the already-linked Python library
    // This avoids loading a second Python library which would cause conflicts
    void* handle = RTLD_DEFAULT;

#define RESOLVE(sym) do { \
    *(void**)(&sym##_ptr) = dlsym(handle, #sym); \
    if (!sym##_ptr) { exit(1); } \
} while(0)
#endif

    RESOLVE(_PyInterpreterState_GetEvalFrameFunc);
    RESOLVE(_PyInterpreterState_SetEvalFrameFunc);
    RESOLVE(_PyEval_EvalFrameDefault);
#undef RESOLVE

    done = true;
}

// Version-specific frame offsets
#if PY_VERSION_HEX >= 0x030B0000  // Python 3.11+
static int f_code_offset = 0x20;       // Points to f_code in _PyInterpreterFrame
static int f_prev_instr_offset = 0x28; // Points to prev_instr

static PyCodeObject* fast_get_code(struct _PyInterpreterFrame* frame) {
    if (!frame) return nullptr;
    return *(PyCodeObject**)((uint8_t*)frame + f_code_offset);
}
#else  // Python 3.10 and earlier
// For Python 3.10, we use PyFrameObject directly
static PyCodeObject* fast_get_code(PyFrameObject* frame) {
    if (!frame) return nullptr;
    return frame->f_code;
}
#endif

// ---------- Public API to register encrypted blobs ----------
extern "C" void register_encrypted_blob(PyCodeObject* original_code, 
                                         const uint8_t* data, size_t size) {
    if (!original_code || !data || size == 0) return;
    
    std::unique_lock<std::shared_mutex> lock(cache_mutex);
    CodeObjectCache cache;
    cache.encrypted_blob = std::vector<uint8_t>(data, data + size);
    cache.decrypted_code = nullptr;
    cache.is_decrypted = false;
    code_cache[original_code] = std::move(cache);
    
    std::lock_guard<std::mutex> seen_lock(seen_mutex);
    seen_codes[original_code] = true;
}

extern "C" std::array<uint8_t, 32> get_runtime_key();

static PyCodeObject* get_or_decrypt_code(PyCodeObject* original_code) {
    {
        std::shared_lock<std::shared_mutex> lock(cache_mutex);
        auto it = code_cache.find(original_code);
        if (it != code_cache.end()) {
            if (it->second.is_decrypted) {
                return it->second.decrypted_code;
            }
            
            auto key = get_runtime_key();
            PyCodeObject* decrypted = decrypt_code_object(it->second.encrypted_blob, key.data());
            
            if (decrypted) {
                lock.unlock();
                std::unique_lock<std::shared_mutex> write_lock(cache_mutex);
                it->second.decrypted_code = decrypted;
                it->second.is_decrypted = true;
                return decrypted;
            }
        }
    }
    return original_code;
}

// ============================================================================
// FRAME EVALUATION HOOK (version-specific)
// ============================================================================

#if PY_VERSION_HEX >= 0x030B0000  // Python 3.11+
PyObject* protected_eval_frame(PyThreadState* tstate,
                                struct _PyInterpreterFrame* frame,
                                int throwflag) {
    resolve_frame_symbols();

    PyCodeObject* code = fast_get_code(frame);
    if (!code) return _PyEval_EvalFrameDefault_ptr(tstate, frame, throwflag);

    PyCodeObject* exec_code = get_or_decrypt_code(code);

    if (exec_code != code) {
        // 1. Swap the code object
        void** frame_code_ptr = (void**)((uint8_t*)frame + f_code_offset);
        *frame_code_ptr = (void*)exec_code;

        // 2. CRITICAL: Reset instruction pointer for Python 3.11/3.12
        // prev_instr must point to the instruction BEFORE the first one to execute
        void** prev_instr_ptr = (void**)((uint8_t*)frame + f_prev_instr_offset);
        *prev_instr_ptr = (void*)(exec_code->co_code_adaptive - 1);

        // Transfer reference ownership to the frame
        Py_INCREF(exec_code);
        Py_DECREF(code);
    }

    return _PyEval_EvalFrameDefault_ptr(tstate, frame, throwflag);
}
#else  // Python 3.10 and earlier
PyObject* protected_eval_frame(PyThreadState* tstate,
                                PyFrameObject* frame,
                                int throwflag) {
    resolve_frame_symbols();

    PyCodeObject* code = fast_get_code(frame);
    if (!code) return _PyEval_EvalFrameDefault_ptr(tstate, frame, throwflag);

    PyCodeObject* exec_code = get_or_decrypt_code(code);

    if (exec_code != code) {
        // For Python 3.10, we can directly replace the code object
        Py_INCREF(exec_code);
        Py_DECREF(frame->f_code);
        frame->f_code = exec_code;
    }

    return _PyEval_EvalFrameDefault_ptr(tstate, frame, throwflag);
}
#endif

extern "C" void install_frame_hook() {
    if (!Py_IsInitialized()) Py_Initialize();
    resolve_frame_symbols();

    PyInterpreterState* interp = PyInterpreterState_Get();
    _PyInterpreterState_SetEvalFrameFunc_ptr(interp, protected_eval_frame);
}
