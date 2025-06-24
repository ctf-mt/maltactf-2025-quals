#pragma once

#if defined(_DEBUG) // useful for debugging
    #define ENABLE_EXCEPTIONS
#endif

#if defined(__clang__)
    #if !defined(_DEBUG)
        #define ALWAYS_INLINE inline __attribute__((always_inline))
    #else // no inlining in debug mode
        #define ALWAYS_INLINE inline
    #endif
#else
    #error unsupported
#endif

/// See `scripts/vm_lib/clang_workaround.py` for details and why this is needed.
constexpr std::size_t kBinOffset = 4;
