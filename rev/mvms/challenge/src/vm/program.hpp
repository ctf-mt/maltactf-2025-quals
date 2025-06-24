#pragma once
#include <array>
#include <cstdint>

namespace vm {
    constexpr auto kProgram = []() -> auto {
        constexpr std::int8_t data[] = {
#if __has_embed(PROGRAM_PATH)
    #embed PROGRAM_PATH
#else
    #error No program
#endif
        };

        std::array<std::uint8_t, sizeof(data)> result_array = {};
        for (size_t i = 0; i < sizeof(data); ++i) {
            result_array[i] = static_cast<std::uint8_t>(data[i]);
        }
        return result_array;
    }();
} // namespace vm