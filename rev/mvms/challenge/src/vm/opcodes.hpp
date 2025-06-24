#pragma once
#include <array>
#include <cstdint>
#include <utility>

#include "util/macros.hpp"

namespace vm {
    /// From 0 to MAX_INDEX, used as indexes for opcodes.bin file
    // clang-format off
    enum class OpcodeIndex : std::size_t {
        NOP = 0,
        LOAD,      // [OP, reg, imm8]          → registers_[reg] = (int8_t)imm8
        LOAD_32,   // [OP, reg, imm32]         → registers_[reg] = (int32_t)imm32
        LOAD_64,   // [OP, reg, imm64]         → registers_[reg] = (int64_t)imm64
        LOAD_128,  // [OP, reg, imm128]        → registers_[reg] = (int128_t)imm64
        ADD,       // [OP, rd, rs1, rs2]       → rd = rs1 + rs2
        SUB,       // [OP, rd, rs1, rs2]       → rd = rs1 - rs2
        OR,        // [OP, rd, rs1, rs2]       → rd = rs1 | rs2
        NOR,       // [OP, rd, rs1, rs2]       → rd = ~(rs1 | rs2)
        ROL,       // [OP, rd, rs1, imm8]      → rd = rol(rs1, imm8)
        ROR,       // [OP, rd, rs1, imm8]      → rd = ror(rs1, imm8)
        AND,       // [OP, rd, rs1, rs2]       → rd = rs1 & rs2
        MOD,       // [OP, rd, rs1, rs2]       → rd = rs1 % rs2
        XOR,       // [OP, rd, rs1, rs2]       → rd = rs1 ^ rs2
        MUL,       // [OP, rd, rs1, rs2]       → rd = rs1 * rs2
        PUSH_R,    // [OP, reg]                → push registers_[reg] onto stack
        POP_R,     // [OP, reg]                → pop stack → registers_[reg]
        ADD_STK,   // [OP]                     → pop a,b; push (a + b)
        SUB_STK,   // [OP]                     → pop a,b; push (a - b)
        OR_STK,    // [OP]                     → pop a,b; push (a | b)
        NOR_STK,   // [OP]                     → pop a,b; push ~(a | b)
        ROL_STK,   // [OP]                     → pop a,b; push rol(a, b)
        ROR_STK,   // [OP]                     → pop a,b; push ror(a, b)
        AND_STK,   // [OP, rd, rs1, rs2]       → pop a,b; push a & b
        MOD_STK,   // [OP, rd, rs1, rs2]       → pop a,b; push a % b
        XOR_STK,   // [OP, rd, rs1, rs2]       → pop a,b; push a ^ b
        MUL_STK,   // [OP, rd, rs1, rs2]       → pop a,b; push a * b
        JZ,        // [OP, reg, offset8]       → if (registers_[reg] == 0) pc += offset8
        JNZ,       // [OP, reg, offset8]       → if (registers_[reg] != 0) pc += offset8
        JMP,       // [OP, offset8]            → pc += offset8
        STOP,      // [OP]                     → stop execution
        PRINTLN,   // [OP]                     → prints top of the stack
        READ,      // [OP, reg]                → reads at most 16 bytes from stdin into registers_[reg]
        MAX_INDEX,
    };
    // clang-format on

    constexpr auto kOpcodesCount = std::to_underlying(OpcodeIndex::MAX_INDEX);
    constexpr auto kOpcodes = []() -> auto {
        constexpr std::int8_t data[] = {
#if __has_embed(OPCODES_PATH)
    #embed OPCODES_PATH
#else
    #error No opcodes
#endif
        };

        std::array<std::uint8_t, sizeof(data)> result_array;
        for (size_t i = 0; i < sizeof(data); ++i) {
            result_array[i] = static_cast<std::uint8_t>(data[i]);
        }
        return result_array;
    }();
    static_assert(kOpcodes.size() == (kOpcodesCount + kBinOffset), "opcodes.bin must contain exactly kOpcodesCount bytes");

    using Opcode = std::uint8_t;
    [[nodiscard]] consteval Opcode opcode(const OpcodeIndex index) noexcept {
        // no bounds check because we know what we are doing right
        const auto value = kOpcodes[std::to_underlying(index) + kBinOffset];
        if constexpr (std::is_same_v<Opcode, std::remove_cv_t<decltype(value)>>) {
            return value;
        } else {
            return static_cast<Opcode>(value);
        }
    }
} // namespace vm
