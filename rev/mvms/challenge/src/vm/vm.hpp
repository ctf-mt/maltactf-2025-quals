#pragma once
#include "vm/opcodes.hpp"
#include "vm/program.hpp"

#include "util/logs.hpp"
#include "util/macros.hpp" /* for enable_exceptions */

#include <span>
#include <vector>

namespace vm {
    constexpr std::size_t kNumRegisters = 6;
    /// \todo @es3n1n: This should be using __m128
    struct Register {
        union {
            std::uint8_t u8[16];
            std::uint16_t u16[8];
            std::uint32_t u32[4];
            std::uint64_t u64[2];
            __int128_t i128;
            __uint128_t u128 = {};
        };

        constexpr Register() = default;
        /* implicit */ Register(const std::int32_t value): i128(value) { }
        /* implicit */ Register(const std::uint32_t value): u128(value) { }
        /* implicit */ Register(const std::int64_t value): i128(value) { }
        /* implicit */ Register(const std::uint64_t value): u128(value) { }
        /* implicit */ Register(const __int128_t i): i128(i) { }
        /* implicit */ Register(const __uint128_t u): u128(u) { }
    };
    static_assert(sizeof(Register) == sizeof(__int128));

    class VM {
    public:
        VM() = default;
        void run();

    private:
        bool running_ = true;
        std::size_t pc_ = kBinOffset;
        std::array<Register, kNumRegisters> registers_{}; // all zero‐initialized
        std::vector<std::byte> stack_;

        [[nodiscard]] static constexpr bool valid_reg(const std::uint8_t r) noexcept {
            return (r < kNumRegisters);
        }

        template <std::size_t N, typename Ty = std::uint8_t>
        [[nodiscard]] constexpr std::array<Ty, N> consume() {
#if defined(ENABLE_EXCEPTIONS)
            if (pc_ + (N * sizeof(Ty)) > kProgram.size()) {
                throw std::out_of_range(error_message()("Not enough bytes to consume: {} pc={} size={}", (N * sizeof(Ty)), pc_, kProgram.size()));
            }
#endif

            std::array<Ty, N> result;
            std::memcpy(result.data(), kProgram.data() + pc_, N * sizeof(Ty));
            pc_ += N * sizeof(Ty);
            return result;
        }

        [[nodiscard]] constexpr Register& reg(const std::size_t index) {
#if defined(ENABLE_EXCEPTIONS)
            if (!valid_reg(static_cast<std::uint8_t>(index))) {
                throw std::out_of_range(error_message()("Invalid register index: {}", index));
            }
#endif
            return registers_[index];
        }

        template <typename Ty>
        void push(Ty& arg) {
            stack_.append_range(std::as_bytes(std::span{&arg, 1}));
        }

        template <std::size_t N>
        [[nodiscard]] constexpr std::array<std::byte, N> pop() {
#if defined(ENABLE_EXCEPTIONS)
            if (stack_.size() < N) {
                throw std::out_of_range(error_message()("Not enough bytes on stack to pop: {} stack_size={}", N, stack_.size()));
            }
#endif

            std::array<std::byte, N> result;
            std::copy_n(stack_.end() - N, N, result.begin());
            stack_.resize(stack_.size() - N);
            return result;
        }

        template <typename Ty>
        [[nodiscard]] constexpr Ty pop_as() {
            const auto raw = pop<sizeof(Ty)>();
            Ty value;
            memcpy(&value, raw.data(), sizeof(Ty));
            return value;
        }

        void execute(Opcode opcode_value, std::size_t opcode_loc);
    };
} // namespace vm
