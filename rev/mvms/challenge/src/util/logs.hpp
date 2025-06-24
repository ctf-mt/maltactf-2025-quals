#pragma once
#include <format>
#include <iostream>
#include <source_location>
#include <string>

/// some parts are from https://github.com/es3n1n/common/blob/master/include/es3n1n/common/logger.hpp

template <typename... Args>
void debugln(const std::format_string<Args...> fmt, Args... args) noexcept {
#if defined(_DEBUG)
    std::cout << "dbg: " << std::vformat(fmt.get(), std::make_format_args(args...)) << std::endl;
#endif
}

template <typename... Args>
void infoln(const std::format_string<Args...> fmt, Args... args) noexcept {
    std::cout << "inf: " << std::vformat(fmt.get(), std::make_format_args(args...)) << std::endl;
}

struct ErrorMaker {
#if defined(_DEBUG)
    std::source_location location;
#else
    std::size_t line;
#endif

    template <typename... Args>
    [[nodiscard]] std::string operator()(const std::format_string<Args...> fmt, //
                                         Args... args) const {
#if defined(_DEBUG)
        return std::format("{}:{}: {}", location.file_name(), location.line(), std::vformat(fmt.get(), std::make_format_args(args...)));
#else
        return std::format("{}: {}", line, std::vformat(fmt.get(), std::make_format_args(args...)));
#endif
    }
};

[[nodiscard]] inline ErrorMaker error_message(const std::source_location loc = std::source_location::current()) {
#if defined(_DEBUG)
    return ErrorMaker{loc};
#else
    return ErrorMaker{loc.line()};
#endif
}
