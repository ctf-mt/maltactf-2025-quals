#include "vm/vm.hpp"
#include <print>


#if defined(ENABLE_EXCEPTIONS)
int main() try {
#else
int main() {
#endif
    vm::VM vm;
    vm.run();
    return 0;
#if defined(ENABLE_EXCEPTIONS)
} catch (const std::exception& err) {
    std::println(stderr, "uh oh: {}", err.what());
    return 1;
#endif
}
