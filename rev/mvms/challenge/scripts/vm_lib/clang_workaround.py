# We are `#embed`ing our files, and they go through the clang's file parser that is used for source files.
# Because of that, this check is being run:
# https://github.com/llvm/llvm-project/blob/b58b3e1d36f12b3f320e574cd82eed4ff111c9bf/clang/lib/Basic/SourceManager.cpp#L171
#
# This workaround is to ensure that the file will always pass these checks (we add this prefix to files we produce).
# If we do not do that, and, for example, the file starts with a `\xFE\xFF` we will get a nice diag:
#   `fatal error: UTF-16 (BE) byte order mark detected in 'opcodes.bin', but encoding is not supported`
# This probably is a clang's bug, but it is not worth the effort to report it.
BIN_PREFIX = b'\x00\x00\x00\x00'
