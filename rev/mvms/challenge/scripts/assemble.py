#!/usr/bin/env python3.12
import subprocess
from collections import defaultdict
from collections.abc import Callable
from os import environ, urandom
from pathlib import Path
from random import choice, getrandbits, randint, shuffle
from shutil import which
from sys import argv
from time import time

from vm_lib import Program, allocate_registers, endianness, root_dir, vm_init


SEED = 0x25C4DD42D3E71E03
FLAG = (root_dir / 'flag.jpg').read_bytes()
OUT_DIR = root_dir / 'out'
BUILD_DIR = root_dir / 'cmake-build-release'
LINKER_LD_PATH = root_dir / 'linker.ld'
BUILT_BIN_PATH = BUILD_DIR / 'chall'
C_COMPILER = which('clang-19') or which('clang-20') or which('clang')
CXX_COMPILER = which('clang++-19') or which('clang++-20') or which('clang++')
CMAKE_GENERATOR = 'Ninja'
GENERATOR_PATH = which('ninja')
LD_SHUFFLER = '--ld-shuffler' in argv
generators = []

_128_BIT_MAX = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF


if not C_COMPILER or not CXX_COMPILER:
    toolchains_msg = 'C/C++ compilers not found! Please install clang-19 or clang-20 and ninja.'
    toolchains_msg += f'\n{C_COMPILER=}, {CXX_COMPILER=}'
    raise RuntimeError(toolchains_msg)


if not GENERATOR_PATH:
    CMAKE_GENERATOR = 'Unix Makefiles'
    GENERATOR_PATH = which('make')

if not GENERATOR_PATH:
    generator_msg = 'CMake generator not found! Please install ninja or make.'
    generator_msg += f'\n{GENERATOR_PATH=}'
    raise RuntimeError(generator_msg)


environ['CC'] = C_COMPILER
environ['CXX'] = CXX_COMPILER


def generator() -> Callable[[Callable[[Program, int], None]], Callable[[Program, int], None]]:
    def decorator(func: Callable[[Program, int], None]) -> Callable[[Program, int], None]:
        generators.append(func)
        return func

    return decorator


def _println(prog: Program, reg: int, message: bytes) -> None:
    prog.load_auto(reg, int.from_bytes(message, endianness))
    prog.push_r(reg)
    prog.println()


def _load_flag_to(prog: Program, reg: int) -> None:
    _println(prog, reg, b'flag?')
    prog.read(reg)


def _print_bad(prog: Program, reg: int) -> None:
    _println(prog, reg, b'bad')


def _print_good(prog: Program, reg: int) -> None:
    _println(prog, reg, b'good')


def _jz_good_bad(prog: Program, reg: int) -> None:
    # if (r0 == 0) jmp good
    prog.jz(reg, 13)

    # bad:
    _print_bad(prog, reg)
    prog.stop()

    # good:
    _print_good(prog, reg)
    prog.stop()


def _cmp_result(prog: Program, flag_reg: int, expected: int) -> None:
    r = flag_reg
    while r == flag_reg:
        r = allocate_registers(1)[0]
    _junk(prog)
    _load_const(prog, r, expected)
    _do_on_stack_or(prog, flag_reg, flag_reg, r, prog.sub, prog.sub_stk)
    _junk(prog)
    _jz_good_bad(prog, flag_reg)


def _junk(prog: Program) -> None:  # noqa: C901
    if not choice([True, False]):
        return

    def _nop() -> None:
        if choice([True, False]):
            prog.nop()

    def insert(cb: Callable[[], Program]) -> None:
        _nop()
        cb()
        _nop()

    n = randint(1, 4)
    if n == 1:
        _nop()
    elif n == 2:
        rr = allocate_registers(1)[0]
        insert(lambda: prog.push_r(rr))
        insert(lambda: prog.pop_r(rr))
    elif n == 3:
        rr = allocate_registers(1)[0]
        insert(lambda: prog.push_r(rr))

        insert(
            lambda: prog.load_auto(
                rr,
                choice(
                    [
                        getrandbits(8),
                        getrandbits(16),
                        getrandbits(32),
                        getrandbits(64),
                        getrandbits(128),
                    ]
                ),
            )
        )
        insert(lambda: prog.pop_r(rr))
    elif n == 4:
        rr1, rr2 = allocate_registers(2)
        insert(lambda: prog.push_r(rr1))
        insert(lambda: prog.push_r(rr2))
        insert(lambda: prog.load_auto(rr1, getrandbits(128)))
        insert(lambda: prog.load_auto(rr2, getrandbits(128)))
        insert(lambda: prog.add(rr1, rr1, rr2))
        if choice([True, False]):
            insert(lambda: prog.sub(rr1, rr1, rr2))
        if choice([True, False]):
            insert(lambda: prog.xor(rr1, rr1, rr2))
        insert(lambda: prog.pop_r(rr2))
        insert(lambda: prog.pop_r(rr1))


def _do_on_stack_or(
    prog: Program,
    out_r: int,
    r1: int,
    r2: int,
    non_stk: Callable[[int, int, int], Program],
    stk: Callable[[], Program],
) -> None:
    if choice([True, False]):
        non_stk(out_r, r1, r2)
        return

    order = [r1, r2]
    shuffle(order)
    [prog.push_r(x) for x in order]
    stk()
    prog.pop_r(out_r)


def _load_const(
    prog: Program,
    reg: int,
    value: int,
) -> None:
    if not choice([True, False]):
        prog.load_auto(reg, value)
        return

    if value < 256:
        imm = getrandbits(8)
    elif value < 2**32:
        imm = getrandbits(32)
    elif value < 2**64:
        imm = getrandbits(64)
    else:
        imm = getrandbits(128)

    prog.load_auto(reg, value ^ imm)
    prog.push_r(reg)
    prog.load_auto(reg, imm)
    prog.push_r(reg)
    prog.xor_stk()
    prog.pop_r(reg)


def ror(n: int, c: int, bits: int = 64) -> int:
    mask = (1 << bits) - 1
    return ((n >> c) | (n << (bits - c))) & mask


def rol(n: int, c: int, bits: int = 64) -> int:
    return ror(n, bits - c, bits)


@generator()
def variant_1(prog: Program, expected: int) -> None:
    flag, r2 = allocate_registers(2)
    _load_flag_to(prog, flag)
    _junk(prog)

    imm = getrandbits(128)
    _load_const(prog, r2, imm)
    if choice([True, False]):
        _do_on_stack_or(prog, flag, flag, r2, prog.xor, prog.xor_stk)
        expected ^= imm
    else:
        _do_on_stack_or(prog, flag, flag, r2, prog.add, prog.add_stk)
        expected = (expected + imm) & _128_BIT_MAX

    imm = getrandbits(128)
    _load_const(prog, r2, imm)
    _do_on_stack_or(prog, flag, flag, r2, prog.xor, prog.xor_stk)
    expected ^= imm

    _cmp_result(prog, flag, expected)


@generator()
def variant_2(prog: Program, expected: int) -> None:
    flag, r2 = allocate_registers(2)
    _load_flag_to(prog, flag)
    _junk(prog)

    imm = getrandbits(128)
    _load_const(prog, r2, imm)
    _do_on_stack_or(prog, flag, flag, r2, prog.xor, prog.xor_stk)
    expected ^= imm

    _cmp_result(prog, flag, expected)


def sh(*args: str) -> tuple[str | None, str | None]:
    raw_cmd = ' '.join(args)
    if len(raw_cmd) > 105:
        raw_cmd = raw_cmd[:105] + '...'

    print(f'\t+ {raw_cmd}')
    proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=Path(__file__).parent)
    stdout, stderr = proc.communicate()
    proc.terminate()
    return stdout.decode() if stdout else None, stderr.decode() if stderr else None


def test_bin(path: Path, expected_input: bytes) -> None:
    def test_with(inp: bytes) -> str:
        proc = subprocess.Popen(
            [str(path.absolute())], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE, cwd=root_dir
        )
        stdout, stderr = proc.communicate(input=inp)
        proc.terminate()
        return stdout.decode()

    bad_input = urandom(16)
    bad_res = test_with(bad_input)
    if bad_res != 'flag?\nbad\n':
        err_msg = f'Bad input handling failed: {bad_input!r}, got {bad_res!r}'
        raise RuntimeError(err_msg)

    expected_res = test_with(expected_input)
    if expected_res != 'flag?\ngood\n':
        err_msg = f'Expected input handling failed: {expected_input!r}, got {expected_res!r}'
        raise RuntimeError(err_msg)


def clean_artifacts(path: Path) -> None:
    if not path.exists():
        return

    for x in path.iterdir():
        if x.is_dir():
            clean_artifacts(x)
            continue

        x.unlink()


def chunks(line: bytes, n: int) -> list[bytes]:
    return [line[i : i + n] for i in range(0, len(line), n)]


def main() -> None:
    global SEED
    counts: defaultdict[str, int] = defaultdict(int)

    if OUT_DIR.exists():
        for file in OUT_DIR.iterdir():
            file.unlink()

        OUT_DIR.rmdir()
    OUT_DIR.mkdir(parents=True)

    batches = chunks(FLAG, 16)

    start = time()
    for i, chunk in enumerate(batches):
        vm_init(SEED)
        gen = choice(generators)

        print(f'{i + 1:>5}/{len(batches)}: generating, seed={hex(SEED)}, generator={gen.__name__}, chunk={chunk!r}')

        prog = Program()
        gen(prog, int.from_bytes(chunk, endianness))
        prog.dump_to_file()

        if LINKER_LD_PATH.exists():
            LINKER_LD_PATH.unlink()

        clean_artifacts(BUILD_DIR / 'CMakeFiles' / 'chall.dir')
        stdout, stderr = sh(
            'cmake',
            '-B',
            str(BUILD_DIR),
            '-S',
            str(root_dir),
            '-DCMAKE_BUILD_TYPE=Release',
            '--fresh',
            '-G',
            CMAKE_GENERATOR,
            f'-DCMAKE_C_COMPILER={C_COMPILER}',
            f'-DCMAKE_CXX_COMPILER={CXX_COMPILER}',
            f'-DCMAKE_MAKE_PROGRAM={GENERATOR_PATH}',
            f'-DLD_SHUFFLER={"ON" if LD_SHUFFLER else "OFF"}',
        )
        if stderr and '-- Configuring done (' not in (stdout or ''):
            msg = f'Configuration failed: {stderr!r}, {stdout!r}'
            raise RuntimeError(msg)

        stdout, stderr = sh('cmake', '--build', str(BUILD_DIR), '--target', 'chall', '--parallel')
        if stderr and stderr != '/usr/bin/ld: warning: .note.gnu.build-id section discarded, --build-id ignored\n':
            msg = f'Build failed: {stderr!r}, {stdout!r}'
            raise RuntimeError(msg)

        if not BUILT_BIN_PATH.exists():
            msg = f'Binary not found after build: {BUILT_BIN_PATH!s}'
            raise RuntimeError(msg)

        stdout, stderr = sh('strip', str(BUILT_BIN_PATH))
        if stderr:
            msg = f'Stripping failed: {stderr!r}, {stdout!r}'
            raise RuntimeError(msg)

        test_bin(BUILT_BIN_PATH, chunk)

        (OUT_DIR / f'{i + 1:08d}').write_bytes(BUILT_BIN_PATH.read_bytes())
        BUILT_BIN_PATH.unlink()

        counts[gen.__name__] += 1
        SEED = getrandbits(64)

    end = time()
    print('\ndone!')
    print(f'took {end - start:.2f} seconds')
    print('generators distribution:')
    for gen in generators:
        count = counts[gen.__name__]
        total = sum(counts.values())
        percentage = (count / total) * 100 if total else 0
        print(f'\t{gen.__name__}: {count} ({percentage:.2f}%)')


if __name__ == '__main__':
    if not LD_SHUFFLER:
        print('!!! LD_SHUFFLER is not enabled, but it should be for production')
    main()
