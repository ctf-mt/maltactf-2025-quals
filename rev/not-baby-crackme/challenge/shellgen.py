from pwn import asm
from numpy import uint64, uint8
from random import choice, randint, seed, getrandbits, shuffle

seed(0x7407ebe90560ff92)

shellcode_decls = []
faker_decls = []


def r8_reproducible() -> int:
    return getrandbits(8)


def r64_reproducible() -> int:
    return getrandbits(64)


def compile_shit(n: int, code: str, replacements: list[tuple[int, int]]) -> None:
    result = bytearray(asm(code, arch='amd64', os='linux', vma=0))
    assert len(result) < 0x5000

    key = uint8(r8_reproducible())
    orig_key = key

    tgt_indices = [result.index(x[0].to_bytes(8, 'little')) for x in replacements]
    replace_vals = [bytearray(x[1].to_bytes(8, 'little')) for x in replacements]

    # for i in range(len(result)):
    #     result[i] ^= int(key)
    #     for index_index, tgt_index in enumerate(tgt_indices):
    #         if tgt_index < i < tgt_index + 8:
    #             replace_vals[index_index][i - tgt_index] ^= int(key)
    #
    #     key = key + uint8(1)

    serialized_result = ', '.join([
        hex(x) for x in result
    ])
    shellcode_decls.append(f'inline constinit Shellcode<{hex(orig_key)}, {serialized_result}> Shellcode_{n} = {{}};')

    for index, val, mmm in zip(tgt_indices, replace_vals, replacements):
        faker_decls.append(f'faker.hidden_write(shellcodes[{n}] + {index}, {hex(int.from_bytes(val, "little"))})  # decrypts to {hex(mmm[1])}')


def _make_shellcode(n: int, rax: int, code: str) -> int:
    rax = uint64(rax)
    fake_vals: list[tuple[int, int]] = []
    for i in range(randint(1024, 1124)):
        imm = r64_reproducible()
        imm_fake = None

        # somewhere in the middle where people dont really look
        if 256 < i <= 512 and choice([True, False, False, False]):
            imm_fake = r64_reproducible()

        op = 'xor'
        op_n = randint(1, 3)
        if op_n == 1:
            op = 'xor'
            rax ^= uint64(imm)
        elif op_n == 2:
            op = 'sub'
            rax -= uint64(imm)
        elif op_n == 3:
            op = 'add'
            rax += uint64(imm)

        code += f'\nmov rsi, {hex(imm_fake if imm_fake is not None else imm)}'
        code += f'\n{op} rax, rsi'

        if imm_fake is not None:
            fake_vals.append((imm_fake, imm))

    code += '\nret'
    compile_shit(n, code, fake_vals)
    return rax


def make_shellcode_type_1(n: int) -> int:
    code = '''mov rax, 0x65
xor rdi, rdi
xor rsi, rsi
xor rdx, rdx
xor r10, r10
syscall
'''
    return _make_shellcode(n, 0, code)


def make_shellcode_type_2(n: int) -> int:
    code = '''mov eax, 0xFFFFFFFF
mov rdi, 0x402356
.loop:
cmp rdi, 0x40359B
jae .done
xor dl, dl
mov dl, al
xor dl, byte [rdi]
shr eax, 8
movzx edx, dl
lea rcx, [0x4070C0]
xor eax, dword [rcx + rdx * 4]
inc rdi
jmp .loop
.done:
not eax
'''
    return _make_shellcode(n, 0x00000000E609EFE8, code)


def main() -> None:
    values = [
        0xf47c61a63969ce39,
        0x8015f0598d213a0b,
        0x5c6736fb75964166, 0xc2bff7bcee3295a7, 0xd5a5aab751607595,
        0xc8608e7d47eb3782, 0x9e3f0c8488a06f9e, 0xd70e965f8c17097c,
    ]
    xor_seeds = []

    queue = ([make_shellcode_type_2] * (len(values) - 1)) + [make_shellcode_type_1]
    shuffle(queue)

    for i in range(len(queue)):
        cbk = queue[i]
        evaluated = int(cbk(i))
        xor_seeds.append(int(values[i]) ^ evaluated)
        print(i, cbk.__name__, 'evaluated:', hex(evaluated))

    print()
    print('\n'.join(shellcode_decls))
    print()
    print('{', end=' ')
    print(', '.join([hex(x) for x in xor_seeds]), end=' ')
    print('}')
    print()
    shuffle(faker_decls)
    print('\n'.join(faker_decls))


if __name__ == '__main__':
    main()
