from io import BytesIO
from pathlib import Path
from typing import TYPE_CHECKING

import z3  # type: ignore[import-untyped]
from capstone import CS_ARCH_X86, CS_MODE_64, Cs, CsInsn  # type: ignore[import-untyped]
from capstone.x86_const import (  # type: ignore[import-untyped]
    X86_OP_IMM,
    X86_OP_REG,
    X86_REG_EDX,
    X86_REG_R13,
    X86_REG_R14,
    X86_REG_R15,
    X86_REG_RAX,
    X86_REG_RBP,
    X86_REG_RDI,
    X86_REG_RDX,
)
from elftools.elf.elffile import ELFFile
from tqdm import tqdm


if TYPE_CHECKING:
    from capstone.x86 import X86Op  # type: ignore[import-untyped]
    from elftools.elf.sections import Section

binaries_dir = Path(__file__).parents[1] / 'attachments' / 'rev_mvms'


def rel32(data: bytes, addr: int, offset: int) -> int:
    base = addr + offset
    displacement = int.from_bytes(data[base : base + 4], 'little')
    return base + displacement + 4


class SigScanner:
    def __init__(self, pattern: str) -> None:
        self.sig_data = self.load_pattern(pattern)
        self.start_offset: int = 0

    def load_pattern(self, pattern: str) -> list[list[int] | bytearray]:
        def parse_pattern(_signature: str) -> list[int]:
            return [int(x, base=16) if '?' not in x else -1 for x in _signature.split(' ')]

        pattern_data: list[int] = parse_pattern(pattern)

        sig_data: list[list[int] | bytearray] = []
        cur_item: list[int] | bytearray | None = None

        for byte_val in pattern_data:
            is_unk: bool = byte_val == -1

            if (
                (not cur_item)
                or (is_unk and not isinstance(cur_item, list))
                or (not is_unk and not isinstance(cur_item, bytearray))
            ):
                if cur_item is not None:
                    sig_data.append(cur_item)
                cur_item = [] if is_unk else bytearray()

            cur_item.append(byte_val)

        if cur_item:
            sig_data.append(cur_item)

        while sig_data and isinstance(sig_data[0], list):
            self.start_offset += len(sig_data.pop(0))

        while sig_data and isinstance(sig_data[-1], list):
            sig_data.pop()

        return sig_data

    def find(self, image_data: bytes) -> list[int]:
        if not self.sig_data:
            return []

        found_offsets: list[int] = []
        search_offset: int = 0
        end: int = len(image_data)

        first_chunk = self.sig_data[0]

        while True:
            match_offset = image_data.find(first_chunk, search_offset, end)  # type: ignore[arg-type]
            if match_offset == -1:
                break

            is_full_match = True
            current_offset = match_offset + len(first_chunk)

            for i in range(1, len(self.sig_data)):
                chunk = self.sig_data[i]

                if isinstance(chunk, list):
                    current_offset += len(chunk)
                    continue

                chunk_len = len(chunk)
                if image_data[current_offset : current_offset + chunk_len] != chunk:
                    is_full_match = False
                    break

                current_offset += chunk_len

            if is_full_match:
                found_offsets.append(match_offset - self.start_offset)

            search_offset = match_offset + 1

        return found_offsets


class Bytecode:
    def __init__(self, bytecode: bytes) -> None:
        self.data = bytecode
        self.pos = 4

    @property
    def available(self) -> bool:
        return self.pos < len(self.data)

    def u8(self) -> int:
        value = self.data[self.pos]
        self.pos += 1
        return value

    def u16(self) -> int:
        value = int.from_bytes(self.data[self.pos : self.pos + 2], 'little')
        self.pos += 2
        return value

    def u32(self) -> int:
        value = int.from_bytes(self.data[self.pos : self.pos + 4], 'little')
        self.pos += 4
        return value

    def u64(self) -> int:
        value = int.from_bytes(self.data[self.pos : self.pos + 8], 'little')
        self.pos += 8
        return value

    def u128(self) -> int:
        value = int.from_bytes(self.data[self.pos : self.pos + 16], 'little')
        self.pos += 16
        return value


def _find_all(data: bytes, pattern: str) -> list[int]:
    s = SigScanner(pattern)
    return s.find(data)


def _find(data: bytes, pattern: str, *, allow_many: bool = False) -> int:
    found = _find_all(data, pattern)
    if len(found) != 1:
        if found and allow_many:
            return found[0]

        msg = f'Pattern {pattern} not found in data or found too many {len(found)=}'
        raise ValueError(msg)
    return found[0]


def recover_vm_jump_table(  # noqa: C901
    text_addr: int,
    text: bytes,
    rodata_addr: int,
    rodata: bytes,
    table_off: int,
    table_end: int,
) -> list[int]:
    seq = list(range(0x100))
    jt_data = []
    for i in range(0, table_end - table_off, 4):
        value = int.from_bytes(rodata[table_off + i : table_off + i + 4], 'little')
        jt_data.append(value)

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    op_move = _find(text, '42 0F B6 14 38')
    max_size = None
    for insn in md.disasm(text[op_move + 5 :], text_addr + op_move):
        first_op: X86Op = insn.operands[0]

        if insn.reg_name(first_op.reg) not in {'edx', 'rdx'}:
            continue

        if insn.mnemonic == 'cmp':
            max_size = insn.operands[1].imm
            break
        if insn.mnemonic == 'add':
            seq = [(x + insn.operands[1].imm) & 0xFFFFFFFF for x in seq]
        elif insn.mnemonic == 'dec':
            seq = [(x - 1) & 0xFFFFFFFF for x in seq]
        elif insn.mnemonic == 'movsxd':
            break
        else:
            raise ValueError(insn.mnemonic, str(insn))

    result = []
    for i in range(len(seq)):
        try:
            jt_mm = jt_data[seq[i]]
        except IndexError:
            result.append(0)
            continue

        result.append((jt_mm + rodata_addr + table_off - text_addr) & 0xFFFFFFFF)

        if max_size is not None and seq[i] >= max_size:
            break

    return result


def match_regs(insn: CsInsn, regs_possible: list[list[int]]) -> bool:
    for combination in regs_possible:
        matches = True

        for i, reg_v in enumerate(combination):
            operand: X86Op = insn.operands[i]
            matches = matches and operand.type == X86_OP_REG and operand.reg == reg_v

        if matches:
            return True
    return False


def dyn_match(text_addr: int, text: bytes, offset: int) -> str | None:  # noqa: PLR0912, C901
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    jumps_count = 0
    while True:
        insns: list[CsInsn] = list(md.disasm(text[offset:], text_addr + offset, count=3))
        insn: CsInsn = insns[0]

        if insn.mnemonic == 'jmp':
            op: X86Op = insn.operands[0]
            if op.type != X86_OP_IMM:
                break

            offset = insn.operands[0].imm - text_addr
            jumps_count += 1

            if jumps_count >= 5:
                break
            continue

        if insn.mnemonic == 'xor' and match_regs(
            insn,
            [
                [X86_REG_R13, X86_REG_RAX],
                [X86_REG_R13, X86_REG_R15],
            ],
        ):
            if insns[1].mnemonic == 'xor' and match_regs(
                insns[1],
                [
                    [X86_REG_RBP, X86_REG_R15],
                    [X86_REG_RBP],  # second op is qword ptr [rsp+98h+var_68]
                ],
            ):
                return 'xor_stk'

        if insn.mnemonic == 'sub' and match_regs(
            insn,
            [
                [X86_REG_R14, X86_REG_R13],
            ],
        ):
            if insns[1].mnemonic == 'sbb' and match_regs(
                insns[1],
                [
                    [X86_REG_R15, X86_REG_RDX],
                ],
            ):
                return 'sub_stk'

        if insn.mnemonic == 'add' and match_regs(
            insn,
            [
                [X86_REG_R13, X86_REG_RAX],
                [X86_REG_R13, X86_REG_R15],
            ],
        ):
            if insns[1].mnemonic == 'adc' and match_regs(
                insns[1],
                [
                    [X86_REG_RBP, X86_REG_R15],
                    [X86_REG_RBP],  # second op is qword ptr [rsp+88h+var_58]
                ],
            ):
                return 'add_stk'

        if insn.mnemonic == 'mov' and match_regs(
            insn,
            [
                [X86_REG_RDI, X86_REG_R14],
            ],
        ):
            if insns[1].mnemonic == 'call':
                if insns[2].mnemonic == 'mov' and match_regs(insn, [[X86_REG_RDI]]):
                    return 'println'

        if insn.mnemonic == 'mov' and match_regs(
            insn,
            [
                [X86_REG_RDI],  # second op is cs:_ZNSt3__13cinE_ptr
            ],
        ):
            if (
                insns[1].mnemonic == 'mov'
                and match_regs(
                    insns[1],
                    [
                        [X86_REG_EDX],
                    ],
                )
                and insns[1].operands[1].type == X86_OP_IMM
                and insns[1].operands[1].imm == 0x10
            ):
                if insns[2].mnemonic == 'call':
                    return 'read'

        offset += insn.size

    return None


def resolve_handlers(text_addr: int, text_data: bytes, jump_table: list[int]) -> dict[int, str]:
    result: dict[int, str] = {}

    def handler(name: str, patterns: list[str], off: int = 0, *, allow_fail: bool = False) -> int:
        p_off = None
        r_i = 0
        for i, pattern in enumerate(patterns):
            try:
                p_off = _find(text_data, pattern)
            except ValueError:
                continue
            r_i = i
            break

        if not p_off:
            if allow_fail:
                return -1
            err_msg = f'Patterns {patterns} not found'
            raise ValueError(err_msg)

        va = text_addr + p_off + off
        result[jump_table.index(va)] = name
        return r_i

    handler('load_64', ['42 0F B6 4C 38 01 4A 8B 54 38 02'])
    handler('push_r', ['42 0F B6 4C 38 01 48 83 C0 02'])
    handler('load_128', ['42 0F B6 4C 38 01 42 0F 10 44 38 02'])
    handler(
        'add',
        [
            '42 0F B6 4C 38 03 C1 E1 10 42 0F B7 54 38 01 48 83 C0 04 48 89 43 08 89 D0 C1 E8 04 83 E0 F0 C1 E9 0C 49 '
            '8B 34 0C 49 03 34 04'
        ],
    )
    handler(
        'xor',
        [
            '42 0F B6 4C 38 03 C1 E1 10 42 0F B7 54 38 01 48 83 C0 04 48 89 43 08 89 D0 C1 E8 04 83 E0 F0 C1 E9 0C 49 '
            '8B 34 0C 49 8B 4C 0C 08 49 33 4C 04 08'
        ],
    )
    handler('pop_r', ['46 0F B6 74 38 01 48 83 C0 02 48 89 43 08 48 8B'])
    handler(
        'sub', ['42 0F B6 4C 38 ? C1 E1 ? 42 0F B7 54 38 ? 48 83 C0 ? 48 89 43 ? 89 D0 C1 E8 ? 83 E0 ? ? ? ? ? C1 E9']
    )
    handler(
        'jz',
        [
            '42 0F B7 4C 38 ? 48 8D 50 ? 48 89 53 ? 0F B6 D1 C1 E2 ? ? ? ? ? 49 0B 74 14 ? 0F 85 ? ? ? ? C1 E9',
            '42 0F B7 4C 38 ? 48 8D 50 ? 48 89 53 ? 0F B6 D1 C1 E2 ? ? ? ? ? 49 0B 74 14 ? 0F 85',
            '42 0F B7 4C 38 ? 48 8D 50 ? 48 89 53 ? 0F B6 D1 C1 E2 ? ? ? ? ? 49 0B 74 14 ? 75',
            '42 0F B7 4C 38 ? 48 8D 50 ? 48 89 53 ? 0F B6 D1 C1 E2 ? ? ? ? ? 49 0B 74 14 ? 75 ? C1 E9',
        ],
    )
    handler('load_32', ['42 0F B6 4C 38 ? 4A 63 54 38'])
    handler(
        'stop',
        [
            'C6 03 00 E9',
            'C6 03 00 EB',
        ],
    )

    occs = _find_all(text_data, '48 8B 43 ? 48 8B')
    occs.extend(_find_all(text_data, '46 0F ?? ?? ?? ?? 48 ?? ?? ?? 48'))
    for occ in occs:
        va = text_addr + occ
        try:
            opcode = jump_table.index(va)
        except ValueError:
            continue

        name = dyn_match(text_addr, text_data, occ)
        if not name:
            continue

        result[opcode] = name

    nf = [n for n in ('xor_stk', 'sub_stk', 'println', 'add_stk', 'read') if n not in result.values()]
    if nf:
        msg = f'dyn search for {nf} has failed'
        raise ValueError(msg)

    handler('nop', ['48 89 C8 48 83 F9', '48 89 C8 48 81 F9'])
    handler('load_8', ['42 0F B7 4C 38 ? 48 83 C0'])
    return result


def disassemble(bin_path: Path) -> list[tuple]:  # noqa: PLR0915, C901, PLR0912
    f = ELFFile(BytesIO(bin_path.read_bytes()))

    text: Section = f.get_section_by_name('.text')
    text_addr = text['sh_addr']
    text_data = text.data()

    rodata: Section = f.get_section_by_name('.rodata')
    rodata_addr = rodata['sh_addr']
    rodata_data = rodata.data()

    bytecode_mov = _find(text_data, '4C 8D 3D', allow_many=True)
    bytecode_start = text_addr + rel32(text_data, bytecode_mov, 3)
    bytecode_end = rodata_addr + rodata['sh_size'] - 0x4A

    try:
        jump_table_mov = _find(text_data, '4C 8D 2D', allow_many=True)
    except ValueError:
        jump_table_mov = _find(text_data, '4C 8D 35', allow_many=True)
    jump_table_addr = text_addr + rel32(text_data, jump_table_mov, 3)

    jump_table = [
        text_addr + x
        for x in recover_vm_jump_table(
            text_addr,
            text_data,
            rodata_addr,
            rodata_data,
            jump_table_addr - rodata_addr,
            bytecode_start - rodata_addr,
        )
    ]
    handlers = resolve_handlers(text_addr, text_data, jump_table)

    bytecode = Bytecode(rodata_data[bytecode_start - rodata_addr : bytecode_end - rodata_addr + 1])
    disassembled: list[tuple] = []
    while bytecode.available:
        opcode = bytecode.u8()
        handler = handlers.get(opcode)

        if not handler:
            msg = f'Unknown opcode {hex(opcode)} at position {hex(bytecode.pos)}'
            raise ValueError(msg)

        if handler in {'load_64'}:
            disassembled.append((handler.upper(), bytecode.u8(), bytecode.u64()))
        elif handler in {'push_r', 'read', 'pop_r'}:
            disassembled.append((handler.upper(), bytecode.u8()))
        elif handler in {'println', 'nop', 'stop', 'xor_stk', 'sub_stk', 'add_stk'}:
            disassembled.append((handler.upper(),))
        elif handler in {'load_128'}:
            disassembled.append((handler.upper(), bytecode.u8(), bytecode.u128()))
        elif handler in {'add', 'xor', 'sub'}:
            disassembled.append((handler.upper(), bytecode.u8(), bytecode.u8(), bytecode.u8()))
        elif handler in {'jz', 'load_8'}:
            disassembled.append((handler.upper(), bytecode.u8(), bytecode.u8()))
        elif handler in {'load_32'}:
            disassembled.append((handler.upper(), bytecode.u8(), bytecode.u32()))
        else:
            err_msg = f'unsupported handler: {handler}'
            raise ValueError(err_msg)

    return disassembled


def solve(bin_path: Path) -> bytes:
    disassembled = disassemble(bin_path)[:-8]

    flag_var = z3.BitVec('flag', 128)
    flag_reg = disassembled[0][1]
    disassembled = disassembled[4:]

    stack = []
    registers_state = [z3.BitVecVal(0, 128) for _ in range(6)]
    registers_state[flag_reg] = flag_var

    for insn in disassembled:
        if insn[0] == 'PUSH_R':
            stack.append(registers_state[insn[1]])
        elif insn[0] == 'POP_R':
            registers_state[insn[1]] = stack.pop()
        elif insn[0] in ('LOAD_128', 'LOAD_64', 'LOAD_32', 'LOAD_8'):
            registers_state[insn[1]] = z3.BitVecVal(insn[2], 128)
        elif insn[0] == 'ADD':
            registers_state[insn[1]] = registers_state[insn[2]] + registers_state[insn[3]]
        elif insn[0] == 'XOR':
            registers_state[insn[1]] = registers_state[insn[2]] ^ registers_state[insn[3]]
        elif insn[0] == 'SUB':
            registers_state[insn[1]] = registers_state[insn[2]] - registers_state[insn[3]]
        elif insn[0] == 'ADD_STK':
            lhs = stack.pop()
            rhs = stack.pop()
            stack.append(lhs + rhs)
        elif insn[0] == 'XOR_STK':
            lhs = stack.pop()
            rhs = stack.pop()
            stack.append(lhs ^ rhs)
        elif insn[0] == 'SUB_STK':
            lhs = stack.pop()
            rhs = stack.pop()
            stack.append(lhs - rhs)
        elif insn[0] == 'JZ':
            break
        elif insn[0] == 'NOP':
            continue
        else:
            msg = f'Unsupported instruction: {insn}'
            raise ValueError(msg)

    s = z3.Solver()
    s.add(registers_state[flag_reg] == 0)
    if s.check() != z3.sat:
        err_msg = f'unsat/unknown: {registers_state[flag_reg]}'
        raise ValueError(err_msg)
    m = s.model()

    return m.eval(flag_var).as_long().to_bytes(16, 'little')


if __name__ == '__main__':
    result = bytearray()

    for bin_path in tqdm(sorted(binaries_dir.iterdir(), key=lambda x: x.name)):
        if bin_path.suffix:
            continue

        result.extend(solve(bin_path))

    (Path(__file__).parent / 'solution.jpg').write_bytes(result)
