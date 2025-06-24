from .clang_workaround import BIN_PREFIX
from .opcodes import OpcodeIndex, opcode
from .packing import p8, p8s, p32, p64, p128
from .paths import program_path


class Program:
    def __init__(self) -> None:
        self.bytecode = bytearray()

    @property
    def pos(self) -> int:
        return len(self.bytecode)

    def dump_to_file(self) -> None:
        program_path.write_bytes(BIN_PREFIX + bytes(self.bytecode))

    def write(self, *args: bytes) -> None:
        for arg in args:
            self.bytecode.extend(arg)

    def nop(self) -> 'Program':
        self.write(opcode(OpcodeIndex.NOP))
        return self

    def load(self, r: int, v: int) -> 'Program':
        self.write(opcode(OpcodeIndex.LOAD), p8(r), p8(v))
        return self

    def load_32(self, r: int, v: int) -> 'Program':
        self.write(opcode(OpcodeIndex.LOAD_32), p8(r), p32(v))
        return self

    def load_64(self, r: int, v: int) -> 'Program':
        self.write(opcode(OpcodeIndex.LOAD_64), p8(r), p64(v))
        return self

    def load_128(self, r: int, v: int) -> 'Program':
        self.write(opcode(OpcodeIndex.LOAD_128), p8(r), p128(v))
        return self

    def load_auto(self, r: int, v: int) -> 'Program':
        if v < 256:
            return self.load(r, v)
        if v < 2**32:
            return self.load_32(r, v)
        if v < 2**64:
            return self.load_64(r, v)
        return self.load_128(r, v)

    def add(self, rd: int, rs1: int, rs2: int) -> 'Program':
        self.write(opcode(OpcodeIndex.ADD), p8(rd), p8(rs1), p8(rs2))
        return self

    def sub(self, rd: int, rs1: int, rs2: int) -> 'Program':
        self.write(opcode(OpcodeIndex.SUB), p8(rd), p8(rs1), p8(rs2))
        return self

    def or_(self, rd: int, rs1: int, rs2: int) -> 'Program':
        self.write(opcode(OpcodeIndex.OR), p8(rd), p8(rs1), p8(rs2))
        return self

    def nor(self, rd: int, rs1: int, rs2: int) -> 'Program':
        self.write(opcode(OpcodeIndex.NOR), p8(rd), p8(rs1), p8(rs2))
        return self

    def rol(self, rd: int, rs1: int, rs2: int) -> 'Program':
        self.write(opcode(OpcodeIndex.ROL), p8(rd), p8(rs1), p8(rs2))
        return self

    def ror(self, rd: int, rs1: int, rs2: int) -> 'Program':
        self.write(opcode(OpcodeIndex.ROR), p8(rd), p8(rs1), p8(rs2))
        return self

    def and_(self, rd: int, rs1: int, rs2: int) -> 'Program':
        self.write(opcode(OpcodeIndex.AND), p8(rd), p8(rs1), p8(rs2))
        return self

    def mod(self, rd: int, rs1: int, rs2: int) -> 'Program':
        self.write(opcode(OpcodeIndex.MOD), p8(rd), p8(rs1), p8(rs2))
        return self

    def xor(self, rd: int, rs1: int, rs2: int) -> 'Program':
        self.write(opcode(OpcodeIndex.XOR), p8(rd), p8(rs1), p8(rs2))
        return self

    def mul(self, rd: int, rs1: int, rs2: int) -> 'Program':
        self.write(opcode(OpcodeIndex.MUL), p8(rd), p8(rs1), p8(rs2))
        return self

    def push_r(self, r: int) -> 'Program':
        self.write(opcode(OpcodeIndex.PUSH_R), p8(r))
        return self

    def pop_r(self, r: int) -> 'Program':
        self.write(opcode(OpcodeIndex.POP_R), p8(r))
        return self

    def add_stk(self) -> 'Program':
        self.write(opcode(OpcodeIndex.ADD_STK))
        return self

    def sub_stk(self) -> 'Program':
        self.write(opcode(OpcodeIndex.SUB_STK))
        return self

    def or_stk(self) -> 'Program':
        self.write(opcode(OpcodeIndex.OR_STK))
        return self

    def nor_stk(self) -> 'Program':
        self.write(opcode(OpcodeIndex.NOR_STK))
        return self

    def rol_stk(self) -> 'Program':
        self.write(opcode(OpcodeIndex.ROL_STK))
        return self

    def ror_stk(self) -> 'Program':
        self.write(opcode(OpcodeIndex.ROR_STK))
        return self

    def and_stk(self) -> 'Program':
        self.write(opcode(OpcodeIndex.AND_STK))
        return self

    def mod_stk(self) -> 'Program':
        self.write(opcode(OpcodeIndex.MOD_STK))
        return self

    def xor_stk(self) -> 'Program':
        self.write(opcode(OpcodeIndex.XOR_STK))
        return self

    def mul_stk(self) -> 'Program':
        self.write(opcode(OpcodeIndex.MUL_STK))
        return self

    def jz(self, reg: int, off: int) -> 'Program':
        self.write(opcode(OpcodeIndex.JZ), p8(reg), p8s(off))
        return self

    def jnz(self, reg: int, off: int) -> 'Program':
        self.write(opcode(OpcodeIndex.JNZ), p8(reg), p8s(off))
        return self

    def jmp(self, off: int) -> 'Program':
        self.write(opcode(OpcodeIndex.JMP), p8s(off))
        return self

    def stop(self) -> 'Program':
        self.write(opcode(OpcodeIndex.STOP))
        return self

    def println(self) -> 'Program':
        self.write(opcode(OpcodeIndex.PRINTLN))
        return self

    def read(self, r: int) -> 'Program':
        self.write(opcode(OpcodeIndex.READ), p8(r))
        return self
