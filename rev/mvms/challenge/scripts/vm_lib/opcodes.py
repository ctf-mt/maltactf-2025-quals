from enum import Enum, auto, unique
from random import randbytes

from .clang_workaround import BIN_PREFIX
from .packing import p8
from .paths import opcodes_path


@unique
class OpcodeIndex(int, Enum):
    NOP = 0
    LOAD = auto()
    LOAD_32 = auto()
    LOAD_64 = auto()
    LOAD_128 = auto()
    ADD = auto()
    SUB = auto()
    OR = auto()
    NOR = auto()
    ROL = auto()
    ROR = auto()
    AND = auto()
    MOD = auto()
    XOR = auto()
    MUL = auto()
    PUSH_R = auto()
    POP_R = auto()
    ADD_STK = auto()
    SUB_STK = auto()
    OR_STK = auto()
    NOR_STK = auto()
    ROL_STK = auto()
    ROR_STK = auto()
    AND_STK = auto()
    MOD_STK = auto()
    XOR_STK = auto()
    MUL_STK = auto()
    JZ = auto()
    JNZ = auto()
    JMP = auto()
    STOP = auto()
    PRINTLN = auto()
    READ = auto()
    MAX_INDEX = auto()


assert OpcodeIndex.MAX_INDEX == 33  # noqa: S101

opcodes = b''


def generate_opcodes() -> None:
    global opcodes

    opcodes = b''
    while not opcodes or len(set(opcodes)) != OpcodeIndex.MAX_INDEX:
        opcodes = randbytes(OpcodeIndex.MAX_INDEX)

    opcodes_path.write_bytes(BIN_PREFIX + opcodes)


def opcode(index: OpcodeIndex) -> bytes:
    return p8(opcodes[index])
