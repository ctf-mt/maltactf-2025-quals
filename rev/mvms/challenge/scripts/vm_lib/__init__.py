from random import seed

from .cases import prepare_vm_cpp
from .opcodes import OpcodeIndex, generate_opcodes, opcode
from .packing import endianness, p8, p8s, p16, p32, p64, p128
from .paths import opcodes_path, program_path, root_dir
from .program import Program
from .registers import allocate_registers


__all__ = (
    'OpcodeIndex',
    'Program',
    'allocate_registers',
    'endianness',
    'generate_opcodes',
    'opcode',
    'opcodes_path',
    'p8',
    'p8s',
    'p16',
    'p32',
    'p64',
    'p128',
    'program_path',
    'root_dir',
    'vm_init',
)


def vm_init(seed_value: int) -> None:
    seed(seed_value)
    generate_opcodes()
    prepare_vm_cpp()
