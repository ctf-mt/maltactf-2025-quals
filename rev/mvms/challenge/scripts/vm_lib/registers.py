from random import shuffle


REGISTERS_COUNT = 6


def allocate_registers(count: int) -> list[int]:
    if count < 1 or count > REGISTERS_COUNT:
        raise ValueError

    registers = list(range(REGISTERS_COUNT))
    shuffle(registers)
    return registers[:count]
