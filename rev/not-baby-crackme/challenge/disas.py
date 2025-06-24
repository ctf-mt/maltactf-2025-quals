import lief
from lief import ELF # type: ignore
import sys

if len(sys.argv) < 2:
    print("python", sys.argv[0], "[file]")
    exit(1)

prg: lief.ELF.Binary = lief.parse(sys.argv[1])

def reloc_to_string(reloc: ELF.Relocation):
    args = {
        # 'type': lief.ELF.RELOCATION_X86_64(reloc.type),
        'address': hex(reloc.address),
    }
    if reloc.is_rela:
        args['addend'] = hex(reloc.addend)
    if reloc.has_symbol:
        # print(reloc.symbol)
        if reloc.symbol.name:
            args['info'] = "\""+reloc.symbol.name+"\""
        else:
            args['info'] = reloc.info
    args = ', '.join([f"{key}={val}" for key, val in args.items()])
    return f"Relocation({args})"


# for idx, sym in enumerate(prg.dynamic_symbols):
#     print(sym.name)

for idx, reloc in enumerate(prg.dynamic_relocations):
    # print(reloc)
    print(reloc_to_string(reloc))

