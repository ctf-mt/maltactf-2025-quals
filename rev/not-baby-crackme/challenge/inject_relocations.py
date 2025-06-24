from pwn import asm, shellcraft, context
from typing import TYPE_CHECKING

context.arch = 'amd64'
from typing import Callable, Any
import lief
from lief import ELF # type: ignore
from functools import wraps, cached_property
import struct


def u64(data):
    return struct.unpack("<Q", data)[0]

def u32(data):
    return struct.unpack("<I", data)[0]

def us_to_s(val):
    if val < 0:
        return val
    if val & (1 << 63) != 0:
        val = val - (1 << 64)
    return val

class Faker:
    DRY_RUN_VAL: int = 0x13371337
    DRY_RUN_SYM: int = 0xdeadbeef
    prg: ELF.Binary
    dry_prg: ELF.Binary

    def __init__(self, filename):
        self.source = filename
        self.prg = lief.parse(self.source)
        self.dry_prg = None
        self.relocs: list[Callable[[bool], ELF.Relocation]] = []
        self.dry_sections: dict[str, ELF.Section] = {}
        self.dry_relocs: dict[Callable[[bool], ELF.Relocation], int] = None
        self.default_relocs = len(self.prg.dynamic_relocations)

    def reloc_instr(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            if 'dry_run' in kwargs: # I swear, this is gonna screw me over later on
                return func(self, *args, **kwargs)
            cache = {}
            @wraps(wrapper)
            def dry_run(dry_run=True):
                # I dont technically need the cache
                if dry_run in cache: # Ensure the exact same relocation is always returned
                    return cache[dry_run]
                cache[dry_run] = func(self, *args, dry_run=dry_run, **kwargs)
                return cache[dry_run]
            return dry_run
        return wrapper


    def make_symbol(self, name, value, size, shndx=1, type=ELF.Symbol.TYPE.OBJECT,
                    visibility=ELF.Symbol.VISIBILITY.DEFAULT, exported=False, binding=None):
        s = ELF.Symbol()
        s.name = name
        s.value = value
        s.size = size
        s.exported = exported
        s.shndx = shndx
        s.type = type
        s.visibility = visibility
        if binding:
            s.binding = binding
        return s

    @reloc_instr
    def mov(self, address, value, dry_run=None):
        reloc = ELF.Relocation(address, ELF.Relocation.TYPE.X86_64_RELATIVE, ELF.Relocation.ENCODING.RELA)
        reloc.addend = us_to_s(value)
        return reloc

    @reloc_instr
    def set_reloc_address(self, reloc: Callable[[bool], ELF.Relocation], value: Callable[[bool], int] | int, dry_run=None):
        if callable(value):
            value = value(dry_run)

        if dry_run:
            return self.mov(self.DRY_RUN_VAL, value, dry_run=dry_run)
        else:
            return self.mov(self.reloc_to_address_addr(reloc), value, dry_run=dry_run)
        
    @reloc_instr
    def set_reloc_addend(self, reloc: Callable[[bool], ELF.Relocation], value: Callable[[bool], int] | int, dry_run=None):
        if callable(value):
            value = value(dry_run)

        if dry_run:
            return self.mov(self.DRY_RUN_VAL, value, dry_run=dry_run)
        else:
            return self.mov(self.reloc_to_addend_addr(reloc), value, dry_run=dry_run)

    def get_section_end(self, section: str):
        rela_section = self.get_dry_section(section)
        return rela_section.virtual_address + rela_section.size

    def hidden_write(self, address, value):
        reloc = self.mov(0, 0)
        self.add_dynamic_relocation(self.set_reloc_address(reloc, address))
        self.add_dynamic_relocation(self.set_reloc_addend(reloc, value))
        self.add_dynamic_relocation(reloc)
        # Cleanup after
        self.add_dynamic_relocation(self.set_reloc_address(reloc, 0))
        self.add_dynamic_relocation(self.set_reloc_addend(reloc, 0))

    def get_dry_reloc(self, reloc):
        if self.dry_relocs:
            return self.dry_relocs[reloc]
        self.dry_relocs = {rel: self.default_relocs + idx for idx, rel in enumerate(self.relocs)}
        return self.dry_relocs[reloc]

    def get_dry_section(self, name) -> ELF.Section:
        if name in self.dry_sections:
            return self.dry_sections[name]
        self.dry_sections[name] = self.dry_prg.get_section(name)
        return self.dry_sections[name]
    
    def get_dry_symbol(self, name) -> dict[str, int]:
        if self.dry_symbols:
            return self.dry_symbols[name]
        self.dry_symbols = {sym.demangled_name: idx for idx, sym in enumerate(self.dry_prg.dynamic_symbols)}
        return self.dry_symbols[name]

    def reloc_to_address_addr(self, reloc: Callable[[bool], ELF.Relocation]):
        sec = self.get_dry_section('.rela.dyn')
        idx = self.get_dry_reloc(reloc)
        return sec.virtual_address + idx*0x18

    def add_dynamic_relocation(self, reloc: Callable[[bool], ELF.Relocation]) -> Callable[[bool], ELF.Relocation]:
        self.relocs.append(reloc)
        return reloc

    def reloc_to_addend_addr(self, reloc: Callable[[bool], ELF.Relocation]):
        sec = self.get_dry_section('.rela.dyn')
        idx = self.get_dry_reloc(reloc)
        return sec.virtual_address + idx*0x18 + 0x10

    def build(self, filename):
        for reloc in self.relocs:
            self.prg.add_dynamic_relocation(reloc(dry_run=True))
        
        self.prg.write(filename)
        self.dry_prg = lief.parse(filename)
        # Reread to avoid bug
        self.prg = lief.parse(self.source)

        for reloc in self.relocs:
            self.prg.add_dynamic_relocation(reloc(dry_run=False))

        self.prg.write(filename)

        self.prg = lief.parse(filename)

        dynsym = self.prg.get_section('.rela.dyn')
        dynsym_seg = list(dynsym.segments)[0]
        dynsym_seg.add(lief.ELF.Segment.FLAGS.W)

        self.prg.write(filename)

    def __getattr__(self, key: str) -> Any:
        return getattr(self.prg, key)

# Cursed
if TYPE_CHECKING:
    class Faker_(Faker, ELF.Binary):
        pass


def chal():
    print('injecting relocations...')
    faker: Faker_ = Faker('./tmp')
    shellcodes = {}

    for s in faker.prg.symbols:
        if not s.demangled_name.startswith('Shellcode_'):
            continue
        num = int(s.demangled_name[10:])
        shellcodes[num] = s.value

    if not shellcodes:
        shellcodes = {
            5: 0x41A0C0,
            0: 0x4086C0,
            4: 0x4169A0,
            1: 0x40C020,
            6: 0x41D620,
            3: 0x413200,
            7: 0x420DA0,
            2: 0x40F8C0,
        }

    faker.hidden_write(shellcodes[1] + 6698, 0xf4be24eec767aef5)  # decrypts to 0xf4be24eec767aef5
    faker.hidden_write(shellcodes[4] + 5866, 0xdc43866d29de15d9)  # decrypts to 0xdc43866d29de15d9
    faker.hidden_write(shellcodes[3] + 6321, 0xb0743878fc7d7446)  # decrypts to 0xb0743878fc7d7446
    faker.hidden_write(shellcodes[4] + 4423, 0xbd116bc8212238f2)  # decrypts to 0xbd116bc8212238f2
    faker.hidden_write(shellcodes[4] + 4085, 0xef2014cd69c79af2)  # decrypts to 0xef2014cd69c79af2
    faker.hidden_write(shellcodes[1] + 4787, 0x920590e473f50c21)  # decrypts to 0x920590e473f50c21
    faker.hidden_write(shellcodes[5] + 6224, 0xe201de4f7afc9807)  # decrypts to 0xe201de4f7afc9807
    faker.hidden_write(shellcodes[5] + 4469, 0xe4c9fd3665db448c)  # decrypts to 0xe4c9fd3665db448c
    faker.hidden_write(shellcodes[5] + 3520, 0xb431bc852df320e7)  # decrypts to 0xb431bc852df320e7
    faker.hidden_write(shellcodes[5] + 6380, 0x16bebb43983eaae5)  # decrypts to 0x16bebb43983eaae5
    faker.hidden_write(shellcodes[1] + 6373, 0xafed5396de2cc7fd)  # decrypts to 0xafed5396de2cc7fd
    faker.hidden_write(shellcodes[0] + 3994, 0x190e2b7e92e6f12b)  # decrypts to 0x190e2b7e92e6f12b
    faker.hidden_write(shellcodes[6] + 3552, 0xd3843ec78b0a0762)  # decrypts to 0xd3843ec78b0a0762
    faker.hidden_write(shellcodes[0] + 4826, 0xdcbefe2670aa0217)  # decrypts to 0xdcbefe2670aa0217
    faker.hidden_write(shellcodes[4] + 3864, 0x6df27fa57051d0df)  # decrypts to 0x6df27fa57051d0df
    faker.hidden_write(shellcodes[3] + 5580, 0x1e0ffa957e9ee027)  # decrypts to 0x1e0ffa957e9ee027
    faker.hidden_write(shellcodes[3] + 4761, 0xb2cf2c6bc904308c)  # decrypts to 0xb2cf2c6bc904308c
    faker.hidden_write(shellcodes[2] + 5424, 0x8f542c71cf0f002b)  # decrypts to 0x8f542c71cf0f002b
    faker.hidden_write(shellcodes[7] + 5151, 0x95929eede90bb39b)  # decrypts to 0x95929eede90bb39b
    faker.hidden_write(shellcodes[5] + 6497, 0x535c958580aa79ff)  # decrypts to 0x535c958580aa79ff
    faker.hidden_write(shellcodes[3] + 6269, 0x567647eac0fa28e)  # decrypts to 0x567647eac0fa28e
    faker.hidden_write(shellcodes[2] + 5034, 0x959dfbccc72e3fc5)  # decrypts to 0x959dfbccc72e3fc5
    faker.hidden_write(shellcodes[4] + 5814, 0xa16a0b492d9d604f)  # decrypts to 0xa16a0b492d9d604f
    faker.hidden_write(shellcodes[1] + 4475, 0xdf132e40b82d7f48)  # decrypts to 0xdf132e40b82d7f48
    faker.hidden_write(shellcodes[3] + 3929, 0xc5cf6f16ce6c1f57)  # decrypts to 0xc5cf6f16ce6c1f57
    faker.hidden_write(shellcodes[4] + 3565, 0x22112df57d97cd2c)  # decrypts to 0x22112df57d97cd2c
    faker.hidden_write(shellcodes[7] + 6620, 0xbdcbddc76c2affe3)  # decrypts to 0xbdcbddc76c2affe3
    faker.hidden_write(shellcodes[5] + 5379, 0xf656f270db9db3df)  # decrypts to 0xf656f270db9db3df
    faker.hidden_write(shellcodes[7] + 5268, 0xeac6e996de25267e)  # decrypts to 0xeac6e996de25267e
    faker.hidden_write(shellcodes[0] + 5775, 0x6a6857238a223280)  # decrypts to 0x6a6857238a223280
    faker.hidden_write(shellcodes[7] + 4722, 0x1e9d097e7da57301)  # decrypts to 0x1e9d097e7da57301
    faker.hidden_write(shellcodes[1] + 6399, 0x70559f4a38618dcf)  # decrypts to 0x70559f4a38618dcf
    faker.hidden_write(shellcodes[5] + 5028, 0xd7a59bed2ee49e03)  # decrypts to 0xd7a59bed2ee49e03
    faker.hidden_write(shellcodes[1] + 3565, 0x568fe474ee5d2f86)  # decrypts to 0x568fe474ee5d2f86
    faker.hidden_write(shellcodes[6] + 4150, 0x7ed0342e7f6d41c1)  # decrypts to 0x7ed0342e7f6d41c1
    faker.hidden_write(shellcodes[2] + 4384, 0xea104ede8e4ddb89)  # decrypts to 0xea104ede8e4ddb89
    faker.hidden_write(shellcodes[0] + 4215, 0xbb1cd2bfe18b5fd0)  # decrypts to 0xbb1cd2bfe18b5fd0
    faker.hidden_write(shellcodes[2] + 5255, 0x3ac19460a5784106)  # decrypts to 0x3ac19460a5784106
    faker.hidden_write(shellcodes[0] + 6191, 0x2fa92914cda11a90)  # decrypts to 0x2fa92914cda11a90
    faker.hidden_write(shellcodes[0] + 5918, 0x2cce01ebe58ef911)  # decrypts to 0x2cce01ebe58ef911
    faker.hidden_write(shellcodes[1] + 3734, 0xb2f4e59445277fd4)  # decrypts to 0xb2f4e59445277fd4
    faker.hidden_write(shellcodes[6] + 5840, 0x3d2abfc25083a650)  # decrypts to 0x3d2abfc25083a650
    faker.hidden_write(shellcodes[4] + 5892, 0xa8259593d4303cfb)  # decrypts to 0xa8259593d4303cfb
    faker.hidden_write(shellcodes[1] + 3929, 0x23de1554f8d3257f)  # decrypts to 0x23de1554f8d3257f
    faker.hidden_write(shellcodes[4] + 6152, 0x795f0d36a62916f)  # decrypts to 0x795f0d36a62916f
    faker.hidden_write(shellcodes[0] + 3864, 0xf2f829b29f239209)  # decrypts to 0xf2f829b29f239209
    faker.hidden_write(shellcodes[4] + 3669, 0xa840b24936fb1d4e)  # decrypts to 0xa840b24936fb1d4e
    faker.hidden_write(shellcodes[4] + 4332, 0x16d60a54c0ff7a84)  # decrypts to 0x16d60a54c0ff7a84
    faker.hidden_write(shellcodes[4] + 3409, 0x52a700a43e457559)  # decrypts to 0x52a700a43e457559
    faker.hidden_write(shellcodes[5] + 5366, 0xeffb91eec6a2505)  # decrypts to 0xeffb91eec6a2505
    faker.hidden_write(shellcodes[7] + 5034, 0x87500cb9ff81593)  # decrypts to 0x87500cb9ff81593
    faker.hidden_write(shellcodes[1] + 3617, 0xd51003a0355c5bc)  # decrypts to 0xd51003a0355c5bc
    faker.hidden_write(shellcodes[2] + 4956, 0x85d58a951b97b02a)  # decrypts to 0x85d58a951b97b02a
    faker.hidden_write(shellcodes[7] + 4033, 0x7b081c5ba7073919)  # decrypts to 0x7b081c5ba7073919
    faker.hidden_write(shellcodes[6] + 3591, 0x90d0f39f4eca5cb5)  # decrypts to 0x90d0f39f4eca5cb5
    faker.hidden_write(shellcodes[2] + 4904, 0xcc5d9ea786bce353)  # decrypts to 0xcc5d9ea786bce353
    faker.hidden_write(shellcodes[4] + 6438, 0x5e8ab1eed3fee69f)  # decrypts to 0x5e8ab1eed3fee69f
    faker.hidden_write(shellcodes[5] + 4963, 0x32790076a9e39cc8)  # decrypts to 0x32790076a9e39cc8
    faker.hidden_write(shellcodes[7] + 3617, 0x6c894bdfddc6c374)  # decrypts to 0x6c894bdfddc6c374
    faker.hidden_write(shellcodes[1] + 6139, 0x9bb8cd8cc60a7f56)  # decrypts to 0x9bb8cd8cc60a7f56
    faker.hidden_write(shellcodes[1] + 4631, 0x76dda98563edd3d7)  # decrypts to 0x76dda98563edd3d7
    faker.hidden_write(shellcodes[5] + 4235, 0xa80f4c9f42777059)  # decrypts to 0xa80f4c9f42777059
    faker.hidden_write(shellcodes[2] + 3552, 0x806c3a99daa65a99)  # decrypts to 0x806c3a99daa65a99
    faker.hidden_write(shellcodes[2] + 5554, 0x6faa2dd3ea33b330)  # decrypts to 0x6faa2dd3ea33b330
    faker.hidden_write(shellcodes[3] + 5346, 0x881582c885b7dc59)  # decrypts to 0x881582c885b7dc59
    faker.hidden_write(shellcodes[3] + 5619, 0x879295b174d93901)  # decrypts to 0x879295b174d93901
    faker.hidden_write(shellcodes[4] + 5632, 0xbc94060095ea95e7)  # decrypts to 0xbc94060095ea95e7
    faker.hidden_write(shellcodes[3] + 5827, 0x5a82f3b4f28ea466)  # decrypts to 0x5a82f3b4f28ea466
    faker.hidden_write(shellcodes[2] + 4020, 0xde485c0e4bf1d54d)  # decrypts to 0xde485c0e4bf1d54d
    faker.hidden_write(shellcodes[1] + 5151, 0x4b45a35d1711b67b)  # decrypts to 0x4b45a35d1711b67b
    faker.hidden_write(shellcodes[1] + 5476, 0x65271854a28797d3)  # decrypts to 0x65271854a28797d3
    faker.hidden_write(shellcodes[4] + 5710, 0x378132837ff068a5)  # decrypts to 0x378132837ff068a5
    faker.hidden_write(shellcodes[6] + 5515, 0x1280baf2f890bb8d)  # decrypts to 0x1280baf2f890bb8d
    faker.hidden_write(shellcodes[2] + 6308, 0x84868b7c97baf3a5)  # decrypts to 0x84868b7c97baf3a5
    faker.hidden_write(shellcodes[5] + 5756, 0x3dc406a53143469e)  # decrypts to 0x3dc406a53143469e
    faker.hidden_write(shellcodes[7] + 4748, 0xadf0de287a0255c5)  # decrypts to 0xadf0de287a0255c5
    faker.hidden_write(shellcodes[4] + 4878, 0x57f0d34d556c5e5a)  # decrypts to 0x57f0d34d556c5e5a
    faker.hidden_write(shellcodes[5] + 6107, 0x1816622fbbd4f964)  # decrypts to 0x1816622fbbd4f964
    faker.hidden_write(shellcodes[6] + 4020, 0xba9154a0e513c443)  # decrypts to 0xba9154a0e513c443
    faker.hidden_write(shellcodes[7] + 3825, 0x6ba9faba0cdec5d5)  # decrypts to 0x6ba9faba0cdec5d5
    faker.hidden_write(shellcodes[1] + 6451, 0xe0f65a40ce6d2509)  # decrypts to 0xe0f65a40ce6d2509
    faker.hidden_write(shellcodes[4] + 5554, 0x8f27ee911b8e4b01)  # decrypts to 0x8f27ee911b8e4b01
    faker.hidden_write(shellcodes[3] + 5476, 0xeae507f765dffe8f)  # decrypts to 0xeae507f765dffe8f
    faker.hidden_write(shellcodes[6] + 6022, 0xd37baeb412720697)  # decrypts to 0xd37baeb412720697
    faker.hidden_write(shellcodes[0] + 6022, 0xdf3fab1e0f7efbc5)  # decrypts to 0xdf3fab1e0f7efbc5
    faker.hidden_write(shellcodes[3] + 5268, 0x660173df6c07f0f0)  # decrypts to 0x660173df6c07f0f0
    faker.hidden_write(shellcodes[1] + 6711, 0x980585f22225c56)  # decrypts to 0x980585f22225c56
    faker.hidden_write(shellcodes[5] + 6536, 0x5eecaea0254bdd45)  # decrypts to 0x5eecaea0254bdd45
    faker.hidden_write(shellcodes[1] + 5502, 0x7e4a0628e0fc8852)  # decrypts to 0x7e4a0628e0fc8852
    faker.hidden_write(shellcodes[7] + 3422, 0xb60c3741f77cb57b)  # decrypts to 0xb60c3741f77cb57b
    faker.hidden_write(shellcodes[7] + 6152, 0x5798939785c53021)  # decrypts to 0x5798939785c53021
    faker.hidden_write(shellcodes[6] + 3669, 0xad57a18d1e89d7d7)  # decrypts to 0xad57a18d1e89d7d7
    faker.hidden_write(shellcodes[0] + 3695, 0xc68c445efb6960e8)  # decrypts to 0xc68c445efb6960e8
    faker.hidden_write(shellcodes[6] + 6061, 0x2ed44cdad3477118)  # decrypts to 0x2ed44cdad3477118
    faker.hidden_write(shellcodes[2] + 3773, 0xd58d4363aabcd4e5)  # decrypts to 0xd58d4363aabcd4e5
    faker.hidden_write(shellcodes[3] + 4202, 0x9fb6383966216147)  # decrypts to 0x9fb6383966216147
    faker.hidden_write(shellcodes[6] + 5372, 0x3d0abaa0520aaa4)  # decrypts to 0x3d0abaa0520aaa4
    faker.hidden_write(shellcodes[7] + 4488, 0xaa13102ff1a0b7a9)  # decrypts to 0xaa13102ff1a0b7a9
    faker.hidden_write(shellcodes[6] + 3487, 0x516c007eb2bc67bf)  # decrypts to 0x516c007eb2bc67bf
    faker.hidden_write(shellcodes[3] + 6607, 0x3810f6c812ca429f)  # decrypts to 0x3810f6c812ca429f
    faker.hidden_write(shellcodes[3] + 4709, 0x10486c2f2b209a18)  # decrypts to 0x10486c2f2b209a18
    faker.hidden_write(shellcodes[3] + 4696, 0xac990186e6e87415)  # decrypts to 0xac990186e6e87415
    faker.hidden_write(shellcodes[2] + 6243, 0x7b33a5fa14daa6b7)  # decrypts to 0x7b33a5fa14daa6b7
    faker.hidden_write(shellcodes[5] + 4443, 0xbf518441905edb64)  # decrypts to 0xbf518441905edb64
    faker.hidden_write(shellcodes[0] + 3487, 0x3d9712cf01bdb8b1)  # decrypts to 0x3d9712cf01bdb8b1
    faker.hidden_write(shellcodes[0] + 5307, 0x72b1e1140b592633)  # decrypts to 0x72b1e1140b592633
    faker.hidden_write(shellcodes[3] + 3500, 0xc19fde656e943199)  # decrypts to 0xc19fde656e943199
    faker.hidden_write(shellcodes[4] + 6659, 0x746ebd3be15800e4)  # decrypts to 0x746ebd3be15800e4
    faker.hidden_write(shellcodes[5] + 6640, 0x8f807cc0c91e9330)  # decrypts to 0x8f807cc0c91e9330
    faker.hidden_write(shellcodes[5] + 4274, 0x178a5db9abead000)  # decrypts to 0x178a5db9abead000
    faker.hidden_write(shellcodes[4] + 4891, 0xac05ec09228e3838)  # decrypts to 0xac05ec09228e3838
    faker.hidden_write(shellcodes[6] + 4800, 0xf96b47a5421c3154)  # decrypts to 0xf96b47a5421c3154
    faker.hidden_write(shellcodes[2] + 6139, 0xb6f30798941a644)  # decrypts to 0xb6f30798941a644
    faker.hidden_write(shellcodes[2] + 3604, 0xd593f5dae96ff47d)  # decrypts to 0xd593f5dae96ff47d
    faker.hidden_write(shellcodes[3] + 4124, 0x746a85478cfc985b)  # decrypts to 0x746a85478cfc985b
    faker.hidden_write(shellcodes[6] + 6529, 0x7b4c7c10e114ebca)  # decrypts to 0x7b4c7c10e114ebca
    faker.hidden_write(shellcodes[1] + 5138, 0x5d982f4cd0313641)  # decrypts to 0x5d982f4cd0313641
    faker.hidden_write(shellcodes[7] + 5489, 0x3de8f638434ad72)  # decrypts to 0x3de8f638434ad72
    faker.hidden_write(shellcodes[0] + 6113, 0x5d99f3b33c55addb)  # decrypts to 0x5d99f3b33c55addb
    faker.hidden_write(shellcodes[4] + 3981, 0x5940b7f382ce0f8b)  # decrypts to 0x5940b7f382ce0f8b
    faker.hidden_write(shellcodes[2] + 3877, 0xff8a3d0a7ddced34)  # decrypts to 0xff8a3d0a7ddced34
    faker.hidden_write(shellcodes[4] + 4761, 0x81413345fc03ca11)  # decrypts to 0x81413345fc03ca11
    faker.hidden_write(shellcodes[2] + 6360, 0x497cf5ff1add91a5)  # decrypts to 0x497cf5ff1add91a5
    faker.hidden_write(shellcodes[6] + 3825, 0x2cd1c7a306c94f86)  # decrypts to 0x2cd1c7a306c94f86
    faker.hidden_write(shellcodes[1] + 4891, 0xe376152a2317fe70)  # decrypts to 0xe376152a2317fe70
    faker.hidden_write(shellcodes[1] + 6633, 0x992383c5b8c13f7b)  # decrypts to 0x992383c5b8c13f7b
    faker.hidden_write(shellcodes[3] + 4618, 0x53843e1bbf11297c)  # decrypts to 0x53843e1bbf11297c
    faker.hidden_write(shellcodes[1] + 5918, 0xb5b6610ddba1c5fe)  # decrypts to 0xb5b6610ddba1c5fe
    faker.hidden_write(shellcodes[6] + 4397, 0x7814a5126b51189e)  # decrypts to 0x7814a5126b51189e
    faker.hidden_write(shellcodes[4] + 3591, 0x23e568dd06e5faad)  # decrypts to 0x23e568dd06e5faad
    faker.hidden_write(shellcodes[3] + 6100, 0x403a5e8526294500)  # decrypts to 0x403a5e8526294500
    faker.hidden_write(shellcodes[7] + 6061, 0x988e93f64ed3b376)  # decrypts to 0x988e93f64ed3b376
    faker.hidden_write(shellcodes[4] + 3435, 0xfe61871ccd7d3c42)  # decrypts to 0xfe61871ccd7d3c42
    faker.hidden_write(shellcodes[1] + 4358, 0x66a6cce65c089d54)  # decrypts to 0x66a6cce65c089d54
    faker.hidden_write(shellcodes[7] + 4176, 0x6324af240412477b)  # decrypts to 0x6324af240412477b
    faker.hidden_write(shellcodes[2] + 3526, 0xdefb01632e3067b3)  # decrypts to 0xdefb01632e3067b3
    faker.hidden_write(shellcodes[1] + 4306, 0x8971759351c20bb4)  # decrypts to 0x8971759351c20bb4
    faker.hidden_write(shellcodes[5] + 5977, 0x694d5d015155afcc)  # decrypts to 0x694d5d015155afcc
    faker.hidden_write(shellcodes[1] + 6022, 0xe6bd440525e7f058)  # decrypts to 0xe6bd440525e7f058
    faker.hidden_write(shellcodes[0] + 5242, 0xe769e3d0aaa64de6)  # decrypts to 0xe769e3d0aaa64de6
    faker.hidden_write(shellcodes[0] + 6347, 0x620fda127b9a8115)  # decrypts to 0x620fda127b9a8115
    faker.hidden_write(shellcodes[7] + 5632, 0xbd8adc38fea24fa)  # decrypts to 0xbd8adc38fea24fa
    faker.hidden_write(shellcodes[4] + 3708, 0x79a1b84439daa6f3)  # decrypts to 0x79a1b84439daa6f3
    faker.hidden_write(shellcodes[4] + 5723, 0xe1490c2e081c1a97)  # decrypts to 0xe1490c2e081c1a97
    faker.hidden_write(shellcodes[2] + 5658, 0xb0714f83918c9c6b)  # decrypts to 0xb0714f83918c9c6b
    faker.hidden_write(shellcodes[6] + 4917, 0xf48fa5bdac4377de)  # decrypts to 0xf48fa5bdac4377de
    faker.hidden_write(shellcodes[1] + 4644, 0x2459a93261845559)  # decrypts to 0x2459a93261845559
    faker.hidden_write(shellcodes[2] + 5918, 0xa2543bd486bd7ae7)  # decrypts to 0xa2543bd486bd7ae7
    faker.hidden_write(shellcodes[4] + 4501, 0xcd2a18fc2898a55)  # decrypts to 0xcd2a18fc2898a55
    faker.hidden_write(shellcodes[1] + 4436, 0xd87de7a69cdac57)  # decrypts to 0xd87de7a69cdac57
    faker.hidden_write(shellcodes[4] + 5996, 0x6d3c744eb40f8f83)  # decrypts to 0x6d3c744eb40f8f83
    faker.hidden_write(shellcodes[4] + 4514, 0x18c21213542b3af2)  # decrypts to 0x18c21213542b3af2
    faker.hidden_write(shellcodes[7] + 4254, 0x8039db707976fa94)  # decrypts to 0x8039db707976fa94
    faker.hidden_write(shellcodes[6] + 6295, 0xa4304cdc74cb1f53)  # decrypts to 0xa4304cdc74cb1f53
    faker.hidden_write(shellcodes[5] + 3806, 0xe1ffd17c62d7ff31)  # decrypts to 0xe1ffd17c62d7ff31
    faker.hidden_write(shellcodes[5] + 5314, 0x720d4c38a45f6e51)  # decrypts to 0x720d4c38a45f6e51
    faker.hidden_write(shellcodes[7] + 6529, 0x1dcbe28d663d1736)  # decrypts to 0x1dcbe28d663d1736
    faker.hidden_write(shellcodes[4] + 4943, 0xa2a1a90c854e3d43)  # decrypts to 0xa2a1a90c854e3d43
    faker.hidden_write(shellcodes[3] + 6217, 0x985879ddd502799c)  # decrypts to 0x985879ddd502799c
    faker.hidden_write(shellcodes[7] + 5320, 0x3f98eeceba36d62c)  # decrypts to 0x3f98eeceba36d62c
    faker.hidden_write(shellcodes[7] + 3994, 0x6c6b87c7e2fbbb40)  # decrypts to 0x6c6b87c7e2fbbb40
    faker.hidden_write(shellcodes[7] + 6698, 0xd8979809e34d0ad9)  # decrypts to 0xd8979809e34d0ad9
    faker.hidden_write(shellcodes[3] + 4631, 0x76c99b97bc9b3e9)  # decrypts to 0x76c99b97bc9b3e9
    faker.hidden_write(shellcodes[3] + 5359, 0x4f3d849e35f840e8)  # decrypts to 0x4f3d849e35f840e8
    faker.hidden_write(shellcodes[3] + 4995, 0x7f324adcd00b4258)  # decrypts to 0x7f324adcd00b4258
    faker.hidden_write(shellcodes[1] + 5827, 0x5fcac9a7d9b2bf59)  # decrypts to 0x5fcac9a7d9b2bf59
    faker.hidden_write(shellcodes[4] + 4020, 0x7996ebd46f3806f)  # decrypts to 0x7996ebd46f3806f
    faker.hidden_write(shellcodes[1] + 6438, 0xcd8019395fdc9c78)  # decrypts to 0xcd8019395fdc9c78
    faker.hidden_write(shellcodes[7] + 5307, 0x718141e9627b4fd1)  # decrypts to 0x718141e9627b4fd1
    faker.hidden_write(shellcodes[7] + 4306, 0xf57fea79cdf3be42)  # decrypts to 0xf57fea79cdf3be42
    faker.hidden_write(shellcodes[0] + 5879, 0x2f5b7ece5138574c)  # decrypts to 0x2f5b7ece5138574c
    faker.hidden_write(shellcodes[5] + 5574, 0xb5936ee736ea4fdf)  # decrypts to 0xb5936ee736ea4fdf
    faker.hidden_write(shellcodes[4] + 5281, 0x825abf2b73810958)  # decrypts to 0x825abf2b73810958
    faker.hidden_write(shellcodes[4] + 3786, 0xccbe9c42928de8e0)  # decrypts to 0xccbe9c42928de8e0
    faker.hidden_write(shellcodes[5] + 5548, 0x7965e0796d2a13d4)  # decrypts to 0x7965e0796d2a13d4
    faker.hidden_write(shellcodes[1] + 5320, 0x91b3b4ae6b1eeac4)  # decrypts to 0x91b3b4ae6b1eeac4
    faker.hidden_write(shellcodes[2] + 4930, 0x759cf580fb2a34f2)  # decrypts to 0x759cf580fb2a34f2
    faker.hidden_write(shellcodes[4] + 6633, 0x7aedeb71ffc6681f)  # decrypts to 0x7aedeb71ffc6681f
    faker.hidden_write(shellcodes[3] + 4644, 0x6b9fda891bece33)  # decrypts to 0x6b9fda891bece33
    faker.hidden_write(shellcodes[7] + 4813, 0x8c8269ed85395570)  # decrypts to 0x8c8269ed85395570
    faker.hidden_write(shellcodes[6] + 6490, 0x33ee340fb13adf0)  # decrypts to 0x33ee340fb13adf0
    faker.hidden_write(shellcodes[0] + 3552, 0x2fc47b55e7c049d6)  # decrypts to 0x2fc47b55e7c049d6
    faker.hidden_write(shellcodes[3] + 5892, 0xbb425c756d408d04)  # decrypts to 0xbb425c756d408d04
    faker.hidden_write(shellcodes[7] + 5450, 0x6cc221fd69f9c230)  # decrypts to 0x6cc221fd69f9c230
    faker.hidden_write(shellcodes[2] + 4891, 0x7c95fae6f94c679d)  # decrypts to 0x7c95fae6f94c679d
    faker.hidden_write(shellcodes[2] + 4423, 0xcf971a3f8af99b3b)  # decrypts to 0xcf971a3f8af99b3b
    faker.hidden_write(shellcodes[2] + 4618, 0x1fc753339d202e1b)  # decrypts to 0x1fc753339d202e1b
    faker.hidden_write(shellcodes[7] + 6113, 0xa98181846d62e453)  # decrypts to 0xa98181846d62e453
    faker.hidden_write(shellcodes[0] + 3669, 0xb0e5cbcfb6b181e1)  # decrypts to 0xb0e5cbcfb6b181e1
    faker.hidden_write(shellcodes[4] + 3968, 0x1b608a7215b5a5e6)  # decrypts to 0x1b608a7215b5a5e6
    faker.hidden_write(shellcodes[0] + 4930, 0x93104e245fe98dd6)  # decrypts to 0x93104e245fe98dd6
    faker.hidden_write(shellcodes[5] + 5496, 0x8395895c8ce5d22a)  # decrypts to 0x8395895c8ce5d22a
    faker.hidden_write(shellcodes[0] + 6139, 0x29b9e80fc2f083ca)  # decrypts to 0x29b9e80fc2f083ca
    faker.hidden_write(shellcodes[5] + 3728, 0x6445585e8d792c44)  # decrypts to 0x6445585e8d792c44
    faker.hidden_write(shellcodes[3] + 6308, 0x110bfe6aaf6ba0)  # decrypts to 0x110bfe6aaf6ba0
    faker.hidden_write(shellcodes[5] + 4300, 0x7e2e60e76dfcd499)  # decrypts to 0x7e2e60e76dfcd499
    faker.hidden_write(shellcodes[0] + 5463, 0x9dbd5dc97fde3ac8)  # decrypts to 0x9dbd5dc97fde3ac8
    faker.hidden_write(shellcodes[0] + 4280, 0xf42350e477587891)  # decrypts to 0xf42350e477587891
    faker.hidden_write(shellcodes[1] + 5216, 0x54dd25eaedeb71c6)  # decrypts to 0x54dd25eaedeb71c6
    faker.hidden_write(shellcodes[4] + 5567, 0x234a23b327e38492)  # decrypts to 0x234a23b327e38492
    faker.hidden_write(shellcodes[2] + 5840, 0x257740a3d0a5954c)  # decrypts to 0x257740a3d0a5954c
    faker.hidden_write(shellcodes[6] + 6256, 0xb6876976ea641c38)  # decrypts to 0xb6876976ea641c38
    faker.hidden_write(shellcodes[1] + 3916, 0xf4f153506e23a364)  # decrypts to 0xf4f153506e23a364
    faker.hidden_write(shellcodes[4] + 4774, 0x6ba3a82f605a8c4e)  # decrypts to 0x6ba3a82f605a8c4e
    faker.hidden_write(shellcodes[1] + 5268, 0xf5f92f92c6c15262)  # decrypts to 0xf5f92f92c6c15262
    faker.hidden_write(shellcodes[7] + 5853, 0x231fb1d357e406e6)  # decrypts to 0x231fb1d357e406e6
    faker.hidden_write(shellcodes[7] + 5528, 0x97b2dd0c3eeca7c9)  # decrypts to 0x97b2dd0c3eeca7c9
    faker.hidden_write(shellcodes[6] + 3682, 0x29e3b4b89f9d5f1c)  # decrypts to 0x29e3b4b89f9d5f1c
    faker.hidden_write(shellcodes[0] + 6373, 0xfce141b5978cbc19)  # decrypts to 0xfce141b5978cbc19
    faker.hidden_write(shellcodes[0] + 4189, 0xec4989d50f2a23e8)  # decrypts to 0xec4989d50f2a23e8
    faker.hidden_write(shellcodes[4] + 5463, 0x4fde5d7697329888)  # decrypts to 0x4fde5d7697329888
    faker.hidden_write(shellcodes[0] + 4020, 0xda28c665aee6f22e)  # decrypts to 0xda28c665aee6f22e
    faker.hidden_write(shellcodes[7] + 3604, 0x1a4469a80df4589d)  # decrypts to 0x1a4469a80df4589d
    faker.hidden_write(shellcodes[5] + 5808, 0x50386427884b9958)  # decrypts to 0x50386427884b9958
    faker.hidden_write(shellcodes[3] + 6620, 0x67fc1c2b8b182db3)  # decrypts to 0x67fc1c2b8b182db3
    faker.hidden_write(shellcodes[3] + 6438, 0x8ac746015da63a77)  # decrypts to 0x8ac746015da63a77
    faker.hidden_write(shellcodes[3] + 5021, 0xa882d9a502a20f09)  # decrypts to 0xa882d9a502a20f09
    faker.hidden_write(shellcodes[0] + 5541, 0x5206ca8e595162e1)  # decrypts to 0x5206ca8e595162e1
    faker.hidden_write(shellcodes[1] + 5515, 0xa2cc623906b75fff)  # decrypts to 0xa2cc623906b75fff
    faker.hidden_write(shellcodes[0] + 5138, 0x314f5a3d5d4aab0d)  # decrypts to 0x314f5a3d5d4aab0d
    faker.hidden_write(shellcodes[7] + 4800, 0x364a1fe271d1e099)  # decrypts to 0x364a1fe271d1e099
    faker.hidden_write(shellcodes[5] + 4768, 0x22da53f08f6d5d21)  # decrypts to 0x22da53f08f6d5d21
    faker.hidden_write(shellcodes[0] + 4696, 0x3f0e1453f7acbb7d)  # decrypts to 0x3f0e1453f7acbb7d
    faker.hidden_write(shellcodes[3] + 5671, 0xde0f2dbf3375d9b4)  # decrypts to 0xde0f2dbf3375d9b4
    faker.hidden_write(shellcodes[0] + 5957, 0x9c1157f480edef45)  # decrypts to 0x9c1157f480edef45
    faker.hidden_write(shellcodes[3] + 5879, 0xdaad1e93af40e6fc)  # decrypts to 0xdaad1e93af40e6fc
    faker.hidden_write(shellcodes[5] + 4105, 0xac225cbdfa8cdf2b)  # decrypts to 0xac225cbdfa8cdf2b
    faker.hidden_write(shellcodes[2] + 6204, 0x24e61b2c34744273)  # decrypts to 0x24e61b2c34744273
    faker.hidden_write(shellcodes[6] + 4319, 0x99f105c43a57a4c2)  # decrypts to 0x99f105c43a57a4c2
    faker.hidden_write(shellcodes[2] + 3890, 0xffe4e4e29b07476e)  # decrypts to 0xffe4e4e29b07476e
    faker.hidden_write(shellcodes[3] + 4384, 0xb9ce0f3cd199ab97)  # decrypts to 0xb9ce0f3cd199ab97
    faker.hidden_write(shellcodes[7] + 5671, 0x25e74e7e09f5444d)  # decrypts to 0x25e74e7e09f5444d
    faker.hidden_write(shellcodes[3] + 3669, 0x7f19573e3333f38c)  # decrypts to 0x7f19573e3333f38c
    faker.hidden_write(shellcodes[2] + 5099, 0xd0c5f162dba37310)  # decrypts to 0xd0c5f162dba37310
    faker.hidden_write(shellcodes[1] + 5983, 0x875b44f3f8874ed6)  # decrypts to 0x875b44f3f8874ed6
    faker.hidden_write(shellcodes[1] + 6386, 0xf663843e92f7e60a)  # decrypts to 0xf663843e92f7e60a
    faker.hidden_write(shellcodes[1] + 5398, 0xfef2e6810856c759)  # decrypts to 0xfef2e6810856c759
    faker.hidden_write(shellcodes[7] + 6217, 0x1f4d7680f6c42ef2)  # decrypts to 0x1f4d7680f6c42ef2
    faker.hidden_write(shellcodes[4] + 4124, 0xec64fc481fa1f5c)  # decrypts to 0xec64fc481fa1f5c
    faker.hidden_write(shellcodes[4] + 5918, 0x339d8e9cede2dffc)  # decrypts to 0x339d8e9cede2dffc
    faker.hidden_write(shellcodes[1] + 6568, 0xc6dc5f5bb8954c5f)  # decrypts to 0xc6dc5f5bb8954c5f
    faker.hidden_write(shellcodes[5] + 5860, 0x30c31c6e89714d55)  # decrypts to 0x30c31c6e89714d55
    faker.hidden_write(shellcodes[1] + 3448, 0xa381533907aa6dc5)  # decrypts to 0xa381533907aa6dc5
    faker.hidden_write(shellcodes[4] + 4553, 0xc56d482c19094d27)  # decrypts to 0xc56d482c19094d27
    faker.hidden_write(shellcodes[7] + 4683, 0xe81bb10e5e4c2dc5)  # decrypts to 0xe81bb10e5e4c2dc5
    faker.hidden_write(shellcodes[7] + 5255, 0x176ae7865b0d6e8a)  # decrypts to 0x176ae7865b0d6e8a
    faker.hidden_write(shellcodes[0] + 4254, 0x49c9d74fe815eae3)  # decrypts to 0x49c9d74fe815eae3
    faker.hidden_write(shellcodes[7] + 4189, 0x7c3d8574c9a81f69)  # decrypts to 0x7c3d8574c9a81f69
    faker.hidden_write(shellcodes[4] + 3682, 0x99ed981f7036d373)  # decrypts to 0x99ed981f7036d373
    faker.hidden_write(shellcodes[1] + 5723, 0xd7a90b9766958e3c)  # decrypts to 0xd7a90b9766958e3c
    faker.hidden_write(shellcodes[2] + 6464, 0x859f7ee856c4687c)  # decrypts to 0x859f7ee856c4687c
    faker.hidden_write(shellcodes[1] + 4540, 0x443424bb8f20f2fb)  # decrypts to 0x443424bb8f20f2fb
    faker.hidden_write(shellcodes[5] + 5743, 0x611c490718aa0931)  # decrypts to 0x611c490718aa0931
    faker.hidden_write(shellcodes[4] + 5034, 0xae300c3c2cddb5ba)  # decrypts to 0xae300c3c2cddb5ba
    faker.hidden_write(shellcodes[5] + 5925, 0xdc2e8ba4cfd999e5)  # decrypts to 0xdc2e8ba4cfd999e5
    faker.hidden_write(shellcodes[5] + 3767, 0x61bd41822cdce9e6)  # decrypts to 0x61bd41822cdce9e6
    faker.hidden_write(shellcodes[4] + 4527, 0xc83e1ddd204c150c)  # decrypts to 0xc83e1ddd204c150c
    faker.hidden_write(shellcodes[1] + 5203, 0xb24a4e1e4b553054)  # decrypts to 0xb24a4e1e4b553054
    faker.hidden_write(shellcodes[1] + 4384, 0xc62bd2fc87f2ae32)  # decrypts to 0xc62bd2fc87f2ae32
    faker.hidden_write(shellcodes[1] + 4371, 0xcdc32ce4523ef297)  # decrypts to 0xcdc32ce4523ef297
    faker.hidden_write(shellcodes[5] + 5158, 0xd3927e1dd243221e)  # decrypts to 0xd3927e1dd243221e
    faker.hidden_write(shellcodes[4] + 5320, 0x96b3a1b0313a0a39)  # decrypts to 0x96b3a1b0313a0a39
    faker.hidden_write(shellcodes[5] + 5132, 0xa2fd561edc75fa0c)  # decrypts to 0xa2fd561edc75fa0c
    faker.hidden_write(shellcodes[3] + 4397, 0x81d49467e1c8d1b5)  # decrypts to 0x81d49467e1c8d1b5
    faker.hidden_write(shellcodes[1] + 5853, 0xbf4fdf5387088809)  # decrypts to 0xbf4fdf5387088809
    faker.hidden_write(shellcodes[6] + 4579, 0xe0ad0a1c75c75b98)  # decrypts to 0xe0ad0a1c75c75b98
    faker.hidden_write(shellcodes[0] + 5151, 0x6daa47a214d4f04e)  # decrypts to 0x6daa47a214d4f04e
    faker.hidden_write(shellcodes[7] + 4553, 0xa38693de43c07cd3)  # decrypts to 0xa38693de43c07cd3
    faker.hidden_write(shellcodes[6] + 4085, 0x7fbd8a14de94e154)  # decrypts to 0x7fbd8a14de94e154
    faker.hidden_write(shellcodes[1] + 5489, 0x5beef6e46729af61)  # decrypts to 0x5beef6e46729af61
    faker.hidden_write(shellcodes[6] + 6659, 0x8310f0806b39e85)  # decrypts to 0x8310f0806b39e85
    faker.hidden_write(shellcodes[1] + 6126, 0x34db268ea0aecbee)  # decrypts to 0x34db268ea0aecbee
    faker.hidden_write(shellcodes[2] + 4605, 0x223cc8926d94bd8c)  # decrypts to 0x223cc8926d94bd8c
    faker.hidden_write(shellcodes[3] + 5151, 0xe1e753c4af5bf30e)  # decrypts to 0xe1e753c4af5bf30e
    faker.hidden_write(shellcodes[4] + 6035, 0x139e3c15c35be310)  # decrypts to 0x139e3c15c35be310
    faker.hidden_write(shellcodes[6] + 3773, 0x4e76deea0667acaa)  # decrypts to 0x4e76deea0667acaa
    faker.hidden_write(shellcodes[4] + 4917, 0x8f5c9c0ac4113cbd)  # decrypts to 0x8f5c9c0ac4113cbd
    faker.hidden_write(shellcodes[1] + 3461, 0x5218acdadbe2baf8)  # decrypts to 0x5218acdadbe2baf8
    faker.hidden_write(shellcodes[3] + 5385, 0x4126e0d84480ec4c)  # decrypts to 0x4126e0d84480ec4c
    faker.hidden_write(shellcodes[7] + 4202, 0x95fff34e30051013)  # decrypts to 0x95fff34e30051013
    faker.hidden_write(shellcodes[0] + 5229, 0x30a85251f23672b4)  # decrypts to 0x30a85251f23672b4
    faker.hidden_write(shellcodes[5] + 3559, 0xb24bec7fde981eda)  # decrypts to 0xb24bec7fde981eda
    faker.hidden_write(shellcodes[7] + 6399, 0xc83b9004253c60a)  # decrypts to 0xc83b9004253c60a
    faker.hidden_write(shellcodes[3] + 6568, 0x7600e61ee372c0d6)  # decrypts to 0x7600e61ee372c0d6
    faker.hidden_write(shellcodes[4] + 5801, 0xad03c904d7641290)  # decrypts to 0xad03c904d7641290
    faker.hidden_write(shellcodes[1] + 3513, 0x1fae2b53b6f97a6e)  # decrypts to 0x1fae2b53b6f97a6e
    faker.hidden_write(shellcodes[6] + 5814, 0xb40bfd8cf4b638c3)  # decrypts to 0xb40bfd8cf4b638c3
    faker.hidden_write(shellcodes[7] + 3708, 0x9bb5b66b52696803)  # decrypts to 0x9bb5b66b52696803
    faker.hidden_write(shellcodes[2] + 6386, 0xede5111fd6d1e6f2)  # decrypts to 0xede5111fd6d1e6f2
    faker.hidden_write(shellcodes[4] + 3604, 0x9fac9a1fcb83ed1f)  # decrypts to 0x9fac9a1fcb83ed1f
    faker.hidden_write(shellcodes[4] + 4462, 0x2707e60411d6e42c)  # decrypts to 0x2707e60411d6e42c
    faker.hidden_write(shellcodes[0] + 6269, 0x622b2532bc6ecb3c)  # decrypts to 0x622b2532bc6ecb3c
    faker.hidden_write(shellcodes[3] + 4033, 0x89a1d63a75d69b1b)  # decrypts to 0x89a1d63a75d69b1b
    faker.hidden_write(shellcodes[4] + 3526, 0x5134a522cb626f0d)  # decrypts to 0x5134a522cb626f0d
    faker.hidden_write(shellcodes[4] + 3448, 0xa17007b9b5f625bb)  # decrypts to 0xa17007b9b5f625bb
    faker.hidden_write(shellcodes[5] + 3897, 0xf90cd597734a230a)  # decrypts to 0xf90cd597734a230a
    faker.hidden_write(shellcodes[7] + 4293, 0xa4d393570e6afaa2)  # decrypts to 0xa4d393570e6afaa2
    faker.hidden_write(shellcodes[1] + 4709, 0xfb96298d2909272d)  # decrypts to 0xfb96298d2909272d
    faker.hidden_write(shellcodes[6] + 6282, 0x2ffb19b6a76642bd)  # decrypts to 0x2ffb19b6a76642bd
    faker.hidden_write(shellcodes[3] + 6139, 0x9b6a70f6a24463b1)  # decrypts to 0x9b6a70f6a24463b1
    faker.hidden_write(shellcodes[5] + 4989, 0xf292e683317388e2)  # decrypts to 0xf292e683317388e2
    faker.hidden_write(shellcodes[5] + 6172, 0xe712a273aae840b2)  # decrypts to 0xe712a273aae840b2
    faker.hidden_write(shellcodes[2] + 3786, 0xdcad4817c5612a62)  # decrypts to 0xdcad4817c5612a62
    faker.hidden_write(shellcodes[2] + 4449, 0xee215f94a6ddf39b)  # decrypts to 0xee215f94a6ddf39b
    faker.hidden_write(shellcodes[3] + 3695, 0x8c5ef88cb3c8cc16)  # decrypts to 0x8c5ef88cb3c8cc16
    faker.hidden_write(shellcodes[4] + 3877, 0x95aa94bb62f5f339)  # decrypts to 0x95aa94bb62f5f339
    faker.hidden_write(shellcodes[0] + 4670, 0xf74c00f44675bbf4)  # decrypts to 0xf74c00f44675bbf4
    faker.hidden_write(shellcodes[4] + 6646, 0xf87e8143562fb9fe)  # decrypts to 0xf87e8143562fb9fe
    faker.hidden_write(shellcodes[4] + 3396, 0x31f637ebbe2dcc80)  # decrypts to 0x31f637ebbe2dcc80
    faker.hidden_write(shellcodes[3] + 4722, 0x18717fe1125252d7)  # decrypts to 0x18717fe1125252d7
    faker.hidden_write(shellcodes[0] + 4553, 0x6a7ddbb9c050edb3)  # decrypts to 0x6a7ddbb9c050edb3
    faker.hidden_write(shellcodes[2] + 5138, 0x2dcca641a4139ebf)  # decrypts to 0x2dcca641a4139ebf
    faker.hidden_write(shellcodes[7] + 5996, 0xcbdb2ecd12508466)  # decrypts to 0xcbdb2ecd12508466
    faker.hidden_write(shellcodes[2] + 6711, 0x713b9922346d8e13)  # decrypts to 0x713b9922346d8e13
    faker.hidden_write(shellcodes[3] + 5931, 0xcacc58b4a967fc03)  # decrypts to 0xcacc58b4a967fc03
    faker.hidden_write(shellcodes[6] + 4228, 0x16e81ac9c7d74102)  # decrypts to 0x16e81ac9c7d74102
    faker.hidden_write(shellcodes[3] + 5138, 0x2ef57cfc7222e9b4)  # decrypts to 0x2ef57cfc7222e9b4
    faker.hidden_write(shellcodes[3] + 6711, 0x72b5d3bb9bbcb66)  # decrypts to 0x72b5d3bb9bbcb66
    faker.hidden_write(shellcodes[4] + 5099, 0x80d3ae3c001b6773)  # decrypts to 0x80d3ae3c001b6773
    faker.hidden_write(shellcodes[0] + 5034, 0xe6e5d0e88d6665f)  # decrypts to 0xe6e5d0e88d6665f
    faker.hidden_write(shellcodes[5] + 5899, 0xcd04507750679aa1)  # decrypts to 0xcd04507750679aa1
    faker.hidden_write(shellcodes[3] + 4592, 0x93a42d5953ef8c3e)  # decrypts to 0x93a42d5953ef8c3e
    faker.hidden_write(shellcodes[0] + 6360, 0xe53717fe2f2ddb1a)  # decrypts to 0xe53717fe2f2ddb1a
    faker.hidden_write(shellcodes[1] + 6113, 0x1ce2416a75c241df)  # decrypts to 0x1ce2416a75c241df
    faker.hidden_write(shellcodes[3] + 5658, 0xd9e3165ff3180eec)  # decrypts to 0xd9e3165ff3180eec
    faker.hidden_write(shellcodes[6] + 5008, 0x43cc7079a836f066)  # decrypts to 0x43cc7079a836f066
    faker.hidden_write(shellcodes[7] + 5411, 0xcdfd894db5e164d2)  # decrypts to 0xcdfd894db5e164d2
    faker.hidden_write(shellcodes[6] + 4787, 0x622fabb5bbafd6d8)  # decrypts to 0x622fabb5bbafd6d8
    faker.hidden_write(shellcodes[7] + 4111, 0xf5149c9b1cc68de)  # decrypts to 0xf5149c9b1cc68de
    faker.hidden_write(shellcodes[3] + 6399, 0x49fee31739f440cb)  # decrypts to 0x49fee31739f440cb
    faker.hidden_write(shellcodes[5] + 5353, 0xe33df119db1500ca)  # decrypts to 0xe33df119db1500ca
    faker.hidden_write(shellcodes[6] + 6685, 0x667f6f1f3fb8c15c)  # decrypts to 0x667f6f1f3fb8c15c
    faker.hidden_write(shellcodes[1] + 5021, 0xcd21e1e7c13f8f9)  # decrypts to 0xcd21e1e7c13f8f9
    faker.hidden_write(shellcodes[7] + 4982, 0x10b85f0fa452d458)  # decrypts to 0x10b85f0fa452d458
    faker.hidden_write(shellcodes[7] + 5190, 0xcbe3e0770c2b81fc)  # decrypts to 0xcbe3e0770c2b81fc
    faker.hidden_write(shellcodes[4] + 3838, 0xfa5eea8f3af1aa31)  # decrypts to 0xfa5eea8f3af1aa31
    faker.hidden_write(shellcodes[2] + 3656, 0x71b7356e74ac3335)  # decrypts to 0x71b7356e74ac3335
    faker.hidden_write(shellcodes[7] + 5021, 0xa276799f306f7b9d)  # decrypts to 0xa276799f306f7b9d
    faker.hidden_write(shellcodes[0] + 4462, 0x431c827d5f1b901d)  # decrypts to 0x431c827d5f1b901d
    faker.hidden_write(shellcodes[2] + 3721, 0x9ae494ac692a0de7)  # decrypts to 0x9ae494ac692a0de7
    faker.hidden_write(shellcodes[3] + 3864, 0xe1495f2afa1449a6)  # decrypts to 0xe1495f2afa1449a6
    faker.hidden_write(shellcodes[5] + 5392, 0x4dcd8410a34c93c1)  # decrypts to 0x4dcd8410a34c93c1
    faker.hidden_write(shellcodes[4] + 4137, 0x85a970e4b4830456)  # decrypts to 0x85a970e4b4830456
    faker.hidden_write(shellcodes[5] + 4027, 0x3bb19d13496c50d2)  # decrypts to 0x3bb19d13496c50d2
    faker.hidden_write(shellcodes[0] + 4072, 0xc2836311441e51f2)  # decrypts to 0xc2836311441e51f2
    faker.hidden_write(shellcodes[6] + 5034, 0x99ce1d008fcc35b2)  # decrypts to 0x99ce1d008fcc35b2
    faker.hidden_write(shellcodes[5] + 5340, 0xccbf89dfc0241518)  # decrypts to 0xccbf89dfc0241518
    faker.hidden_write(shellcodes[0] + 3903, 0x41844b88c65faf80)  # decrypts to 0x41844b88c65faf80
    faker.hidden_write(shellcodes[7] + 4566, 0xe6c5b291de440aa0)  # decrypts to 0xe6c5b291de440aa0
    faker.hidden_write(shellcodes[0] + 5905, 0x2ae30930e88f6e2e)  # decrypts to 0x2ae30930e88f6e2e
    faker.hidden_write(shellcodes[7] + 4436, 0xdb75b336f9bef09a)  # decrypts to 0xdb75b336f9bef09a
    faker.hidden_write(shellcodes[3] + 6451, 0xd477b17a83393990)  # decrypts to 0xd477b17a83393990
    faker.hidden_write(shellcodes[1] + 3604, 0x27aa93f3205b4e68)  # decrypts to 0x27aa93f3205b4e68
    faker.hidden_write(shellcodes[3] + 4228, 0xb7b0fa0b08b1197c)  # decrypts to 0xb7b0fa0b08b1197c
    faker.hidden_write(shellcodes[7] + 4852, 0x333b266ea406e150)  # decrypts to 0x333b266ea406e150
    faker.hidden_write(shellcodes[0] + 3461, 0x34b12b727f6e1963)  # decrypts to 0x34b12b727f6e1963
    faker.hidden_write(shellcodes[6] + 5944, 0x6e234ed9da9f957e)  # decrypts to 0x6e234ed9da9f957e
    faker.hidden_write(shellcodes[5] + 6614, 0x5da2bbbb78eac344)  # decrypts to 0x5da2bbbb78eac344
    faker.hidden_write(shellcodes[3] + 3981, 0xfdce5a548ef06e18)  # decrypts to 0xfdce5a548ef06e18
    faker.hidden_write(shellcodes[2] + 4540, 0x611ff4ca53c1137e)  # decrypts to 0x611ff4ca53c1137e
    faker.hidden_write(shellcodes[2] + 6581, 0x531ed2357ae2ebdb)  # decrypts to 0x531ed2357ae2ebdb
    faker.hidden_write(shellcodes[2] + 4774, 0x12d3e9eb238a312d)  # decrypts to 0x12d3e9eb238a312d
    faker.hidden_write(shellcodes[4] + 5021, 0xfbca29728201dbf8)  # decrypts to 0xfbca29728201dbf8
    faker.hidden_write(shellcodes[6] + 6464, 0x69517cfc60860799)  # decrypts to 0x69517cfc60860799
    faker.hidden_write(shellcodes[7] + 3539, 0xbf5171c34c0833f9)  # decrypts to 0xbf5171c34c0833f9
    faker.hidden_write(shellcodes[7] + 6295, 0x49e464a6cac788b4)  # decrypts to 0x49e464a6cac788b4
    faker.hidden_write(shellcodes[5] + 6471, 0x58536879aaf6a2f2)  # decrypts to 0x58536879aaf6a2f2
    faker.hidden_write(shellcodes[6] + 6698, 0x8be9809cc8c98b55)  # decrypts to 0x8be9809cc8c98b55
    faker.hidden_write(shellcodes[1] + 5567, 0x6738e336d1ea9aeb)  # decrypts to 0x6738e336d1ea9aeb
    faker.hidden_write(shellcodes[7] + 5463, 0x5b0c75ae4bf8ac4e)  # decrypts to 0x5b0c75ae4bf8ac4e
    faker.hidden_write(shellcodes[3] + 4319, 0xa732f63a92f9548)  # decrypts to 0xa732f63a92f9548
    faker.hidden_write(shellcodes[2] + 6230, 0x8694a6a5b1202bcf)  # decrypts to 0x8694a6a5b1202bcf
    faker.hidden_write(shellcodes[7] + 3682, 0x8a39dd2a4a40bcd9)  # decrypts to 0x8a39dd2a4a40bcd9
    faker.hidden_write(shellcodes[2] + 4644, 0x46d8d2d3c1390512)  # decrypts to 0x46d8d2d3c1390512
    faker.hidden_write(shellcodes[3] + 6191, 0x34641ad0e74f854a)  # decrypts to 0x34641ad0e74f854a
    faker.hidden_write(shellcodes[1] + 5905, 0xc668407c39673a98)  # decrypts to 0xc668407c39673a98
    faker.hidden_write(shellcodes[1] + 5086, 0xfde53231b77252de)  # decrypts to 0xfde53231b77252de
    faker.hidden_write(shellcodes[2] + 3838, 0x77fc516eaaf02908)  # decrypts to 0x77fc516eaaf02908
    faker.hidden_write(shellcodes[3] + 3786, 0xf8eb47aa4efd400d)  # decrypts to 0xf8eb47aa4efd400d
    faker.hidden_write(shellcodes[5] + 6237, 0xde52b7360d09b10c)  # decrypts to 0xde52b7360d09b10c
    faker.hidden_write(shellcodes[5] + 5457, 0x815117514e01e1f4)  # decrypts to 0x815117514e01e1f4
    faker.hidden_write(shellcodes[7] + 6243, 0xd9ffdb7ceeb4bafb)  # decrypts to 0xd9ffdb7ceeb4bafb
    faker.hidden_write(shellcodes[0] + 5177, 0x60a36bb0f8bacdd7)  # decrypts to 0x60a36bb0f8bacdd7
    faker.hidden_write(shellcodes[6] + 3942, 0x1145061281ba9fdc)  # decrypts to 0x1145061281ba9fdc
    faker.hidden_write(shellcodes[5] + 3598, 0xc27f6bcb02fd09e)  # decrypts to 0xc27f6bcb02fd09e
    faker.hidden_write(shellcodes[3] + 4735, 0x72ee9c7bd492cdff)  # decrypts to 0x72ee9c7bd492cdff
    faker.hidden_write(shellcodes[4] + 3422, 0x1262ae3150937736)  # decrypts to 0x1262ae3150937736
    faker.hidden_write(shellcodes[4] + 5138, 0x2115679f94b94e45)  # decrypts to 0x2115679f94b94e45
    faker.hidden_write(shellcodes[1] + 4345, 0xef6746504247d6d3)  # decrypts to 0xef6746504247d6d3
    faker.hidden_write(shellcodes[5] + 4547, 0x837dd8ef66d20184)  # decrypts to 0x837dd8ef66d20184
    faker.hidden_write(shellcodes[5] + 3871, 0x19cd1961443e5f5b)  # decrypts to 0x19cd1961443e5f5b
    faker.hidden_write(shellcodes[4] + 3799, 0x39d3ddcb63f60682)  # decrypts to 0x39d3ddcb63f60682
    faker.hidden_write(shellcodes[7] + 3578, 0x4590b25aea405436)  # decrypts to 0x4590b25aea405436
    faker.hidden_write(shellcodes[0] + 5944, 0x4dee3d299706481a)  # decrypts to 0x4dee3d299706481a
    faker.hidden_write(shellcodes[3] + 3747, 0x1e499219763764be)  # decrypts to 0x1e499219763764be
    faker.hidden_write(shellcodes[7] + 4007, 0x194a31bd975e00f5)  # decrypts to 0x194a31bd975e00f5
    faker.hidden_write(shellcodes[6] + 4709, 0xa01faa86d5b6697)  # decrypts to 0xa01faa86d5b6697
    faker.hidden_write(shellcodes[4] + 4228, 0x54307f02e6a02c5d)  # decrypts to 0x54307f02e6a02c5d
    faker.hidden_write(shellcodes[5] + 4456, 0xca211c54cc45e7d6)  # decrypts to 0xca211c54cc45e7d6
    faker.hidden_write(shellcodes[5] + 3442, 0x58dd38bb948fa4f4)  # decrypts to 0x58dd38bb948fa4f4
    faker.hidden_write(shellcodes[0] + 3825, 0x946d63a6e4c9980c)  # decrypts to 0x946d63a6e4c9980c
    faker.hidden_write(shellcodes[2] + 4319, 0x8b23e7a0ea2b54db)  # decrypts to 0x8b23e7a0ea2b54db
    faker.hidden_write(shellcodes[1] + 6347, 0x1cea70c373b1b893)  # decrypts to 0x1cea70c373b1b893
    faker.hidden_write(shellcodes[2] + 4241, 0x1ec1a63fd421376)  # decrypts to 0x1ec1a63fd421376
    faker.hidden_write(shellcodes[4] + 5008, 0x77f6494ac2463092)  # decrypts to 0x77f6494ac2463092
    faker.hidden_write(shellcodes[3] + 6113, 0x79ea15c375a8bd5)  # decrypts to 0x79ea15c375a8bd5
    faker.hidden_write(shellcodes[3] + 4943, 0x5cda5101688d2238)  # decrypts to 0x5cda5101688d2238
    faker.hidden_write(shellcodes[6] + 5398, 0x495aa4571ab3562)  # decrypts to 0x495aa4571ab3562
    faker.hidden_write(shellcodes[4] + 3474, 0x13afd2cf2db67267)  # decrypts to 0x13afd2cf2db67267
    faker.hidden_write(shellcodes[1] + 4124, 0x14a59c62daf1c46c)  # decrypts to 0x14a59c62daf1c46c
    faker.hidden_write(shellcodes[2] + 6477, 0x914191df33dffed8)  # decrypts to 0x914191df33dffed8
    faker.hidden_write(shellcodes[1] + 4098, 0x347652dd055a93f8)  # decrypts to 0x347652dd055a93f8
    faker.hidden_write(shellcodes[0] + 4332, 0x4c7c9cfa9a49fd5a)  # decrypts to 0x4c7c9cfa9a49fd5a
    faker.hidden_write(shellcodes[1] + 4293, 0xcd3e125c1accc797)  # decrypts to 0xcd3e125c1accc797
    faker.hidden_write(shellcodes[1] + 4878, 0xcec29c6d061f81c2)  # decrypts to 0xcec29c6d061f81c2
    faker.hidden_write(shellcodes[4] + 3630, 0x3e5eebcb62c6aff9)  # decrypts to 0x3e5eebcb62c6aff9
    faker.hidden_write(shellcodes[1] + 4111, 0x451c25fc907f402e)  # decrypts to 0x451c25fc907f402e
    faker.hidden_write(shellcodes[3] + 5242, 0x913f5ef9e0d3682b)  # decrypts to 0x913f5ef9e0d3682b
    faker.hidden_write(shellcodes[0] + 3682, 0xce047d002b003a7b)  # decrypts to 0xce047d002b003a7b
    faker.hidden_write(shellcodes[7] + 6477, 0x4768a0fe75ae8398)  # decrypts to 0x4768a0fe75ae8398
    faker.hidden_write(shellcodes[0] + 4917, 0x1e557ec04496aac)  # decrypts to 0x1e557ec04496aac
    faker.hidden_write(shellcodes[7] + 4670, 0x1c1b22590dee755a)  # decrypts to 0x1c1b22590dee755a
    faker.hidden_write(shellcodes[2] + 4631, 0xff47ca9931315428)  # decrypts to 0xff47ca9931315428
    faker.hidden_write(shellcodes[4] + 4345, 0x50aafce0673747f6)  # decrypts to 0x50aafce0673747f6
    faker.hidden_write(shellcodes[6] + 6178, 0x59a08b72bdfd6f0c)  # decrypts to 0x59a08b72bdfd6f0c
    faker.hidden_write(shellcodes[5] + 3754, 0x862c5efff8999c78)  # decrypts to 0x862c5efff8999c78
    faker.hidden_write(shellcodes[3] + 4670, 0x9a7564f9b8db8bc6)  # decrypts to 0x9a7564f9b8db8bc6
    faker.hidden_write(shellcodes[7] + 6711, 0x5af5b2bf0e2d8bed)  # decrypts to 0x5af5b2bf0e2d8bed
    faker.hidden_write(shellcodes[5] + 3377, 0xf6643557a5fba68b)  # decrypts to 0xf6643557a5fba68b
    faker.hidden_write(shellcodes[5] + 6003, 0x13b20a0d9cc298e)  # decrypts to 0x13b20a0d9cc298e
    faker.hidden_write(shellcodes[1] + 3422, 0x61264a21e56c669d)  # decrypts to 0x61264a21e56c669d
    faker.hidden_write(shellcodes[1] + 6178, 0x8d50bf6ff9052381)  # decrypts to 0x8d50bf6ff9052381
    faker.hidden_write(shellcodes[6] + 5086, 0x64dae5e56bec6999)  # decrypts to 0x64dae5e56bec6999
    faker.hidden_write(shellcodes[6] + 4618, 0xb6bbd5ff18962397)  # decrypts to 0xb6bbd5ff18962397
    faker.hidden_write(shellcodes[3] + 3994, 0xe5458284a68b2e2a)  # decrypts to 0xe5458284a68b2e2a
    faker.hidden_write(shellcodes[4] + 6451, 0x37bcd4fc17035eaa)  # decrypts to 0x37bcd4fc17035eaa
    faker.hidden_write(shellcodes[7] + 3487, 0x9ccf57b08e77e1da)  # decrypts to 0x9ccf57b08e77e1da
    faker.hidden_write(shellcodes[3] + 4527, 0x47f0317cf910b23a)  # decrypts to 0x47f0317cf910b23a
    faker.hidden_write(shellcodes[1] + 3994, 0x67254dccaefd2771)  # decrypts to 0x67254dccaefd2771
    faker.hidden_write(shellcodes[0] + 6100, 0x8d281685d5ac02ca)  # decrypts to 0x8d281685d5ac02ca
    faker.hidden_write(shellcodes[4] + 3773, 0x38a00c881ac1fcf6)  # decrypts to 0x38a00c881ac1fcf6
    faker.hidden_write(shellcodes[5] + 4742, 0x9305f2f8a3e80a89)  # decrypts to 0x9305f2f8a3e80a89
    faker.hidden_write(shellcodes[7] + 3799, 0x827c4ce5f58696c6)  # decrypts to 0x827c4ce5f58696c6
    faker.hidden_write(shellcodes[6] + 5918, 0x121f019ec80bc4fb)  # decrypts to 0x121f019ec80bc4fb
    faker.hidden_write(shellcodes[1] + 4553, 0xbe236ae95d098a20)  # decrypts to 0xbe236ae95d098a20
    faker.hidden_write(shellcodes[0] + 5554, 0x9f4c3c935e8d2a80)  # decrypts to 0x9f4c3c935e8d2a80
    faker.hidden_write(shellcodes[3] + 5528, 0x6a92661e934e2582)  # decrypts to 0x6a92661e934e2582
    faker.hidden_write(shellcodes[7] + 6412, 0xf766f2956f6b7841)  # decrypts to 0xf766f2956f6b7841
    faker.hidden_write(shellcodes[6] + 6412, 0x21dd16ac50a8ce17)  # decrypts to 0x21dd16ac50a8ce17
    faker.hidden_write(shellcodes[2] + 5905, 0x4bf5b330ce3fbcb4)  # decrypts to 0x4bf5b330ce3fbcb4
    faker.hidden_write(shellcodes[0] + 5892, 0xba6c8514803bfebe)  # decrypts to 0xba6c8514803bfebe
    faker.hidden_write(shellcodes[4] + 5125, 0xf80ac9eeedb33918)  # decrypts to 0xf80ac9eeedb33918
    faker.hidden_write(shellcodes[3] + 6048, 0xee90950bf416280)  # decrypts to 0xee90950bf416280
    faker.hidden_write(shellcodes[1] + 4137, 0xc176a1227884993e)  # decrypts to 0xc176a1227884993e
    faker.hidden_write(shellcodes[5] + 5080, 0xfc1f6b9ff7cf5457)  # decrypts to 0xfc1f6b9ff7cf5457
    faker.hidden_write(shellcodes[7] + 4995, 0xbd18695fac5ffc67)  # decrypts to 0xbd18695fac5ffc67
    faker.hidden_write(shellcodes[0] + 5853, 0x9bd68e7f2437abdb)  # decrypts to 0x9bd68e7f2437abdb
    faker.hidden_write(shellcodes[4] + 5047, 0xcffd5a48e91b092f)  # decrypts to 0xcffd5a48e91b092f
    faker.hidden_write(shellcodes[2] + 3630, 0xe4b5f6d54b2283fa)  # decrypts to 0xe4b5f6d54b2283fa
    faker.hidden_write(shellcodes[3] + 3734, 0xf6e57589a8beb30b)  # decrypts to 0xf6e57589a8beb30b
    faker.hidden_write(shellcodes[7] + 5710, 0x8a463cec49c50cff)  # decrypts to 0x8a463cec49c50cff
    faker.hidden_write(shellcodes[5] + 3624, 0x7cd70d9b1b5f1677)  # decrypts to 0x7cd70d9b1b5f1677
    faker.hidden_write(shellcodes[1] + 4202, 0xcce3045433274000)  # decrypts to 0xcce3045433274000
    faker.hidden_write(shellcodes[1] + 5684, 0x1addb22c3e344e19)  # decrypts to 0x1addb22c3e344e19
    faker.hidden_write(shellcodes[2] + 3929, 0xbe57ebc1be0e5ecd)  # decrypts to 0xbe57ebc1be0e5ecd
    faker.hidden_write(shellcodes[5] + 3572, 0x512c03bbfb413203)  # decrypts to 0x512c03bbfb413203
    faker.hidden_write(shellcodes[1] + 4449, 0x86b07594d74e412b)  # decrypts to 0x86b07594d74e412b
    faker.hidden_write(shellcodes[3] + 5164, 0x9b4c380a990bd5e1)  # decrypts to 0x9b4c380a990bd5e1
    faker.hidden_write(shellcodes[5] + 4326, 0x991e0d35c05e8b87)  # decrypts to 0x991e0d35c05e8b87
    faker.hidden_write(shellcodes[7] + 3955, 0xbbca1ae832dc79ff)  # decrypts to 0xbbca1ae832dc79ff
    faker.hidden_write(shellcodes[0] + 4345, 0x4c69b7df64a7e2ca)  # decrypts to 0x4c69b7df64a7e2ca
    faker.hidden_write(shellcodes[7] + 4969, 0xdf99d926d2fe6e22)  # decrypts to 0xdf99d926d2fe6e22
    faker.hidden_write(shellcodes[6] + 6607, 0x207ed0243db6a79f)  # decrypts to 0x207ed0243db6a79f
    faker.hidden_write(shellcodes[2] + 5333, 0xddafb8c19c36a571)  # decrypts to 0xddafb8c19c36a571
    faker.hidden_write(shellcodes[3] + 4800, 0xd472be706eeb117c)  # decrypts to 0xd472be706eeb117c
    faker.hidden_write(shellcodes[1] + 4826, 0x20df3eb3c013bbdd)  # decrypts to 0x20df3eb3c013bbdd
    faker.hidden_write(shellcodes[3] + 6412, 0xdd8798f64fd7b093)  # decrypts to 0xdd8798f64fd7b093
    faker.hidden_write(shellcodes[2] + 5125, 0x4fb7c409c61f454)  # decrypts to 0x4fb7c409c61f454
    faker.hidden_write(shellcodes[4] + 6308, 0xe59c49f327dd7609)  # decrypts to 0xe59c49f327dd7609
    faker.hidden_write(shellcodes[0] + 4033, 0x2dea2161c019f2be)  # decrypts to 0x2dea2161c019f2be
    faker.hidden_write(shellcodes[1] + 5437, 0xab181cbe6af3ce93)  # decrypts to 0xab181cbe6af3ce93
    faker.hidden_write(shellcodes[0] + 5697, 0xce5f14ea636d61d6)  # decrypts to 0xce5f14ea636d61d6
    faker.hidden_write(shellcodes[6] + 4566, 0xe9ac10599c3a6c66)  # decrypts to 0xe9ac10599c3a6c66
    faker.hidden_write(shellcodes[5] + 4560, 0x42a8d6a7a963536b)  # decrypts to 0x42a8d6a7a963536b
    faker.hidden_write(shellcodes[7] + 5112, 0x7aa85f2b8cd58e23)  # decrypts to 0x7aa85f2b8cd58e23
    faker.hidden_write(shellcodes[2] + 4332, 0xd2143386ee02f529)  # decrypts to 0xd2143386ee02f529
    faker.hidden_write(shellcodes[7] + 5593, 0x40b826be7392042e)  # decrypts to 0x40b826be7392042e
    faker.hidden_write(shellcodes[2] + 5281, 0x28204deb947a1242)  # decrypts to 0x28204deb947a1242
    faker.hidden_write(shellcodes[7] + 5645, 0x6b44cb84323b63eb)  # decrypts to 0x6b44cb84323b63eb
    faker.hidden_write(shellcodes[1] + 4007, 0xbf62af7435dcadae)  # decrypts to 0xbf62af7435dcadae
    faker.hidden_write(shellcodes[0] + 4852, 0x58f8d69844139633)  # decrypts to 0x58f8d69844139633
    faker.hidden_write(shellcodes[7] + 3916, 0xa29ca83c6ab44be)  # decrypts to 0xa29ca83c6ab44be
    faker.hidden_write(shellcodes[0] + 6659, 0x2bd48887a627afbc)  # decrypts to 0x2bd48887a627afbc
    faker.hidden_write(shellcodes[1] + 4332, 0x17de820dd4d742b4)  # decrypts to 0x17de820dd4d742b4
    faker.hidden_write(shellcodes[5] + 4885, 0x8ccb9f9c808f6c6a)  # decrypts to 0x8ccb9f9c808f6c6a
    faker.hidden_write(shellcodes[4] + 4800, 0xfa9cd2d46ce7ab18)  # decrypts to 0xfa9cd2d46ce7ab18
    faker.hidden_write(shellcodes[0] + 3409, 0x82cf7c8f519b37d8)  # decrypts to 0x82cf7c8f519b37d8
    faker.hidden_write(shellcodes[3] + 3916, 0x404d7062c026c2e4)  # decrypts to 0x404d7062c026c2e4
    faker.hidden_write(shellcodes[2] + 4189, 0xd9dd2d8c75f69d35)  # decrypts to 0xd9dd2d8c75f69d35
    faker.hidden_write(shellcodes[1] + 4982, 0xa3b166d24430a9bf)  # decrypts to 0xa3b166d24430a9bf
    faker.hidden_write(shellcodes[5] + 3936, 0x1c7ccf7f029f751a)  # decrypts to 0x1c7ccf7f029f751a
    faker.hidden_write(shellcodes[7] + 6269, 0x50cbfec425af6f66)  # decrypts to 0x50cbfec425af6f66
    faker.hidden_write(shellcodes[2] + 5827, 0x6e045f7e6a371959)  # decrypts to 0x6e045f7e6a371959
    faker.hidden_write(shellcodes[7] + 5359, 0x703e5de19694007f)  # decrypts to 0x703e5de19694007f
    faker.hidden_write(shellcodes[3] + 6087, 0x8963b87f46475574)  # decrypts to 0x8963b87f46475574
    faker.hidden_write(shellcodes[3] + 6009, 0x3552021b87c30b8e)  # decrypts to 0x3552021b87c30b8e
    faker.hidden_write(shellcodes[5] + 5691, 0x81bc572dc00770d6)  # decrypts to 0x81bc572dc00770d6
    faker.hidden_write(shellcodes[7] + 4904, 0x73c155deb554aabe)  # decrypts to 0x73c155deb554aabe

    faker.build('./main')
    print('done')


if __name__ == '__main__':
    chal()
