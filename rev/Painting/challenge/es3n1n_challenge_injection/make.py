from pefile import PE

pe = PE(r'C:\Users\es3n1n\source\repos\mspaint\x64\Release\mspaint.dll')
payload_sec = pe.sections[0]
payload = payload_sec.get_data()
entry_rrva = pe.OPTIONAL_HEADER.AddressOfEntryPoint - payload_sec.VirtualAddress
print(hex(entry_rrva), type(payload_sec))

patch = 0x14003582A
start = 0x14065AA00
entry = start + entry_rrva
print(hex(entry))

tgt_path = r'C:\Users\es3n1n\Desktop\paint_chal\chall.exe'
with open(tgt_path, 'rb') as f:
    tgt_bin = bytearray(f.read())

path_fo = 0x34c2A
tgt_bin[path_fo:path_fo+5] = b'\xE8' + int.to_bytes(entry - patch - 5, 4, 'little')

with open(tgt_path, 'wb') as f:
    f.write(tgt_bin)

reloc = open('./reloc.bin', 'rb').read()
open('./reloc2.bin', 'wb').write(reloc + payload)

"""
patch = 0x14003582A

reloc = open('./reloc.bin', 'rb').read()
payload = open('./payload.bin', 'rb').read()
out = reloc + payload

start = 0x14065AA00
entry = start + 0x00001690 - 0x00001000
print(f'entry at {entry:#x}')

code = 'E8 '
for c in int.to_bytes(entry - patch - 5, 4, 'little'):
    code += hex(c)[2:].upper() + ' '
print(code)

open('./reloc2.bin', 'wb').write(out)
"""