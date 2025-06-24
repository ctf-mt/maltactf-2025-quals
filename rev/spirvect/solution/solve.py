from PIL import Image
import string

def recover_key(path: str = "output.png") -> bytes:
    img = Image.open(path).convert("RGBA")
    w, h = img.size
    C = {i: [set(range(256)) for _ in range(4)] for i in range(10)}

    for y in range(h):
        for x in range(w):
            idx = (x + y * w) % 10
            s   = (x * y) & 0xFF
            r, g, b, a = img.getpixel((x, y))
            m = [(s ^ 0xED) & 0xFF,
                 (s ^ 0xFA) & 0xFF,
                 (s ^ 0xAD) & 0xFF,
                 (s ^ 0xBA) & 0xFF]

            for j, ch in enumerate((r, g, b, a)):
                C[idx][j] = {k for k in C[idx][j] if (k * m[j]) & 0xFF == ch}

    key = []
    printable = {ord(c) for c in string.printable}
    for idx in range(10):
        for j in range(4):
            k = next((x for x in sorted(C[idx][j]) if x in printable),
                     next(iter(C[idx][j])))
            key.append(k)

    return bytes(key)

if __name__ == "__main__":
    print(recover_key().decode())
