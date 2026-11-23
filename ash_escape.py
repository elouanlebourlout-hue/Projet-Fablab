ESCAPE_BYTE = 0x7D
FLAG_BYTE = 0x7E
BYTES_TO_ESCAPE = {0x7E, 0x7D, 0x11, 0x13, 0x18, 0x1A}


def stuff_bytes(data: bytes) -> bytes:
    """Échappe les octets réservés ASHv2 avec 0x7D (XOR 0x20)."""
    out = bytearray()
    for b in data:
        if b in BYTES_TO_ESCAPE:
            out.append(ESCAPE_BYTE)
            out.append(b ^ 0x20)
        else:
            out.append(b)
    return bytes(out)


def unstuff_bytes(data: bytes) -> bytes:
    """Restaure les octets échappés par 0x7D."""
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == ESCAPE_BYTE:
            if i + 1 >= len(data):
                raise ValueError("Séquence d'échappement incomplète en fin de trame")
            out.append(data[i + 1] ^ 0x20)
            i += 2
        else:
            out.append(b)
            i += 1
    return bytes(out)


if __name__ == "__main__":
    sample = bytes([0x01, 0x7E, 0x7D, 0x11, 0x1A, 0x05])
    stuffed = stuff_bytes(sample)
    unstuffed = unstuff_bytes(stuffed)

    print("Original :", sample.hex(" ").upper())
    print("Stuffed  :", stuffed.hex(" ").upper())
    print("Unstuffed:", unstuffed.hex(" ").upper())
    print("Identique:", unstuffed == sample)