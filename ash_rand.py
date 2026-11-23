def randomize_ash(data: bytes) -> bytes:
    """Applique ou retire le masque pseudo-aléatoire ASHv2 (seed 0x42)."""
    lfsr = 0x42
    out = bytearray()

    for b in data:
        out.append(b ^ lfsr)
        if lfsr & 0x01:
            lfsr = ((lfsr >> 1) ^ 0xB8) & 0xFF
        else:
            lfsr = (lfsr >> 1) & 0xFF

    return bytes(out)


if __name__ == "__main__":
    sample = bytes.fromhex("00 01 02 03 04")
    masked = randomize_ash(sample)
    unmasked = randomize_ash(masked)

    print("Original :", sample.hex(" ").upper())
    print("Masqué   :", masked.hex(" ").upper())
    print("Démasqué :", unmasked.hex(" ").upper())
    print("Identique:", unmasked == sample)