def crc16_ccitt(data: bytes) -> int:
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc


def crc16_bytes(data: bytes) -> bytes:
    val = crc16_ccitt(data)
    return bytes([(val >> 8) & 0xFF, val & 0xFF])
    
def verify_ash_frame(frame: bytes) -> bool:
    """Vérifie le CRC-16 d'une trame ASH (sans l'octet 0x7E final)."""
    if frame.startswith(b"\x1a"):
        frame = frame[1:]
    if len(frame) < 3:
        return False
    payload, received_crc = frame[:-2], frame[-2:]
    return crc16_bytes(payload) == received_crc

if __name__ == "__main__":
    rst_payload = bytes([0xC0])
    calc = crc16_bytes(rst_payload)
    print("CRC calculé pour [C0] :", calc.hex(" ").upper())

    sample_rstack = bytes.fromhex("1A C1 02 0B 0A 52")
    print("RSTACK CRC valide ?    :", verify_ash_frame(sample_rstack))