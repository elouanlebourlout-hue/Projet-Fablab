from ash_crc import crc16_bytes, verify_ash_frame
from ash_escape import FLAG_BYTE, stuff_bytes, unstuff_bytes
from ash_rand import randomize_ash


def build_ack_frame(ack_num: int = 0) -> bytes:
    """Construit une trame ACK ASHv2 : octet de contrôle 0x80 | (ack_num & 0x07)."""
    control = 0x80 | (ack_num & 0x07)
    raw = bytes([control]) + crc16_bytes(bytes([control]))
    return stuff_bytes(raw) + bytes([FLAG_BYTE])


def build_data_frame(frm_num: int, ack_num: int, ezsp_payload: bytes, retransmit: bool = False) -> bytes:
    """Construit une trame DATA ASHv2 : contrôle, payload randomisé, CRC-16, stuffing + 0x7E."""
    control = ((frm_num & 0x07) << 4) | ((1 if retransmit else 0) << 3) | (ack_num & 0x07)
    header = bytes([control])
    randomized_payload = randomize_ash(ezsp_payload)
    body_for_crc = header + randomized_payload
    raw = body_for_crc + crc16_bytes(body_for_crc)
    return stuff_bytes(raw) + bytes([FLAG_BYTE])


def parse_ash_frame(wire_frame: bytes) -> dict:
    """Décode une trame reçue (avec ou sans 0x7E final) et vérifie le CRC."""
    clean = wire_frame[:-1] if wire_frame.endswith(bytes([FLAG_BYTE])) else wire_frame
    unstuffed = unstuff_bytes(clean)

    if unstuffed.startswith(b"\x1a"):
        unstuffed = unstuffed[1:]

    if not verify_ash_frame(unstuffed):
        return {"valid": False, "reason": "CRC invalide", "raw": unstuffed}

    frame_type_byte = unstuffed[0]
    payload_and_crc = unstuffed[1:]
    payload = payload_and_crc[:-2]

    # RSTACK = 0xC1
    if frame_type_byte == 0xC1:
        return {
            "valid": True,
            "kind": "RSTACK",
            "version": payload[0] if len(payload) > 0 else None,
            "reset_reason": payload[1] if len(payload) > 1 else None,
            "raw": unstuffed,
        }

    # Trame DATA : bit 7 == 0
    if (frame_type_byte & 0x80) == 0:
        frm_num = (frame_type_byte >> 4) & 0x07
        retransmit = bool((frame_type_byte >> 3) & 0x01)
        ack_num = frame_type_byte & 0x07
        return {
            "valid": True,
            "kind": "DATA",
            "frm_num": frm_num,
            "retransmit": retransmit,
            "ack_num": ack_num,
            "ezsp_payload": randomize_ash(payload),
            "raw": unstuffed,
        }

    # Trame superviseur (ACK / NAK / ERROR) : bit 7 == 1
    return {
        "valid": True,
        "kind": "SUPERVISOR",
        "control": frame_type_byte,
        "payload": payload,
        "raw": unstuffed,
    }


if __name__ == "__main__":
    rstack_sample = bytes.fromhex("1A C1 02 0B 0A 52 7E")
    print("Décodage RSTACK :", parse_ash_frame(rstack_sample))

    ack_sample = build_ack_frame(ack_num=0)
    print("Trame ACK (0)   :", ack_sample.hex(" ").upper())
    print("Décodage ACK    :", parse_ash_frame(ack_sample))