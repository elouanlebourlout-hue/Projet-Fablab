import time
import serial
from ash_codec import build_ack_frame, build_data_frame, parse_ash_frame

PORT = "/dev/serial/by-id/usb-Itead_Sonoff_Zigbee_3.0_USB_Dongle_Plus_V2_b24c1f4600c3ef11a020e2b08048b910-if00-port0"
BAUDRATE = 115200
ASH_RST_FRAME = bytes([0x1A, 0xC0, 0x38, 0xBC, 0x7E])


class EdgeSentinelClient:
    def __init__(self, port: str = PORT, baudrate: int = BAUDRATE, timeout: float = 0.2):
        self.port = port
        self.baudrate = baudrate
        self.timeout = timeout
        self.ser: serial.Serial | None = None
        self.frm_out = 0
        self.ack_out = 0
        self.seq = 0

    def __enter__(self):
        self.ser = serial.Serial(self.port, self.baudrate, timeout=self.timeout)
        self.ser.reset_input_buffer()
        self.reset_and_handshake()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.ser and self.ser.is_open:
            self.ser.close()

    def _read_frames(self, duration_s: float = 1.2):
        deadline = time.monotonic() + duration_s
        buf = bytearray()
        frames = []

        while time.monotonic() < deadline:
            chunk = self.ser.read(32)
            if not chunk:
                continue
            for b in chunk:
                if b == 0x7E:
                    if buf:
                        frames.append(bytes(buf))
                        buf.clear()
                else:
                    buf.append(b)
        return frames

    def reset_and_handshake(self):
        self.frm_out = 0
        self.ack_out = 0
        self.seq = 0
        self.ser.write(ASH_RST_FRAME)

        for f in self._read_frames(duration_s=1.0):
            parsed = parse_ash_frame(f)
            if parsed.get("kind") == "RSTACK":
                self.ack_out = 0
                self.ser.write(build_ack_frame(ack_num=self.ack_out))

        version_cmd = bytes([self.seq, 0x00, 0x00, 0x00, 13])
        self.seq = (self.seq + 1) & 0xFF
        resp = self.send_ezsp_raw(version_cmd)
        return resp

    def send_ezsp_raw(self, ezsp_payload: bytes, duration_s: float = 1.2) -> bytes | None:
        frame = build_data_frame(
            frm_num=self.frm_out,
            ack_num=self.ack_out,
            ezsp_payload=ezsp_payload,
        )
        self.frm_out = (self.frm_out + 1) % 8
        self.ser.write(frame)

        reply_payload = None
        for f in self._read_frames(duration_s=duration_s):
            parsed = parse_ash_frame(f)
            if parsed.get("kind") == "DATA":
                self.ack_out = (parsed["frm_num"] + 1) % 8
                self.ser.write(build_ack_frame(ack_num=self.ack_out))
                reply_payload = parsed["ezsp_payload"]
        return reply_payload

    def call_command(self, cmd_id: int, params: bytes = b"") -> bytes | None:
        cmd_lo = cmd_id & 0xFF
        cmd_hi = (cmd_id >> 8) & 0xFF
        payload = bytes([self.seq, 0x00, 0x00, cmd_lo, cmd_hi]) + params
        self.seq = (self.seq + 1) & 0xFF
        return self.send_ezsp_raw(payload)
    
    def get_eui64(self) -> bytes | None:
        """Commande EZSP 'getEui64' (ID 0x0026) : retourne la réponse brute."""
        return self.call_command(0x0026)
    
    def permit_joining(self, duration_s: int = 60) -> bytes | None:
        """Commande EZSP 'permitJoining' (ID 0x0022) : ouvre l'appairage pendant duration_s."""
        duration_clamped = max(0, min(255, int(duration_s)))
        return self.call_command(0x0022, bytes([duration_clamped]))

EZSP_COMMANDS = {
    0x0018: "networkState",
    0x0022: "permitJoining",
    0x0026: "getEui64",
    0x0027: "getNodeId",
}

def decode_ezsp_response(payload: bytes | None) -> dict:
    """Décode une trame de réponse EZSP v13."""
    if not payload or len(payload) < 5:
        return {"ok": False, "reason": "Réponse vide ou trop courte", "raw_hex": payload.hex(" ").upper() if payload else None}

    seq = payload[0]
    flags = payload[1]
    ezsp_ctrl = payload[2]
    cmd_id = payload[3] | (payload[4] << 8)
    status = payload[5] if len(payload) >= 6 else None
    extra = payload[6:] if len(payload) > 6 else b""

    return {
        "ok": True,
        "seq": seq,
        "is_response": bool(flags & 0x80),
        "ezsp_ctrl": f"0x{ezsp_ctrl:02X}",
        "cmd_id": f"0x{cmd_id:04X}",
        "status": f"0x{status:02X}" if status is not None else None,
        "extra_hex": extra.hex(" ").upper() if extra else "",
        "raw_hex": payload.hex(" ").upper(),
    }

if __name__ == "__main__":
    with EdgeSentinelClient() as client:
        for label, cmd_id in [
            ("networkState", 0x0018),
            ("getNodeId", 0x0027),
            ("getEui64", 0x0026),
        ]:
            resp = client.call_command(cmd_id)
            info = decode_ezsp_response(resp)
            print(f"{label:12s} (0x{cmd_id:04X}) -> {info}")

        pj_resp = client.permit_joining(duration_s=30)
        print(f"{'permitJoin':12s} (0x0022) -> {decode_ezsp_response(pj_resp)}")    