import hashlib
import random
import socket
import struct
import time
from block import BlockHeader

MAINNET_MAGIC = b"\xf9\xbe\xb4\xd9"
GENESIS_HASH_HEX = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"


def recv_exact(sock, n_bytes: int) -> bytes:
    """循环读取，精准凑满 n_bytes 字节才返回，彻底解决半包截断问题"""
    buf = bytearray()
    while len(buf) < n_bytes:
        chunk = sock.recv(min(n_bytes - len(buf), 4096))
        if not chunk:
            raise ConnectionResetError("节点提前断开连接")
        buf.extend(chunk)
    return bytes(buf)


def decode_varint(data: bytes, offset: int = 0):
    """解码比特币 VarInt，返回 (数值, 下一个字节偏移量)"""
    prefix = data[offset]
    if prefix < 0xFD:
        return prefix, offset + 1
    elif prefix == 0xFD:
        return struct.unpack("<H", data[offset + 1 : offset + 3])[0], offset + 3
    elif prefix == 0xFE:
        return struct.unpack("<I", data[offset + 1 : offset + 5])[0], offset + 5
    else:
        return struct.unpack("<Q", data[offset + 1 : offset + 9])[0], offset + 9


class Packet:
    def __init__(self, command: str, payload: bytes = b""):
        self.magic = MAINNET_MAGIC
        self.command = command.encode("ascii").ljust(12, b"\x00")
        self.payload = payload
        self.length = len(payload)
        self.checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

    def serialize(self) -> bytes:
        """封装完整的 24 字节 Header + Payload"""
        header = (
            self.magic
            + self.command
            + struct.pack("<I", self.length)
            + self.checksum
        )
        return header + self.payload

    @classmethod
    def parse_header(cls, raw_header: bytes):
        """解析 24 字节的 Header"""
        if len(raw_header) < 24:
            raise ValueError("Header 不足 24 字节")
        magic = raw_header[:4]
        command = raw_header[4:16].rstrip(b"\x00").decode("ascii", errors="ignore")
        length = struct.unpack("<I", raw_header[16:20])[0]
        checksum = raw_header[20:24]
        return magic, command, length, checksum


def read_message(sock):
    """原子化读取一个完整的比特币 P2P 消息包（保证报文边界严格对齐）"""
    raw_header = recv_exact(sock, 24)
    magic, cmd, length, csum = Packet.parse_header(raw_header)
    payload = recv_exact(sock, length) if length > 0 else b""
    return cmd, payload


def build_version_payload(node_ip: str, node_port: int) -> bytes:
    """构建最小版本协商消息 (version payload: 86 字节)"""
    version = 70016
    services = 0
    timestamp = int(time.time())

    addr_recv_services = 1
    addr_recv_ip = b"\x00" * 10 + b"\xff\xff" + socket.inet_aton(node_ip)
    addr_recv = struct.pack("<Q", addr_recv_services) + addr_recv_ip + struct.pack(">H", node_port)

    addr_from_ip = b"\x00" * 10 + b"\xff\xff" + socket.inet_aton("127.0.0.1")
    addr_from = struct.pack("<Q", 0) + addr_from_ip + struct.pack(">H", 8333)

    nonce = random.getrandbits(64)
    user_agent = b"\x00"
    start_height = 0
    relay = b"\x00"

    payload = (
        struct.pack("<i", version)
        + struct.pack("<Q", services)
        + struct.pack("<q", timestamp)
        + addr_recv
        + addr_from
        + struct.pack("<Q", nonce)
        + user_agent
        + struct.pack("<i", start_height)
        + relay
    )
    return payload


# --- 客户端连接与收发 ---
node_ip = "70.240.234.148"
node_port = 8333

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
    client.settimeout(15.0)
    client.connect((node_ip, node_port))

    # 1. 发送本地 version 报文
    version_payload = build_version_payload(node_ip, node_port)
    client.sendall(Packet(command="version", payload=version_payload).serialize())

    # 2. 发送本地 verack，确认接受协议握手
    client.sendall(Packet("verack").serialize())

    # 3. 发送 getheaders 请求（以创世块为起点索取后 2000 个块）
    getheaders_payload = (
        struct.pack("<I", 70016)
        + b"\x01"
        + bytes.fromhex(GENESIS_HASH_HEX)[::-1]
        + b"\x00" * 32
    )
    client.sendall(Packet("getheaders", getheaders_payload).serialize())
    print("握手与 getheaders 已发出，进入统一消息事件流...")

    # 4. 单一事件循环：所有包都由 read_message 解析，彻底保证边界安全
    client.settimeout(60.0)
    block_headers = []

    while True:
        try:
            cmd, payload = read_message(client)
            print(f"--> 收到数据包: {cmd:<12} (载荷: {len(payload)} 字节)")

            if cmd == "ping":
                client.sendall(Packet("pong", payload).serialize())
                print("    已响应 pong 心跳")

            elif cmd == "headers":
                count, offset = decode_varint(payload, 0)
                print(f"\n成功收到 headers 报文，共包含 {count} 个区块头：\n")

                for i in range(count):
                    raw_header = payload[offset : offset + 80]
                    header = BlockHeader.parse(raw_header)
                    offset += 81

                    block_hash = hashlib.sha256(hashlib.sha256(raw_header).digest()).digest()[::-1].hex()
                    prev_hash = header.prev_block[::-1].hex()
                    merkle_root = header.merkle_root[::-1].hex()
                    utc_time = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(header.timestamp))

                    print(f"=== Block #{i + 1} ===")
                    print(f"Hash:        {block_hash}")
                    print(f"Prev Block:  {prev_hash}")
                    print(f"Merkle Root: {merkle_root}")
                    print(f"Timestamp:   {header.timestamp} ({utc_time} UTC)")
                    print(f"Bits (Target): 0x{header.bits:08x}")
                    print(f"Nonce:       {header.nonce}")
                    print(f"Version:     {header.version}")
                    print("-" * 80)

        except socket.timeout:
            print("等待超时")
            break
