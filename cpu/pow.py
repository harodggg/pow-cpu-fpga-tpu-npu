import hashlib
import block


def bits_to_target(bits: int) -> int:
    exponent = bits >> 24

    mantissa = bits  & 0x00ffffff

    target = mantissa * (256 ** (exponent -3) )

    return target


    




def validate_pow(header: bytes, bits: int) -> bool:
    hash = hashlib.sha256(hashlib.sha256(header).digest()).digest()
    hash_int = int.from_bytes(hash, byteorder="little")

    target = bits_to_target(bits)

    return hash_int <= target


def mine(header_without_nonce: bytes, bits: int) -> tuple[int,bytes]:
    target = bits_to_target(bits)


    for nonce in range(0xffffffff + 1):
        full_header = header_without_nonce + nonce.to_bytes(
            4, byteorder="little"
        )

        hash_bytes = hashlib.sha256(
            hashlib.sha256(full_header).digest()
        ).digest()
        hash_int = int.from_bytes(hash_bytes, byteorder="little")

        if hash_int <= target:
            print(f"挖矿成功！Nonce: {nonce}")
            print(f"区块哈希: {hash_bytes[::-1].hex()}")
            return nonce,full_header


def test_mine_second_block():
    # 1. 组装第 2 个区块的 76 字节头部前缀
    version = (1).to_bytes(4, "little")

    # 创世区块哈希在区块头物理内存中以小端序（倒序）存储
    genesis_hash_hex = (
        "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
    )
    prev_block = bytes.fromhex(genesis_hash_hex)[::-1]

    # 模拟该区块中交易树的根哈希（32 字节）
    mock_tx = b"coinbase: 50 BTC to miner"
    merkle_root = hashlib.sha256(hashlib.sha256(mock_tx).digest()).digest()

    # 时间戳：创世块时间戳递增 10 分钟 (600 秒)
    timestamp = (1231006505 + 600).to_bytes(4, "little")

    # 采用本地易测试的难度 bits (0x1f00ffff)
    test_bits = 0x1cffffff 
    bits_bytes = test_bits.to_bytes(4, "little")

    header_prefix = version + prev_block + merkle_root + timestamp + bits_bytes

    # 断言 1: 前缀长度必须严格为 76 字节
    assert len(header_prefix) == 76, (
        f"头部前缀长度错误: 应为 76 字节，实为 {len(header_prefix)}"
    )

    # 2. 执行挖矿
    nonce,mined_header= mine(header_prefix, test_bits)


    # 断言 2: 拼接 Nonce 后的完整区块头必须严格为 80 字节
    assert len(mined_header) == 80, (
        f"完整区块头长度错误: 应为 80 字节，实为 {len(mined_header)}"
    )

    # 断言 3: 必须通过 PoW 难度断言 (Hash <= Target)
    assert validate_pow(mined_header, test_bits) is True, "PoW 校验失败"

    # 断言 4: 闭环反序列化验证，解析出来的对象字段必须与原始输入完全一致
    parsed_header = block.BlockHeader.parse(mined_header)
    assert parsed_header.version == 1
    assert parsed_header.prev_block == prev_block
    assert parsed_header.merkle_root == merkle_root
    assert parsed_header.timestamp == 1231006505 + 600
    assert parsed_header.bits == test_bits
    assert parsed_header.nonce == nonce

    # 打印最终计算出的新区块哈希（大端序展示格式）
    mined_hash = (
        hashlib.sha256(hashlib.sha256(mined_header).digest()).digest()[::-1].hex()
    )
    print(f"\n[测试通过] 成功挖出新区块！")
    print(f"Nonce      : {nonce}")
    print(f"Block Hash : {mined_hash}")


if __name__ == "__main__":
    test_mine_second_block()
