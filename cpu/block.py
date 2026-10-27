from dataclasses import dataclass
import hashlib

@dataclass
class BlockHeader:
    version: int
    prev_block: bytes
    merkle_root: bytes
    timestamp: int
    bits: int
    nonce: int

    @classmethod
    def parse(cls,raw_bytes:bytes):
        assert len(raw_bytes) == 80, "区块头必须严格为 80 字节"

        version = int.from_bytes(raw_bytes[0:4],byteorder="little",signed=True)
        prev_block = raw_bytes[4:36]
        merkle_root = raw_bytes[36:68]
        timestamp = int.from_bytes(raw_bytes[68:72],byteorder="little",signed=False)
        bits = int.from_bytes(raw_bytes[72:76],byteorder="little",signed=False)
        nonce = int.from_bytes(raw_bytes[76:80],byteorder="little",signed=False)

        return cls(version,prev_block,merkle_root,timestamp,bits,nonce)


    def serialize(self) -> bytes:
        """将对象字段按比特币协议小端序重新打包为 80 字节"""
        return (
            self.version.to_bytes(4, "little", signed=True)
            + self.prev_block
            + self.merkle_root
            + self.timestamp.to_bytes(4, "little")
            + self.bits.to_bytes(4, "little")
            + self.nonce.to_bytes(4, "little")
        )


@dataclass
class TxIn:
    prev_tx: bytes
    prev_index: int
    script_sig: bytes
    sequence: int



@dataclass
class TxOut:
    value: int
    script_pubkey: bytes


@dataclass
class Transaction:
    version: int
    ins: list[TxIn]
    outs: list[TxOut]
    locktime: int
    
    @classmethod
    def parse(cls,raw_bytes: bytes) -> tuple["Transaction",int]:
        # 记录当前的索引
        cursor = 0

        version = int.from_bytes(raw_bytes[cursor:cursor+4],byteorder="little",signed= False)
        cursor = cursor + 4 

        in_count = int.from_bytes(raw_bytes[cursor:cursor+1],byteorder="little",signed= False)
        cursor = cursor + 1

        ins:list[TxIn] = []
        for _ in range(in_count):
            prev_tx = raw_bytes[cursor:cursor + 32]
            cursor += 32

            prev_index = raw_bytes[cursor:cursor + 4]
            cursor += 4

            script_len = raw_bytes[cursor]
            cursor += 1

            script_sig = raw_bytes[cursor:cursor + script_len]
            cursor += script_len

            sequence = int.from_bytes(raw_bytes[cursor:cursor + 4], byteorder="little")
            cursor += 4

            ins.append(TxIn(prev_tx, prev_index, script_sig, sequence))


        out_count = int.from_bytes(raw_bytes[cursor:cursor+1],byteorder="little",signed= True)
        cursor += 1

        outs:list[TxOut] = []
        for _ in range(out_count):
            value = int.from_bytes(raw_bytes[cursor:cursor + 8], byteorder="little")
            cursor += 8
            
            script_len = raw_bytes[cursor]
            cursor += 1
            
            script_pubkey = raw_bytes[cursor:cursor + script_len]
            cursor += script_len
            
            outs.append(TxOut(value, script_pubkey))

        locktime = int.from_bytes(raw_bytes[cursor:cursor + 4], byteorder="little")
        cursor += 4

        return cls(version, ins, outs, locktime), cursor





@dataclass
class Block:
    header: BlockHeader
    transactions: list[Transaction]

    @classmethod
    def parse(cls,raw_bytes:bytes):

        header = BlockHeader.parse(raw_bytes[0:80])
        tx_count = int.from_bytes(raw_bytes[80:81],byteorder="little",signed=False)

        transactions = [ ]
        cursor = 0

        for _ in range(tx_count):
            t = Transaction.parse(raw_bytes[cursor + 81:]) 
            transactions.append(t[0])
            cursor += t[1]

        return cls(header,transactions)
        


if __name__ == "__main__":

    # header(80bytes) + len(1bytes) + coinbase()
    genesis_hex = "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c0101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000"

    
    raw = bytes.fromhex(genesis_hex)

    assert len(raw) == 285, f"数据长度异常！当前为 {len(raw)} 字节，标准应为 285 字节"

    header_bytes = raw[0:80]
    block_hash = hashlib.sha256(hashlib.sha256(header_bytes).digest()).digest()[::-1].hex()
    assert block_hash == "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", "哈希不匹配！"

    print(Block.parse(raw))


    # 1. 提取留言文本（第 131 至 199 字节，共 69 字节 ASCII）
    message = raw[131:200].decode("ascii")

    # 2. 提取出块奖励（第 205 至 212 字节，8 字节小端序聪，转为 BTC）
    reward_btc = int.from_bytes(raw[205:213], "little") / 1e8

    print(f"新闻留言: {message}")
    print(f"出块奖励: {reward_btc} BTC")
