import hashlib
import block


def hash160(data: bytes) -> bytes:
    sha = hashlib.sha256(data).digest()
    rip = hashlib.new("ripemd160")
    rip.update(sha)
    return rip.digest()


def dsha256(data: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def mock_ecdsa_verify(pubkey: bytes, sighash: bytes, sig: bytes) -> bool:
    return sig.startswith(b"VALID_SIG_FOR_") and pubkey in sig


class ScriptVM:

    def __init__(self, sighash: bytes):
        self.stack: list[bytes] = []
        self.sighash = sighash

    def execute(self, script_tokens: list[bytes | str]) -> bool:
        for token in script_tokens:
            if isinstance(token, bytes):
                self.stack.append(token)
            elif token == "OP_DUP":
                if not self.stack:
                    return False
                self.stack.append(self.stack[-1])
            elif token == "OP_HASH160":
                if not self.stack:
                    return False
                top = self.stack.pop()
                self.stack.append(hash160(top))
            elif token == "OP_EQUALVERIFY":
                if len(self.stack) < 2:
                    return False
                a = self.stack.pop()
                b = self.stack.pop()
                if a != b:
                    return False
            elif token == "OP_CHECKSIG":
                if len(self.stack) < 2:
                    return False
                pubkey = self.stack.pop()
                sig = self.stack.pop()
                valid = mock_ecdsa_verify(pubkey, self.sighash, sig)
                self.stack.append(b"\x01" if valid else b"\x00")
            else:
                raise NotImplementedError(f"未实现的操作码: {token}")
        return bool(self.stack and self.stack[-1] not in (b"", b"\x00"))


# ==============================================================================
# 补齐的 UTXO 状态机实现
# ==============================================================================
class UTXOSet:

    def __init__(self):
        # 内存账本：(prev_tx: bytes, prev_index: int) -> block.TxOut
        self.db: dict[tuple[bytes, int], block.TxOut] = {}

    def apply_transaction(
        self,
        tx: block.Transaction,
        txid: bytes,
        skip_script: bool = False,
        script_tokens_getter=None,
    ) -> int:
        """
        处理单笔交易：
        1. 区分 Coinbase 与普通交易
        2. 校验防双花 (Double Spend)
        3. 执行 ScriptVM 鉴权
        4. 校验非负守恒 (防凭空印钱)
        5. 原子状态转移：删除旧 UTXO，新增输出 UTXO
        """
        # 判断是否为 Coinbase (创世/挖矿交易输入为 32 字节 0)
        is_coinbase = len(tx.ins) == 1 and tx.ins[0].prev_tx == b"\x00" * 32

        total_in = 0
        spent_keys = []

        if not is_coinbase:
            for i, inp in enumerate(tx.ins):
                # 兼容 prev_index 无论是 int 还是 bytes
                vout = (
                    inp.prev_index
                    if isinstance(inp.prev_index, int)
                    else int.from_bytes(inp.prev_index, "little")
                )
                outpoint = (inp.prev_tx, vout)

                # 1. 防双花检查
                if outpoint not in self.db:
                    raise KeyError(
                        f"UTXO 不存在或已被双花: {outpoint[0].hex()[:16]}...:{vout}"
                    )

                spent_utxo = self.db[outpoint]

                # 2. 脚本验证 (通过回调注入脚本 Token 或直接跳过)
                if not skip_script and script_tokens_getter:
                    sighash = dsha256(
                        txid + outpoint[0] + vout.to_bytes(4, "little")
                    )
                    tokens = script_tokens_getter(inp, spent_utxo)
                    vm = ScriptVM(sighash=sighash)
                    if not vm.execute(tokens):
                        raise PermissionError(
                            f"脚本验证失败，拒绝花费 UTXO: {outpoint}"
                        )

                total_in += spent_utxo.value
                spent_keys.append(outpoint)

        # 3. 守恒验证
        total_out = sum(out.value for out in tx.outs)
        if not is_coinbase and total_in < total_out:
            raise ValueError(
                f"支出金额 ({total_out}) 大于可用输入 ({total_in})，违规印钱"
            )

        # 4. 原子状态转移
        # A. 抹除已花费的 UTXO
        for k in spent_keys:
            del self.db[k]

        # B. 记录新生成的 UTXO
        for vout, out in enumerate(tx.outs):
            self.db[(txid, vout)] = out

        return 0 if is_coinbase else (total_in - total_out)

    def apply_block(self, blk: block.Block):
        """按序将一个区块内的所有交易应用到状态机"""
        for tx in blk.transactions:
            # 计算每笔交易的小端序 32 字节哈希
            # 如果 block.py 里的 Transaction 带有 raw_bytes，则直接计算；否则做模拟
            raw_tx = getattr(tx, "raw_bytes", None)
            txid = (
                dsha256(raw_tx)
                if raw_tx
                else hashlib.sha256(str(tx).encode()).digest()
            )
            self.apply_transaction(tx, txid, skip_script=True)


# ==============================================================================
# 测试套件：验证 Script 与 UTXOSet 的完整联动
# ==============================================================================
def test_full_pipeline():
    print("--- 1. 验证脚本虚拟机 ---")
    alice_pubkey = b"ALICE_PUBLIC_KEY_SECP256K1_33B"
    alice_pkh = hash160(alice_pubkey)
    tx_sighash = dsha256(b"TX_SPENDING_PREIMAGE_BYTES")

    script_pubkey = [
        "OP_DUP",
        "OP_HASH160",
        alice_pkh,
        "OP_EQUALVERIFY",
        "OP_CHECKSIG",
    ]
    valid_sig = b"VALID_SIG_FOR_" + alice_pubkey
    valid_script_sig = [valid_sig, alice_pubkey]

    vm = ScriptVM(sighash=tx_sighash)
    assert (
        vm.execute(valid_script_sig + script_pubkey) is True
    ), "P2PKH 解锁失败"
    print("✓ P2PKH 栈式脚本虚拟机验证通过")

    print("\n--- 2. 验证 UTXO 状态机与防双花 ---")
    utxo_set = UTXOSet()

    # A. 模拟创世区块的 Coinbase 交易产出 50 BTC
    genesis_txid = b"\x01" * 32
    cb_tx = block.Transaction(
        version=1,
        ins=[
            block.TxIn(
                prev_tx=b"\x00" * 32,
                prev_index=0xFFFFFFFF,
                script_sig=b"The Times 03/Jan/2009",
                sequence = 0xFFFFFFFF
            )
        ],
        outs=[
            block.TxOut(
                value=50 * 100_000_000, script_pubkey=b"ALICE_P2PKH_SCRIPT"
            )
        ],
        locktime=0,
    )
    utxo_set.apply_transaction(cb_tx, genesis_txid, skip_script=True)
    assert len(utxo_set.db) == 1
    print("✓ Coinbase 交易成功初始化 UTXO 状态 (50 BTC)")

    # B. 模拟 Alice 转账：花费 50 BTC，支付 Bob 20 BTC，找零 29 BTC，手续费 1 BTC
    spend_txid = b"\x02" * 32
    spend_tx = block.Transaction(
        version=1,
        ins=[
            block.TxIn(
                prev_tx=genesis_txid,
                prev_index=0,
                script_sig=b"ALICE_SIG",
                sequence=0xFFFFFFFF,
            )
        ],
        outs=[
            block.TxOut(
                value=20 * 100_000_000, script_pubkey=b"BOB_SCRIPT"
            ),  # 给 Bob
            block.TxOut(
                value=29 * 100_000_000, script_pubkey=b"CHANGE_SCRIPT"
            ),  # 找零
        ],
        locktime=0,
    )

    fee = utxo_set.apply_transaction(
        spend_tx,
        spend_txid,
        skip_script=False,
        script_tokens_getter=lambda inp, utxo: valid_script_sig + script_pubkey,
    )
    assert fee == 1 * 100_000_000
    assert len(utxo_set.db) == 2
    assert (genesis_txid, 0) not in utxo_set.db, "原 50 BTC 应该已被销毁"
    print(f"✓ 转账成功，带脚本验证通过，产生手续费: {fee / 1e8} BTC")

    # C. 验证双花拦截：再次尝试花费创世 50 BTC
    try:
        utxo_set.apply_transaction(spend_tx, b"\x03" * 32, skip_script=True)
        assert False, "未能拦截双花交易！"
    except KeyError as e:
        print(f"✓ 拦截双花成功: {e}")

    print("\n整个客户端状态机与脚本虚拟机全部闭环！")


if __name__ == "__main__":
    test_full_pipeline()
