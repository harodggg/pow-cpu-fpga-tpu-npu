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
        self.sighash  = sighash

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
                    return False  # 公钥哈希不匹配，执行失败
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

class UTXOSet:

    def __init__(self):
        pass
        



def test_p2pkh_script_execution():
    # 1. 模拟 Alice 的密钥对与地址
    alice_pubkey = b"ALICE_PUBLIC_KEY_SECP256K1_33B"
    alice_pkh = hash160(alice_pubkey)

    # 2. 模拟花费交易的 Sighash
    tx_sighash = dsha256(b"TX_SPENDING_PREIMAGE_BYTES")

    # 3. 构造锁定脚本 (scriptPubKey)
    # OP_DUP OP_HASH160 <alice_pkh> OP_EQUALVERIFY OP_CHECKSIG
    script_pubkey = [
        "OP_DUP",
        "OP_HASH160",
        alice_pkh,
        "OP_EQUALVERIFY",
        "OP_CHECKSIG"
    ]

    # 4. 正确的解锁脚本 (scriptSig)：Alice 提供了合法签名和真实公钥
    valid_sig = b"VALID_SIG_FOR_" + alice_pubkey
    valid_script_sig = [valid_sig, alice_pubkey]

    # 将 scriptSig 与 scriptPubKey 串联执行
    vm1 = ScriptVM(sighash=tx_sighash)
    success = vm1.execute(valid_script_sig + script_pubkey)
    assert success is True, "合法签名应成功解锁 UTXO"
    print("✓ 合法 P2PKH 解锁成功！")

    # 5. 伪造攻击测试：Eve 试图用自己的公钥和签名去解锁 Alice 的 UTXO
    eve_pubkey = b"EVE_ATTACKER_KEY_SECP256K1_33B"
    eve_sig = b"VALID_SIG_FOR_" + eve_pubkey
    invalid_script_sig = [eve_sig, eve_pubkey]

    vm2 = ScriptVM(sighash=tx_sighash)
    failed = vm2.execute(invalid_script_sig + script_pubkey)
    assert failed is False, "OP_EQUALVERIFY 必须拦截未匹配公钥哈希的攻击"
    print("✓ 非法窃取被 OP_EQUALVERIFY 精准拦截！")

if __name__ == "__main__":
    test_p2pkh_script_execution()









