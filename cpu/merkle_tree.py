import hashlib


def dsha256(b: bytes):
    return  hashlib.sha256(hashlib.sha256(b).digest()).digest()


class Merkle_tree:

    def __init__(self,txs):
        self.txs = txs

        byte_txs = [bytes.fromhex(tx)[::-1] for tx in txs]

        root_bytes = Merkle_tree.compute_merkle_tree_root(byte_txs)
        self.root = root_bytes[::-1].hex()

    @staticmethod
    def compute_merkle_tree_root(txs): 
        if not txs:
            raise ValueError("交易列表不能为空")
        
        current_level = list(txs)

        while len(current_level) > 1:
            # 每一层如果节点数为奇数，复制最后一个节点凑成偶数对
            if len(current_level) % 2 != 0:
                current_level.append(current_level[-1])

            next_level = []
            for n in range(len(current_level) // 2):
                left = current_level[2 * n]
                right = current_level[2 * n + 1]
                # 左右直接拼接做 dsha256
                parent = dsha256(left + right)
                next_level.append(parent)

            current_level = next_level

        return current_level[0]
        



    







if __name__ == "__main__":
    # case 1
    tx1 = ["4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"]
    assert(Merkle_tree(tx1).root == tx1[0] ), "tx1 错误"


    # case 2
    tx2 = ["1111111111111111111111111111111111111111111111111111111111111111","2222222222222222222222222222222222222222222222222222222222222222"]
    assert(Merkle_tree(tx2).root == "ba982c0808a9a03c4e958ae612516f85faac3780dcb34d9ab83ceeaf74b54011"), "tx2 错误"

    # case 3 
    tx3 = ["1111111111111111111111111111111111111111111111111111111111111111","2222222222222222222222222222222222222222222222222222222222222222","3333333333333333333333333333333333333333333333333333333333333333"]
    assert(Merkle_tree(tx3).root == "e6f5f3a082e7117eca9f5b077b5f9e08a64c213c92f4b6377af3825e5c89cdca"), "tx3 错误"
    

    # case 4
    tx4 = ["1111111111111111111111111111111111111111111111111111111111111111","2222222222222222222222222222222222222222222222222222222222222222","3333333333333333333333333333333333333333333333333333333333333333","4444444444444444444444444444444444444444444444444444444444444444"]
    assert(Merkle_tree(tx4).root == "94f4bc8f37716b47234bcfa62a03b2c75ae43c28c52244d38777d48504a28523"), "tx4 错误"


    print("测试")
    print(dsha256(b"ll"))
