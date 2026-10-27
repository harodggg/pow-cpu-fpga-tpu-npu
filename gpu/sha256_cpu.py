import hashlib


# 填充 到512 位 在末尾 加上0x80
def padding(b:bytes) -> bytes:

    # 1. 记录原始的数据长度
    orbit_len = len(b) * 8

    # 2 填充1,也就是0x80
    b = b + bytes.fromhex("80")


    # 3. 检测数据长度 如果字节数小于 512,补充0,直到512位
    # 如果字节数大于512,也就是 64字节，则截取最后的字节。补充到还剩8字节。
    while(len(b) % 64 != 56): 
        b = b + bytes.fromhex("00")

    b += orbit_len.to_bytes(8,byteorder="big")

    return (b)



# 切分成 64字节切块
def div_64_block(b:bytes):
    print(b)
    blocks = []

    total_len =  len(b)


    cursor = 0 

    while cursor < total_len:
        chunk = b[cursor: cursor + 64]
        blocks.append(chunk)
        cursor += 64

    return blocks

def rotr(b:int,n: int) -> int:
    return (b >> n | b << (32 - n))  & 0xFFFFFFFF

def sigma0(x:int) -> int:
    return  rotr(x,7) ^ rotr(x, 18) ^ x >> 3

def sigma1(x: int) -> int:
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)

# expend_w
def expend_w(block:bytes) -> list[int]: 
    assert len(block) == 64, "单个块的大小必须严格等于 64 字节"

    w = [ ]


    # 获得 16 个字 。16 * 4 = 64字节
    for i in range(0,64,4):
        word = block[i:i+4]
        
        w.append(int.from_bytes(word,byteorder="big"))


    for t  in range(16,64):
        s0 = sigma0(w[t - 15])
        s1 = sigma1(w[t - 2])
        wt = (s1 + w[t - 7] + s0 + w[t - 16]) & 0xFFFFFFFF
        w.append(wt)
    return w


K = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
]


def Sigma0(x: int) -> int:
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def Sigma1(x: int) -> int:
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

# 条件选择函数：若 x 的当前位为 1 取 y，否则取 z
def ch(x: int, y: int, z: int) -> int:
    return (x & y) ^ ((~x & 0xFFFFFFFF) & z)

# 多数表决函数：x, y, z 中至少有两位为 1 则为 1
def maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)

def sha256(data:bytes):
    H = [
        0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
        0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    ]

    padding_data = padding(data)
    bs = div_64_block(padding_data)

    for b in bs:
        W = expend_w(b)

        a, b, c, d, e, f, g, h = H

        for t in  range(64):
            T1 = (h + Sigma1(e) + ch(e, f, g) + K[t] + W[t]) & 0xFFFFFFFF
            T2 = (Sigma0(a) + maj(a, b, c)) & 0xFFFFFFFF
    
            h = g
            g = f
            f = e
            e = (d + T1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (T1 + T2) & 0xFFFFFFFF

        H[0] = (H[0] + a) & 0xFFFFFFFF
        H[1] = (H[1] + b) & 0xFFFFFFFF
        H[2] = (H[2] + c) & 0xFFFFFFFF
        H[3] = (H[3] + d) & 0xFFFFFFFF
        H[4] = (H[4] + e) & 0xFFFFFFFF
        H[5] = (H[5] + f) & 0xFFFFFFFF
        H[6] = (H[6] + g) & 0xFFFFFFFF
        H[7] = (H[7] + h) & 0xFFFFFFFF
    return "".join(f"{h:08x}" for h in H)

if __name__ == "__main__":
    data = b"gggxxxx"
    print(sha256(data))
    d1 = hashlib.sha256(data).hexdigest()
    print(d1)


