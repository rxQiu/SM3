import time,binascii,random
from SM3 import SM3 as sm3
from SM3 import CF,padding
#传入参数消息长度、已知的消息哈希和可以任意构造的x(x用二进制表示)
def expansion_attack(m_len,hash1,x):
    #计算m需要填充'0'的长度
    length1 = (448-1-m_len*8)%512
    #构造消息M的长度
    length2 = m_len*8 + length1 + len(x) + 1 + 64

    #填充构造消息长度
    lenth = (448-1-len(x))%512
    #最后一个消息串为x + padding + bin(lenth)

    Z_bin = x + "1" + "0"*lenth + bin(length2)[2:].zfill(64)
    Z_hex = hex(int(Z_bin,2))[2:].zfill(128)
    H = CF(hash1,Z_hex)
    return H

#进行校验传入参数m为原始消息,x为任意选取的二进制比特
def check(m,x):
    m_expand = padding(m) + hex(int(x,2))[2:].zfill(len(x)//4)
    h = sm3(m_expand)
    return h
    

if __name__=="__main__":
    M1 = "HELLO"
    m_byte = M1.encode()
    M = binascii.b2a_hex(m_byte)
    #已知的H(m)和长度
    V1 = sm3(M)
    M_len = len(M1)
    #选取x为 world,即第一块加密HELLO,第二块对world进行压缩.
    X = "world"
    X_byte = X.encode()
    X_hex = binascii.b2a_hex(X_byte)
    #获得x的二进制串
    X_bin = bin(int(X_hex,16))[2:].zfill(len(X)*8)
    #攻击者进行构造得到输出哈希值
    H_attack = expansion_attack(M_len,V1,X_bin)

    #验证
    H = check(M,X_bin)
    print("H_attack: ",H_attack)
    print("H: ",H)
