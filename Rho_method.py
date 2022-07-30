import brith_attack,time,binascii

brith_attack.SM3(b'48454c4c4f')

#传入参数消息16进制,攻击bit数目
def rho_attack( m, num):
    count = 0
    m_byte = m.encode()
    M = binascii.b2a_hex(m_byte)
    #初始时刻V_1,V_2
    V_1 = M
    V_2 = M
    while( 1 ):
        #V_1每次进行一次SM3,
        V_1 = brith_attack.SM3(V_1)
        #对消息哈希次数进行统计
        count += 1
        #V_2进行两次SM3,
        tmp = brith_attack.SM3(V_2)
        V_2 = brith_attack.SM3(tmp)
        #寻找碰撞比特
        if(V_1[0:num] == V_2[0:num]):
            return V_1,V_2,count

if __name__ == "__main__":
    m = "HELLO"
    start = time.time()
    v_1, v_2,count = rho_attack(m,5)
    end = time.time()
    print(v_1,"\n",v_2)
    print("time using: " ,end - start,"s")
    m_byte = m.encode()
    M = binascii.b2a_hex(m_byte)
    V1 = M
    for i in range(count):
        V1 = brith_attack.SM3(V1)
    print(V1)
