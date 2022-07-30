import binascii,time ,random

Tj = ["79cc4519", "7a879d8a" ]
iv = "7380166f4914b2b9172442d7da8a0600a96f30bc163138aae38dee4db0fb0e4e"


#X,Y,Z位字,mode为1时计算XYZ的异或
def FF(X,Y,Z,mode):
    x_num = int(X,16)
    y_num = int(Y,16)
    z_num = int(Z,16)
    if(mode == 0):
        result = x_num^y_num^z_num
    elif (mode==1):
        result = (x_num&y_num) | (x_num&z_num) | (y_num&z_num)
    #返回结果字
    word_result = hex(result)[2:].zfill(8)
    return word_result

def GG(X,Y,Z,mode):
    x_num = int(X,16)
    y_num = int(Y,16)
    z_num = int(Z,16)
    #X取反,为32位无符号整数，使用符号为有符号,可以加上2**32=4294967296,即与上0xFFFFFFFF
    x_reverse = ~x_num + 4294967296
    if(mode == 0):
        result = x_num^y_num^z_num
    elif (mode==1):
        result = (x_num&y_num) | (x_reverse&z_num)
    #返回结果字
    word_result = hex(result)[2:].zfill(8)
    return word_result

def Rotate_left(X,n):
    x_bin = bin(int(X,16))[2:].zfill(32)
    #利用切片进行左移，返回结果字,比特长度为32,
    #每左移32位相当于未移动,所以使用切片n模32
    x_bin_rotate = x_bin[n%32:]+x_bin[:n%32]
    
    result = "" 
    for i in range(8):
        result += hex(int(x_bin_rotate[4*i:4*i+4],2))[2:]
    return result
    #return hex(result)[2:].zfill(8)

def P_0(X):
    x_0 = int(X,16)
    x_1 = int(Rotate_left(X,9),16)
    x_2 = int(Rotate_left(X,17),16)
    Result = x_0^x_1^x_2
    return hex(Result)[2:].zfill(8)
    
def P_1(X):
    x_0 = int(X,16)
    x_1 = int(Rotate_left(X,15),16)
    x_2 = int(Rotate_left(X,23),16)
    Result = x_0^x_1^x_2
    return hex(Result)[2:].zfill(8)

def padding(m_hex):
    #数据长度
    m_lenth = len(m_hex)
    m_bin   =  bin(int(m_hex,16))[2:]
    #对于左侧为0的消息进行填充
    bit = m_bin.zfill(4*m_lenth)
    #填充长度
    num = 448 - 1 - 4*m_lenth%512
    #数据长度二进制,长度为64位
    m_lenth_bin = bin(4*m_lenth)[2:].zfill(64)
    bit_padding = bit+ "1" + num*"0" + m_lenth_bin
    #消息字长度
    words_len = len(bit_padding)//8
    #返回填充后的结果字
    return hex(int(bit_padding,2))[2:].zfill(words_len)


#每一个消息分组进行消息扩展
def Expansion(message_lump):
    W_0 = []
    W_1 = []
    for i in range(16):
        W_0.append(message_lump[8*i:8*i+8])
    for j in range(16,68):
        tmp1 = int(W_0[j-16],16)
        tmp2 = int(W_0[j-9],16)
        tmp3 = int(Rotate_left(W_0[j-3],15),16)

        tmp4 = int(Rotate_left(W_0[j-13],7),16)
        tmp5 = int(W_0[j-6],16)
        #计算异或
        tmp6 = hex(tmp1^tmp2^tmp3)[2:].zfill(8)
        #计算Wj数值
        tmp7 = int(P_1(tmp6),16) ^ tmp4 ^ tmp5
        #将Wj整数转化为字加入结果集合
        result = hex(tmp7)[2:].zfill(8)
        W_0.append(result)
    for k in range(64):
        num_0 = int( W_0[k],16)
        num_1 = int( W_0[k+4],16)
        tmp = hex(num_0 ^ num_1)[2:].zfill(8)
        W_1.append( tmp )
    return W_0,W_1

#压缩函数
def CF(V,B):
    W_0,W_1 = Expansion(B)
    A=V[0:8]
    B=V[8:16]
    C=V[16:24]
    D=V[24:32]
    E=V[32:40]
    F=V[40:48]
    G=V[48:56]
    H=V[56:64]
##    tj = str(),ff = "",w_0 = "",w_1 = ""
    for i in range(64):
        if(i < 16):
            tj = Rotate_left(Tj[0],i)
            ff = FF(A,B,C,0)
            gg = GG(E,F,G,0)
            w_0 = W_1[i]
            w_1 = W_0[i]
        else:
            tj  = Rotate_left(Tj[1],i)
            ff = FF(A,B,C,1)
            gg = GG(E,F,G,1)
            w_0 = W_1[i]
            w_1 = W_0[i]
        tmp_1 = Rotate_left(A,12)
        
        tmp_2 = (int(tmp_1,16) + int(E,16) + int(tj,16))%2**32
        
        SS1 = Rotate_left( hex(tmp_2)[2:].zfill(8) , 7 )
        
        SS2 = hex(int(SS1,16) ^ int(tmp_1,16))[2:].zfill(8)
        
        tt1_num = ( int(ff,16) + int(D,16) + int(SS2,16) + int(W_1[i],16) )%2**32
        
        TT1 = hex(tt1_num)[2:].zfill(8)
        
        tt2_num = ( int(gg,16) + int(H,16) + int(SS1,16) + int(W_0[i],16) )%2**32
        TT2 = hex(tt2_num)[2:].zfill(8)
        
        D = C
        C = Rotate_left(B,9)
        B = A
        A = TT1
        H = G
        G = Rotate_left(F,19)
        F = E
        E = P_0(TT2)
        #print(A, B ,C ,D , E ,F ,G , H)
    result = int(A + B + C + D + E + F + G + H,16)^int(V,16)
    return hex(result)[2:]

def SM3(message):

    m_padding = padding(message)
    
    lenth = len(m_padding)

    V=iv
    for i in range(lenth //128):
        tmp = V
        V = CF(tmp,m_padding[128*i:128*i+128])
    return V


###将消息使用utf-8进行编码
##plaint = input("")
##m_byte = plaint.encode()
##M = binascii.b2a_hex(m_byte)
##print(M)
##print(SM3(M))

def brith_attack( num):
    count = 0
    while( 1 ):
        num1 = random.randint(0,2**256)
        num2 = random.randint(0,2**256)
        message1 = hex(num1)[2:]
        message2 = hex(num2)[2:]
        hash1 = SM3(message1)
        hash2 = SM3(message2)
        count += 1
        if( hash1[0:num] == hash2[0:num]):
            return (message1,hash1), (message2,hash2),count

if __name__ == "__main__":
    start = time.time()
    (M1,Hash1),(M2,Hash2),count = brith_attack( 5 )
    end  = time.time()
    print("累计尝试次数: ",count)
    print(M1,"\n hash值为: ",Hash1)
    print(M2,"\n hash值为: ",Hash2)
    print("time using:" , end - start,"s")



        
