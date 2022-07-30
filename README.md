小组成员: 邱容兴, 2019级网安2班, GitHub名称: rxQiu  
完成项目名称(仅个人,未组队):  


`1.python SM3实现  
2.SM3生日攻击  
3.The Rho method of SM3  
4.SM3长度拓展攻击`
  
### 1.SM3实现(参考国家标准文档)
tips:所使用的结构为str,能将消息哈希出结果  
reference:`http://www.sca.gov.cn/sca/xwdt/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf`  
SM3是我国采用的一种密码散列算法,在SHA-256基础上进行改进,消息分组长度为512bit,生成消息摘要长度为256bit.算法流程分为4个部分: 填充比特,消息拓展,输出结果.下面我们对每一部分进行解释.  
#### 1.1填充比特  
我们需要对消息m,转化为2进制后先填充1在填充0至规定长度,在填充消息长度的64位二进制.  
```
#函数传入消息16进制,输出填充后16进制串
def padding(m_hex):
    #数据长度
    m_lenth = len(m_hex)
    m_bin   =  bin(int(m_hex,16))[2:]
    #对于左侧为0的消息进行填充,这是由于对于16进制01而言,经过上述操作后会成为二进制1,缺少长度
    bit = m_bin.zfill(4*m_lenth)
    #计算填充0的长度
    num = 448 - 1 - 4*m_lenth%512
    #数据长度二进制,长度为64位
    m_lenth_bin = bin(4*m_lenth)[2:].zfill(64)
    #进行填充,填充1和num长度的0和数据长度
    bit_padding = bit+ "1" + num*"0" + m_lenth_bin
    #16进制串长度
    words_len = len(bit_padding)//4
    #返回填充后的结果字
    return hex(int(bit_padding,2))[2:].zfill(words_len)```

#### 1.2消息拓展  
对于每一个512bit的消息分组,拓展生成132个字,使用在压缩函数处.  
```
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
 ```
   
