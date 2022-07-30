小组成员: 邱容兴, 2019级网安2班, GitHub名称: rxQiu  
完成项目名称(仅个人,未组队):  

```
1.python SM3实现
2.SM3生日攻击
3.The Rho method of SM3
4.SM3长度拓展攻击`
```  
### 1.SM3实现(参考国家标准文档)
tips:所使用的结构为str,能将消息哈希出结果  
reference:`http://www.sca.gov.cn/sca/xwdt/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf`  
SM3是我国采用的一种密码散列算法,在SHA-256基础上进行改进,消息分组长度为512bit,生成消息摘要长度为256bit.算法流程分为4个部分: 填充比特,消息拓展,输出结果.下面我们对每一部分进行解释.  
#### 1.1填充比特  
我们需要对消息m,转化为2进制后先填充1在填充0至规定长度,在填充消息长度的64位二进制.  
``` python
#函数传入消息16进制,输出填充后16进制串
def padding(m_hex):
    #数据长度
    m_lenth = len(m_hex)
    m_bin   =  bin(int(m_hex,16))[2:]
    #对于左侧为0的消息进行填充,这是由于对于16进制01而言,经过上述操作后会成为二进制1,缺少长度,所以zfill功能为在左侧补0到指定长度,即01即可成为0000 0001,而不是简单的1.
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
    return hex(int(bit_padding,2))[2:].zfill(words_len)
```

#### 1.2消息拓展  
由于需要用到循环移位,编写Rotate_left函数使用切片进行,先将16进制数据转为2进制串后,进行切片再转化为16进制.
``` python
def Rotate_left(X,n):
    x_bin = bin(int(X,16))[2:].zfill(32)
    #利用切片进行左移，返回结果字,比特长度为32,
    #每左移32位相当于未移动,所以使用切片n模32
    x_bin_rotate = x_bin[n%32:]+x_bin[:n%32]
    result = int(x_bin_rotate,2)
    #返回结果16进制
    return hex(result)[2:].zfill(8)
```

对于每一个512bit的消息分组,拓展生成132个字,使用在压缩函数处. W_0表示W,W_1表示W',先生成W前16个字,再根据算法,计算剩余的字.  
对于算法中的异或操作,python可以转化为int类型使用运算符号^.  
``` python
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

#### 1.3压缩函数  
压缩函数需要使用FF和GG两个函数,再此先进行介绍.FF函数和GG函数在前16轮和后48轮是不同的，所以我们传入参数进行控制.mode为0表示前16轮,mode为1表示后48轮.  
``` python
#X,Y,Z为字,mode为1时计算XYZ的异或
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
    #X取反使用取符号~,为32位无符号整数，使用符号为有符号,可以加上2**32=4294967296,即与上0xFFFFFFFF
    x_reverse = ~x_num + 4294967296
    if(mode == 0):
        result = x_num^y_num^z_num
    elif (mode==1):
        result = (x_num&y_num) | (x_reverse&z_num)
    #返回结果字
    word_result = hex(result)[2:].zfill(8)
    return word_result
```

P置换存在两种,因此写了两个函数.初始量Tj存放于数组当中,前16轮使用Tj[0],后48轮使用TJ[1].初始IV在文档中已给.  
#### 1.4输出结果
SM3将消息每512bit进行分组,对于每一块分组调用压缩函数进行迭代计算,V'=CF(B',V).
```python
def SM3(message):
    #经过填充
    m_padding = padding(message)
    lenth = len(m_padding)
    V=iv
    #对于每一个消息分组进行压缩函数,更新迭代的V
    for i in range(lenth //128):
        tmp = V
        V = CF(tmp,m_padding[128*i:128*i+128])
    return V
```
结果如图所示,可以看到输出结果一致.
![sm3测试](https://user-images.githubusercontent.com/104824678/181903312-450a2e63-5676-4791-a662-940048da9d75.png)
![网站测试](https://user-images.githubusercontent.com/104824678/181903339-22ff6234-d22a-4185-959b-afe079360a0e.png)

### 2.SM3生日攻击  
生日悖论:假如随机选择n个人，那么这个n个人中有两个人的生日相同的概率是多少。如果要想概率是100%，那么只需要选择367个人就够了。因为只有366个生日日期（包括2月29日）。如果想要概率达到99.9% ，那么只需要70个人就够了。50%的概率只需要23个人。  
正是由于这个的存在,我们可以用该方法进行求解哈希函数碰撞问题,对于长度为n比特的消息,我们只需要经过2^(n/2)次的寻找,就有超过50%的概率找到拥有相同杂凑值的两个不同的消息.
因此我们对于消息在消息空间为0~2^256上进行了生日攻击;所使用的SM3为完整的64轮,并未缩减轮数,分别查找了8、12、16、20bit的碰撞.碰撞比特越长所用时间越久,由于使用了随机数,代码运行效率并不高.  
``` python
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
```
实验结果如下图,输出了包含消息16进制,以及对应的哈希值:  
[实验2_8bit](https://user-images.githubusercontent.com/104824678/181915821-52b2baae-3531-4b6b-8fe9-eb88a822b3ee.png)  
[实验2_12bit](https://user-images.githubusercontent.com/104824678/181915826-11655e24-9fb5-46d1-80b6-21c046aa1366.png)  
[实验2_16bit](https://user-images.githubusercontent.com/104824678/181915831-fbfe18fb-6a46-4032-88a8-65f9bb280aed.png)  
![实验2_20bit](https://user-images.githubusercontent.com/104824678/181915835-393184ff-f623-437e-8818-d55e45443248.png)

### 3.The Rho method of SM3 
Rho方法原理为一个随机串进行n多次的哈希后,会进入一个圆环内,也就是说从圆外一点形成一个圆环必然两点会重合.对于我们的哈希值而言就找到了一组碰撞.因此可以使用Rho方法寻找碰撞.  
实现的具体方法类似于整数分解中的Rho方法,让V1每次进行一次哈希,V2每次进行两次哈希,最终形成套圈现象即V1=V2,可以寻找到碰撞.如下图：
![Rho](https://user-images.githubusercontent.com/104824678/181913910-1feea42d-b914-4e7e-b519-5c6993857b40.png)  

``` python
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
```

代码运行需要将sm3.py和该代码放在同一个文件夹中.实验结果如下,使用了完整的64轮SM3对于8、12、16bit进行了碰撞,可以看见随着碰撞比特数目越多,其寻找碰撞的时间越长,符合实际情况.  
截图:  [实验3_8bit](https://user-images.githubusercontent.com/104824678/181914237-46c29c69-4dbc-45a9-95f2-d980fe111e00.png)  
[实验3_12bit](https://user-images.githubusercontent.com/104824678/181914318-8bbe3946-ef0f-42ab-a075-87cf83d30215.png)  
16bit碰撞如图:  
![实验3_16bit](https://user-images.githubusercontent.com/104824678/181914640-00aaff70-4cab-4dc6-af0c-42f920b09c8a.png)



### 4.长度拓展攻击  
长度拓展攻击是由于MD结果导致的,可以看到我们SM3由于需要对消息进行512分组,因此如果我们在已知消息M和其哈希值的情况下,可以构造一个消息M'= M||Z,使得H(M')= h'.Z其中的若干比特可以有我们任意选取.Z的构造方法为Z=padding(M)+ X.(其中padding(M)为消息填充1、多个0和消息长度的二进制,X为人为任意串).这是因为我们知道H(M),因此需要保证其不变已知，再根据我们任意构造的X,将其作为压缩函数的输入CF(X,H(M)),即可得到h'=H(M') = CF(H(M),Z).具体可以参照慕课密码学引论上.  

![长度拓展攻击](https://user-images.githubusercontent.com/104824678/181911959-b82131e4-01e0-4058-962e-20322422f6d1.png)  
代码运行需要将sm3.py和长度拓展攻击.py放在同一个文件夹中.  
若攻击者已知消息长度和其杂凑值,可以构造出M'包含M的消息杂凑值.
![实验4](https://user-images.githubusercontent.com/104824678/181914568-4ba93fc1-2e2f-4bc5-88fd-c4e3b2afbe3f.png)


