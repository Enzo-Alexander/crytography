//这是DES实现加密解密的代码
#include<bits/stdc++.h>
using namespace std;
//先导入初始置换和逆初始置换的表
int changetable[8][8]={
    {58,50,42,34,26,18,10,2},
    {60,52,44,36,28,20,12,4},
    {62,54,46,38,30,22,14,6},
    {64,56,48,40,32,24,16,8},
    {57,49,41,33,25,17,9,1},
    {59,51,43,35,27,19,11,3},
    {61,53,45,37,29,21,13,5},
    {63,55,47,39,31,23,15,7}};
int Rechangetable[8][8] = {
    {40,8,48,16,56,24,64,32},
    {39,7,47,15,55,23,63,31},
    {38,6,46,14,54,22,62,30},
    {37,5,45,13,53,21,61,29},
    {36,4,44,12,52,20,60,28},
    {35,3,43,11,51,19,59,27},
    {34,2,42,10,50,18,58,26},
    {33,1,41,9,49,17,57,25}};

//初始置换IP
string IP_perm(string raw64)
{
    string res;
    for(int i=0;i<8;i++){
        for(int j=0;j<8;j++){
            int pos = changetable[i][j] - 1;
            res += raw64[pos];
        }
    }
    return res;
}
//逆初始置换 IP⁻¹
string IP_inv_perm(string raw64)
{
    string res;
    for(int i=0;i<8;i++){
        for(int j=0;j<8;j++){
            int pos = Rechangetable[i][j] - 1;
            res += raw64[pos];
        }
    }
    return res;
}

const int PC2_table[48] = {
    13,16,10,23,0,4,
    2,27,14,5,20,9,
    22,18,11,3,25,7,
    15,6,26,19,12,1,
    40,51,30,36,46,54,
    29,39,50,44,32,47,
    43,48,38,55,33,52,
    45,41,49,35,28,31
};


//总体上先64个bit为一组做循环，用res字符串接住加密后的密文，解密的时候也这样
//先将明文转ASCII，再把ASCII转比特，比特补齐到大于当前数的最小64的倍数，先记录一开始的比特数，最后先去掉补的那些
//因为在明文的时候就补，解密出来的时候应该和当前一样。所以只需要去掉补的那些，每8位比特做一次ASCII的还原，最后还原成密文。
//比特用map<int,string>存
map<int,string> m;//存储需要加密的明文，这个string是64比特，64个比特64个比特地做加密循环
map<int,string> e;//存储加密后的密文
map<int,string> de;//存储解密后的明文
int len_m;//记录明文比特长度
int len_cur;//记录已经转换的比特数，到达len_m后就停止转换
//ASCII转8位比特串
string byteTobit(char m){
    unsigned char ch=static_cast<unsigned char>(m);
    string bits;
    for(int i=7;i>=0;i--){
        if(ch&(1<<i)) bits+='1';
        else bits+='0';
    }
    return bits;
}
//8位比特串转16进制
string bitToHex(string bits8)
{
    int val = 0;
    for(char c : bits8)
    {
        val = val * 2 + (c - '0');
    }
    char buf[3];
    sprintf(buf, "%02X", val);
    return string(buf);
}
//16进制转bit
string hexToBit(string hex2)
{
    int val;
    sscanf(hex2.c_str(), "%X", &val);
    string bits;
    for(int i=7;i>=0;i--){
        if(val & (1<<i)) bits += '1';
        else bits += '0';
    }
    return bits;
}

string hexStrToBitStr(string hexStr)
{
    string bitAll;
    for(int i=0;i<hexStr.size();i+=2)
    {
        string sub = hexStr.substr(i,2);
        bitAll += hexToBit(sub);
    }
    return bitAll;
}

char bit8ToChar(string bits8)
{
    unsigned char val = 0;
    for(char c : bits8)
    {
        val = val*2 + (c-'0');
    }
    return (char)val;
}

//轮密钥的左移位表
const int shift_table[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
//左移位函数
string rotl28_str(string bitstr, int n)
{
    n %= 28;
    // 取出前n个高位，放到字符串尾部
    string head = bitstr.substr(0, n);
    string tail = bitstr.substr(n);
    return tail + head;
}

string PC2(string in56)
{
    string out48;
    for(int i = 0; i < 48; i++)
    {
        out48 += in56[ PC2_table[i] ];
    }
    return out48;
}
// void RoundF(string *l,string *r){

// }
int extend[8][6]={
    {31,0,1,2,3,4},
    {3,4,5,6,7,8},
    {7,8,9,10,11,12},
    {11,12,13,14,15,16},
    {15,16,17,18,19,20},
    {19,20,21,22,23,24},
    {23,24,25,26,27,28},
    {27,28,29,30,31,0}
};

//这已经是经过pc1以后的56位密钥，没经过pc1是64位的比特串
string key[2]={"1011010010011011001010010011","0110100100111001110011000101"};
string checkkey[16][2][2];//检查每一轮移位是否正确
vector<string> childkey; //这是每一轮用的子密钥

void tochildkey(string key[2]){
    string C = key[0];
    string D = key[1];
//生成16轮的子密钥
    for(int round = 0; round < 16; round++)
    {
        int shift_n = shift_table[round];
        // 保存移位前
        checkkey[round][0][0] = C;
        checkkey[round][1][0] = D;

        // C D各自循环左移
        string C_new = rotl28_str(C, shift_n);
        string D_new = rotl28_str(D, shift_n);

        // 保存移位后，用于校验
        checkkey[round][0][1] = C_new;
        checkkey[round][1][1] = D_new;

        // 拼接CiDi为56bit，PC2压缩得到48位子密钥
        string CD56 = C_new + D_new;
        string subkey = PC2(CD56);
        childkey.push_back(subkey);

        // 更新C D，进入下一轮
        C = C_new;
        D = D_new;
    }
}
//48位比特异或
string xor_48bit(string a, string b)
{
    string res;
    for(int i = 0; i < 48; i++)
    {
        int bitA = a[i] - '0';
        int bitB = b[i] - '0';
        res += ( (bitA ^ bitB) ? '1' : '0' );
    }
    return res;
}

//8个S盒
const int S[8][4][16] = {
    // S1
    {{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7},
     {0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8},
     {4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0},
     {15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13}},
    // S2
    {{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10},
     {3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5},
     {0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15},
     {13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9}},
    // S3
    {{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8},
     {13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1},
     {13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7},
     {1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12}},
    // S4
    {{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15},
     {13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9},
     {10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4},
     {3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14}},
    // S5
    {{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9},
     {14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6},
     {4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14},
     {11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3}},
    // S6
    {{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11},
     {10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8},
     {9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6},
     {4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13}},
    // S7
    {{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1},
     {13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6},
     {1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2},
     {6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12}},
    // S8
    {{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7},
     {1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2},
     {7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8},
     {2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}}
};

// S盒置换：输入48bit串，输出32bit串
string sbox_trans(string xor_r)
{
    string out32;
    out32.reserve(32);
    // 分成8组，每组6bit
    for(int s_idx = 0; s_idx < 8; s_idx++)
    {
        // 取出当前6bit子串
        string sixbit = xor_r.substr(s_idx*6, 6);
        // bit0: sixbit[0], bit5: sixbit[5]
        int row = (sixbit[0] - '0') * 2 + (sixbit[5] - '0');
        // 中间4位：sixbit[1],sixbit[2],sixbit[3],sixbit[4]，计算加权值，也就是转成10进制
        int col = (sixbit[1]-'0')*8 + (sixbit[2]-'0')*4 + (sixbit[3]-'0')*2 + (sixbit[4]-'0');
        int val = S[s_idx][row][col];

        // 把十进制val转为4位二进制字符串，高位在前
        string fourbit;
        fourbit += ( (val & 8) ? '1' : '0' );
        fourbit += ( (val & 4) ? '1' : '0' );
        fourbit += ( (val & 2) ? '1' : '0' );
        fourbit += ( (val & 1) ? '1' : '0' );

        out32 += fourbit;
    }
    return out32;
}
//异或完以后要进行的置换
const int P_table[32] = {
    15,6,19,20,28,11,27,16,
    0,14,22,25,4,17,30,9,
    1,7,23,13,31,26,2,8,
    18,12,29,5,21,10,3,24
};

string p_change(string s32)
{
    string out32;
    out32.reserve(32);
    for(int i=0;i<32;i++)
    {
        out32 += s32[ P_table[i] ];
    }
    return out32;
}

// 32位比特串按位异或
string xor_32bit(string a, string b)
{
    string res;
    res.reserve(32);
    for(int i = 0; i < 32; i++)
    {
        int bitA = a[i] - '0';
        int bitB = b[i] - '0';
        int bitXor = bitA ^ bitB;
        res += (bitXor ? '1' : '0');
    }
    return res;
}

int main(){
    tochildkey(key);
    while(1){
        cout<<"Input the text you want to encrypt,the text will be encrypted in DES:"<<endl;
        string str;//一个字符一个ASCII，一个ASCII一个字节，那么字节数应该是8的倍数，字符串长度也应该是8的倍数，不足的一律补‘0’
        cin>>str;
        int len_str=str.size();
        for(int i=0;i<(8-(len_str%8))%8;i++) str+='0';//这一步保证了比特数是64的倍数，字符串长度保存在了len_str里
        int len_newstr=str.size();//计算map的键值
        //接下来是转比特,现在的str是明文字符串，加补0后的字符串
        for(int i=0;i<len_newstr;i++){
            //还要写每个字符转比特函数
            m[i]=byteTobit(str[i]);
        }
        //到此为止，已经将明文字符串转成了比特串，在m里，每个键对应8个比特串
        //为方便计算，每32位比特串合并成一个
        map<int,string> m_32;
        int len_m32=len_newstr/4;//新32位一个键的map长度
        for(int i=0;i<len_newstr/4;i++){
            m_32[i]=m[i*4]+m[i*4+1]+m[i*4+2]+m[i*4+3];
        }
        
    //外层控制字符串，内层做16轮的加密
        for(int round=0;round<len_m32;round+=2){
            string raw64 = m_32[round] + m_32[round+1];
            //初始置换IP
            string ip_out = IP_perm(raw64);
            string L = ip_out.substr(0,32);
            string R = ip_out.substr(32,32);
            string *l=&L;
            string *r=&R;
            //每次开始都用l,r指针指向的数据加密，在每次循环的结尾做指针指向的调换
            for(int i=0;i<16;i++){
                string temp_r;//这个是做完扩展的r
                //这是每一轮的扩展置换
                for(int z=0;z<8;z++){
                    for(int j=0;j<6;j++) temp_r+=(*r)[extend[z][j]];
                }

                string xor_r=xor_48bit(temp_r,childkey[i]);
                string s_out = sbox_trans(xor_r);
                string changed_r = p_change(s_out);
                string result_r=xor_32bit(*l, changed_r);
                *l=*r;
                *r=result_r;
            }
            string feistel_out = (*r) + (*l);
            //逆初始置换
            string cipher64 = IP_inv_perm(feistel_out);
            //存入密文map，round/2是分组编号
            e[round/2] = cipher64;
        }
        //====输出密文====
        string cipher_bit_all;
        for(auto &p:e){
            cipher_bit_all += p.second;
        }
        string cipher_text;
        //每8bit转一个字符
        for(int i=0;i+7 < cipher_bit_all.size();i+=8){
            string eightbit = cipher_bit_all.substr(i,8);
            cipher_text += bitToHex(eightbit);
        }
        cout<<"encrypt result: "<<cipher_text<<endl;
        cout<<"Input the text you want to decrypt(just hexadecimal):"<<endl;
        string hexCipher;
        cin>>hexCipher;
        string cipherAllBit = hexStrToBitStr(hexCipher);
        int blockNum = cipherAllBit.size() / 64;
        // 64bit分组存入de
        for(int b=0;b<blockNum;b++)
        {
            de[b] = cipherAllBit.substr(b*64, 64);
        }
        string allDecryptBit;
        // 对每个64bit分组解密
        for(auto &blk : de)
        {
            string c64 = blk.second;
            string ip_out = IP_perm(c64);
            string L = ip_out.substr(0,32);
            string R = ip_out.substr(32,32);
            string *l=&L;
            string *r=&R;
            //解密：子密钥逆序 i=15 downto 0
            for(int i=15;i>=0;i--)
            {
                string temp_r;
                for(int z=0;z<8;z++){
                    for(int j=0;j<6;j++) temp_r+=(*r)[extend[z][j]];
                }
                string xor_r=xor_48bit(temp_r,childkey[i]);
                string s_out = sbox_trans(xor_r);
                string changed_r = p_change(s_out);
                string result_r=xor_32bit(*l, changed_r);
                *l=*r;
                *r=result_r;
            }
            string feistel_out = (*r) + (*l);
            string plain64bit = IP_inv_perm(feistel_out);
            allDecryptBit += plain64bit;
        }
        //bit串转回字符
        string decryptFullStr;
        for(int i=0;i+7 < allDecryptBit.size();i+=8)
        {
            string b8 = allDecryptBit.substr(i,8);
            decryptFullStr += bit8ToChar(b8);
        }
        //用原始长度len_str截断，去掉加密时补的'0'
        string plainResult = decryptFullStr.substr(0, len_str);
        cout<<"decrypt result: "<<plainResult<<endl;
    }
    return 0;
}