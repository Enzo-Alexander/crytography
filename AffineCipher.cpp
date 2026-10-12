//仿射密码，k1,k2分别为仿射密码中的a和b，其中a应与26互素，以便使a在模26下有逆
#include<bits/stdc++.h>
#include <limits>
using namespace std;
const long long N=1e3+5;
//先把输入转ASCII存起来，这是明文；
int mArry[N];
//这是ASCII加密后的密文数组
int eArry[N];
int k1,k2;       //原来k1=17,k2=7删掉，改成运行时输入
int a_inv;       //a在模26下的逆元
char order;
map<char,int> entable;//加密表
map<int,char> detable;//解密表
//扩展欧几里得，求逆元
int exgcd(int a,int b,int &x,int &y){
    if(b == 0){
        x = 1;
        y = 0;
        return a;
    }
    int d = exgcd(b,a%b,y,x);
    y -= a/b * x;
    return d;
}
//求a mod mod的逆元，不存在返回-1
int getInv(int a,int mod){
    int x,y;
    int g = exgcd(a,mod,x,y);
    if(g != 1) return -1;
    return (x % mod + mod) % mod;
}
int main(){
    for(int i=0;i<26;i++) entable['a'+i]=i;
    for(int i=0;i<26;i++) detable[i]='a'+i;
    // cout<<detable[1];
    while(1){
        cout<<"Do you want to encrypt(e) or decrypt(d) a text?"<<endl;
        cin>>order;
        //清理缓冲区的
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        if(order!='e' && order!='d'){
            cout<<"exit program"<<endl;
            break;
        }
        //输入密钥k1,k2
        cout<<"Please input k1(a) and k2(b): ";
        cin>>k1>>k2;
        cin.ignore(numeric_limits<streamsize>::max(), '\n');
        if(k1 < 0 || k1 >25 || k2 <0 || k2>25){
            cout<<"Error: k1 and k2 must be between 0 and 25! Please re-enter!"<<endl;
            continue;
        }

        a_inv = getInv(k1,26);
        if(a_inv == -1){
            cout<<"Error: k1(a) and 26 are not coprime, no inverse! Cannot decrypt, please re-enter!"<<endl;
            continue;
        }
        cout<<"The inverse of k1 mod26 = "<<a_inv<<endl;
        if(order=='e'){
            string m;
            printf("please input the original text:");
            getline(cin,m);   
            int len_m=m.size();
            cout<<"The text had been encrypted,result:";
            for(int i=0;i<len_m;i++){
                char ch = m[i];
                if(isalpha(ch)){
                    mArry[i]=entable[tolower(ch)];
                    eArry[i]=(1LL * mArry[i] * k1 + k2)%26;
                    cout<<detable[eArry[i]];
                }else{
                    //非字母原样输出，数字提示
                    cout<<ch;
                }
            }
            cout<<endl;
        }
        else if(order=='d'){
            string e;
            cout<<"Input the text you want to decrypt(can contain space):";
            getline(cin,e); //替换cin>>e，支持空格
            int len_e=e.size();
            cout<<"The text had been decrypted,result:";
            for(int i=0;i<len_e;i++){
                char ch = e[i];
                if(isalpha(ch)){
                    eArry[i]=entable[tolower(ch)];
                    //解密公式 P = a_inv*(C - b) mod26，加26防负数
                    mArry[i]=(1LL * a_inv * (eArry[i] - k2 + 26))%26;
                    cout<<detable[mArry[i]];
                }else{
                    cout<<ch;
                }
            }
            cout<<endl;
        }
    }
    return 0;
}
