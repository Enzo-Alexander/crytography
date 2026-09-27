//仿射密码，k1,k2分别为仿射密码中的a和b，其中a应与26互素，以便使a在模26下有逆
#include<bits/stdc++.h>
using namespace std;
const long long N=1e3+5;
//先把输入转ASCII存起来，这是明文；
int mArry[N];
//这是ASCII加密后的密文数组
int eArry[N];
int k1=17;
int b=7;
char order;
map<char,int> entable;//加密表
map<int,char> detable;//解密表
int  main(){
    for(int i=0;i<26;i++) entable['a'+i]=i;
    for(int i=0;i<26;i++) detable[i]='a'+i;
    // cout<<detable[1];
    while(1){
        cout<<"Do you want to encrypt(e) or decrypt(d) a text?"<<endl;
        cin>>order;
        if(order=='e'){
            string m;
            printf("please input the original text:");
            cin>>m;
            //cout<<m;
            int len_m=m.size();
            for(int i=0;i<len_m;i++) mArry[i]=entable[tolower(m[i])]; //这是转小写以后存了对应的顺序
            // for(int i=0;i<len_m;i++) cout<<mArry[i]<<" ";           //检查顺序
            // cout<<endl;
            for(int i=0;i<len_m;i++){                               //加密
                eArry[i]=(mArry[i]*17+7)%26;
                // cout<<eArry[i]<<" ";
            }        
            // cout<<endl;
            cout<<"The text had been encrypted,result:";
            for(int i=0;i<len_m;i++) cout<<detable[eArry[i]];       //这是加密后的字母
            cout<<endl;
        }
//在这断开
        else if(order=='d'){
            string e;
            cout<<"Input the text you want to decrypt:";
            cin>>e;
            int len_e=e.size();
            //先把字母转成对应的顺序
            for(int i=0;i<len_e;i++){
                eArry[i]=entable[tolower(e[i])];
                // cout<<eArry[i]<<" ";
            }
            // cout<<endl;
            //再来一边逆加密过程
            cout<<"The text had been decrypted,result:";
            for(int i=0;i<len_e;i++){
                mArry[i]=((eArry[i]+19)*23)%26;
                // cout<<mArry[i];
                //输出结果
                cout<<detable[mArry[i]];
            }
            cout<<endl;
        }
    //这也断开
        else{
            break;
        }
    }
    return 0;
}
