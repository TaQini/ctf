#include<bits/stdc++.h>
using namespace std;
struct Node{
    float value; //重合指数差,与我们的标准重合指数的差值越小越好
    int length;
};
vector< Node > key; //存放key可能的长度和重合指数差
set< int > key_len; //存放key可能的长度
/*
英文字母使用频率表 g
*/
double g[]={0.08167, 0.01492, 0.02782, 0.04253, 0.12702, 0.02228, 0.02015, 0.06094, 0.06966, 0.00153, 0.00772, 0.04025,0.02406, 0.06749, 0.07507, 0.01929, 0.00095, 0.05987, 0.06327, 0.09056, 0.02758, 0.00978, 0.02360, 0.00150,0.01974, 0.00074};
bool Greater_sort(Node a,Node b){
    return a.value<b.value;
}
/*
Coincidence_index,计算所选分组的重合指数
start表示分组的起点,length表示步长
重合指数CI的实际估计值是
X(i)=F(i)*(F(i)-1)/sum*(sum-1)
('a'<=i<='z',F(i)为i字符在当前分组出现的次数)
对上述X(i)求和就是整个分组的重合指数CI
*/
float Coincidence_index(string cipher,int start,int length){
    float index=0.000;
    int sum=0;
    int num[26];
    memset(num,0,sizeof(num));
    while(start<=cipher.length()){
        num[cipher[start]-'a']++;
        start+=length;
        sum++;
    }
    for(int i=0;i<26;i++){
        if(num[i]<=1) continue;
        index+=(float)(num[i]*(num[i]-1))/(float)((sum)*(sum-1));
    }
    return index;
}
/*
Find_same()函数即是根据 kasiski测试法的原理
我们可以获取key可能的长度
*/
void Find_same(string cipher){
    for(int i=3;i<5;i++){
        for(int j=0;j<cipher.length()-i;j++){
            string p=cipher.substr(j,i);
            for(int k=j+i;k<cipher.length()-i;k++){
                string tmp=cipher.substr(k,i);
                if(tmp==p){
                    Node x;
                    x.length=k-j;
                    key.push_back(x);
                }
            }
        }
    }
}
int gcd(int a,int b){
    if(b==0) return a;
    else return gcd(b,a%b);
}
/*

求出可能的key的值的最大公因子
经过重合指数检验,对key的长度进行排序

*/
void Get_key(string cipher){
    Find_same(cipher);
    for(int i=0;i<key.size();i++){
        int x=key[i].length;
        for(int j=0;j<key.size();j++){
            if(key[i].length>key[j].length)
                key_len.insert(gcd(key[i].length,key[j].length));
            else
                key_len.insert(gcd(key[j].length,key[i].length));
        }
    }
    key.clear();
    set< int >::iterator it=key_len.begin();
    while(it!=key_len.end()){
        int length=*it;
        if(length==1){
            it++;
            continue;
        }
        float sum=0.000;
        cout<<length<<" ";
        for(int i=0;i<length;i++){
            cout<<Coincidence_index(cipher,i,length)<<"  ";
            sum+=Coincidence_index(cipher,i,length);
        }
        cout<<endl;
        Node x;
        x.length=length;
        x.value=(float)fabsf(0.065-(float)(sum/(float)length));
        if(x.value<=0.1)
            key.push_back(x);
        it++;
    }
    sort(key.begin(),key.end(),Greater_sort);
}
/*

为了提高解密的成功率,我们取前面10个公因子进行求解
对每个公因子的每个分子进行字母的拟重合指数分析
由Chi测试(卡方检验),获取峰值点
该峰值点极有可能是明文

*/
void Get_ans(string cipher){
    int lss=0;
    while(lss<key.size()&&lss<10){
        Node x=key[lss];
        int ans[cipher.length()];
        memset(ans,0,sizeof(ans));
        map< char ,int > mp;
        for(int i=0;i<x.length;i++){
            double max_pg=0.000;
            for(int k=0;k<26;k++){
                mp.clear();
                double pg=0.000;
                int sum=0;
                for(int j=i;j<cipher.length();j+=x.length){
                    char c=(char)((cipher[j]-'a'+k)%26+'a');
                    mp[c]++;
                    sum++;
                }
                for(char j='a';j<='z';j++){
                    pg+=((double)mp[j]/(double)sum)*g[j-'a'];
                }
                if(pg>max_pg){
                    ans[i]=k;
                    max_pg=pg;
                }
            }
        }
        cout<<endl<<"key_length: "<<x.length<<endl<<"key is: ";
        for(int i=0;i<x.length;i++){
            cout<<(char)((26-ans[i])%26+'a')<<" ";
        }
        cout<<endl<<"Clear text:"<<endl;
        for(int i=0;i<cipher.length();i++){
            cout<<(char)((cipher[i]-'a'+ans[i%x.length])%26+'a');
        }
        cout<<endl;
        lss++;
    }
}
int main(){
    string cipher;
    cin>>cipher;
    transform(cipher.begin(), cipher.end(), cipher.begin(),::tolower);
    Get_key(cipher);
    for(int i=0;i<key.size();i++){
        cout<<key[i].length<<"  and "<<key[i].value<<endl;
    }
    Get_ans(cipher);
    return 0;
}
