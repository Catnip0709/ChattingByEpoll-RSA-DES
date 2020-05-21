#include <iostream>
#include <string>
#include <vector>
#include "DefineCode.h"
using namespace std;

struct RSAKeyPair {
    int64 publicKey_e;
    int64 secretKey_d;
    int64 n;
    string en;
};

class CRsaOperate {
public:
    int NewRsaKeyPair(RSAKeyPair &keyPair); // 服务器端生成RSA公私钥对
    string ClientEncry(string Des, int64 publicKey_e, int64 n); // 客户端使用服务器的公钥加密DES秘钥
    string ServerDecry(string keyInfo, int64 secretKey_d, int64 n); // 服务器使用私钥解密客户端发来的DES秘钥
    
private:
    int64 PowMod(int64 a, int64 q, int64 n); // 计算(a^q)%n
    int64 RandomPrime(char bits); // 质数生成函数
    int64 Euler(int64 n); // 返回小于n且与n互质的正整数个数
    bool RabinMillerKnl(int64 n); // Rabin-Miller原理，判断参数n是否是质数
    bool RabinMiller(int64 n, int time);// 重复调用RabinMillerKnl()判别某数n是否是质数
    bool GreatestCommonDivisor(int64 p, int64 q); // 判断两个参数是否互质
};