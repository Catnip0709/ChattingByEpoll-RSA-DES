#include <iostream>
#include <string>
#include <stdlib.h>
#include "../Rsa.h"
#include "../DefineCode.h"


// 模乘运算
inline int64 MulMod (int64 a, int64 b, int64 n) {
    return (a % n) * (b % n) % n;
}

// 计算(a^q)%n，模幂运算即首先计算某数的若干次幂，然后对其结果进行取模运算，
int64 CRsaOperate::PowMod(int64 base, int64 pow, int64 n) {
    int64 a = base, b = pow, c=1;
    while(b) {
        while(!(b & 1)) {
            b>>=1; 
            a = MulMod(a, a, n);
        }   
        b--; 
        c = MulMod(a, c, n);
    } 
    return c;
}

// Rabin-Miller原理，判断参数n是否是质数。可能不准。
bool CRsaOperate::RabinMillerKnl(int64 n) {
    int64 q = n - 1, k = 0; 
    while (!(q & 1)) {
        ++k;
        q >>= 1;
    }
    int64 a = 2 + rand() % (n - 1); // 随机数a满足 2 ≤ a < n − 1
    if (PowMod(a, q, n) == 1) {
        return true;
    }
    for (int64 j = 0; j < k; j++) {
        int64 z = 1;
        for(int64 w = 0; w < j; w++) {
            z *= 2;
        }
        if(PowMod(a, z * q, n) == n-1) {
            return true;
        }
    }
    return false;
}

// 重复调用RabinMillerKnl()判别某数n是否是质数
bool CRsaOperate::RabinMiller(int64 n, int time) {
    for(int i = 0; i < time; ++i) {
        if(!RabinMillerKnl(n)) {
            return false;
        }
    } 
    return true;
}

// 质数生成函数
int64 CRsaOperate::RandomPrime(char bits) {
    int64 base;
    
    static int randHelp = 0;
    randHelp++;
    srand((unsigned)time(NULL) + randHelp);

    do {
        base = (unsigned long)1 << (bits - 1); //保证最高位是 1
        base += rand() % base; //加上一个随机数
        base |= 1; //保证最低位是1，即保证是奇数
    } while(!RabinMiller(base, 30)); //测试 30 次
    return base; //全部通过认为是质数
}

// 判断两个参数是否互质
bool CRsaOperate::GreatestCommonDivisor(int64 p, int64 q) {
    int64 a = p > q ? p : q;
    int64 b = p < q ? p : q;
    int t;
    if(p == q) {
        return false; //两数相等,最大公约数就是本身
    }
    else {
        while(b) { // 辗转相除法，GreatestCommonDivisor(a,b) = GreatestCommonDivisor(b,a-qb)
            a = a % b;
            t = a;
            a = b;
            b = t;
        } 
        if (a == 1) {
            return true;
        }
        else {
            return false;
        }
    }
}

// 返回小于n且与n互质的正整数个数
int64 CRsaOperate::Euler(int64 n) {
    int64 res = n, a = n;
    for (int64 i = 2; i * i <= a; ++i) {
        if (a % i == 0) {
            res = res / i * (i - 1);//先进行除法是为了防止中间数据的溢出
            while (a % i == 0) {
                a /= i;
            }
        }
    }
    if (a > 1) {
        res = res / a * (a - 1);
    }
    return res;
}

/*
任意选取两个质数p和q，设n = p × q；
函数ф(n)为 Euler 函数，返回小于n且与n互质的正整数个数；
选择一个任意正整数e，使其与ф(n)互质且小于ф(n)，公钥{e，n}已经确定；
最后确定d，使得 d*e ≡ 1 % ф(n)，即(d*e − 1) % ф(n) = 0，至此，私钥{d，n}也被确定。
*/
// 服务器端生成RSA公私钥对
int CRsaOperate::NewRsaKeyPair(RSAKeyPair &keyPair) {
    // 生成公钥{e，n}
    int64 primeP = RandomPrime(16);
    int64 primeQ = RandomPrime(16);
    int64 n = primeP * primeQ;
    
    int euler = Euler(n);
    int64 e;
    while(1) {
        e = rand() % 65536 + 1;
        // e = rand() % (euler - 1) + 1;
        if (GreatestCommonDivisor(e, euler)) {
            break;
        }
    }
    
    // 生成私钥{d，n}
    int64 max = 0xffffffffffffffff - euler;
    int64 i = 1, d = 0;

    while(1) {
        if ( ((i * euler) + 1) % e == 0) {
            d = ((i * euler) + 1) / e;
            break;
        }
        i++;
        int64 temp = (i + 1) * euler;
        if (temp > max){
            break;
        }
    }
    
    // 如果循环结束后d值仍然为0表示秘钥生成失败
    if (d == 0) {
        return RSA_KEY_PAIR_ERR;
    }

    keyPair.publicKey_e = e;
    keyPair.secretKey_d = d;
    keyPair.n = n;
    keyPair.en = to_string(e) + "," + to_string(n);

    return SUCCESS;
}
