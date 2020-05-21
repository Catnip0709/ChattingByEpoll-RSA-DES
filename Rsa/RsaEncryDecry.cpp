#include <assert.h>
#include <string>
#include "../Rsa.h"
#include "../HelpFunc.h"
using namespace std;

// 客户端使用服务器的公钥加密DES秘钥
// unsigned short = 16位，本作业中64为需要分四次加密
// 使用服务器公钥，计算 C = (M^e) mod n
// 返回值是4个string类型的16位加密结果，逗号分隔
string CRsaOperate::ClientEncry(string DesKey, int64 publicKey_e, int64 n) {
    // 将8个字母的string类型DesKey转为64位int类型，例如ABCDEFGH
    int64 int64DesKey = 0;
    for (unsigned int i = 0; i < DesKey.length(); ++i) {
        int64DesKey += DesKey[i];
        if (i != DesKey.length() - 1) {
            int64DesKey <<= 8;
        }
    }
    
    // 64为int拆成4份，每份16位，得到的M[0] = GH，M[1] = EF，M[2] = CD，M[3] = AB
    unsigned short* pRes = (unsigned short*)&int64DesKey;
    unsigned short M[4];
    for (int i = 0; i < 4; ++i) {
        M[i] = pRes[i];
    }

    string result;
    // 对每一份执行加密函数，并将4个16位数字转成string，用逗号分隔
    for (int i = 3; i >= 0; --i) {
        string temp = to_string(PowMod(M[i], publicKey_e, n));
        result += temp;
        result += ',';
    }
    return result;
}

// 服务器使用私钥解密客户端发来的DES秘钥
// 使用服务器私钥，计算 M = (C^d) mod n 
string CRsaOperate::ServerDecry(string keyInfo, int64 secretKey_d, int64 n) {
    // keyInfo = "AA,BB,CC,DD,"，这些XX是64位的数字
    string DesKey = "";
    int pos = 0;
    for (int i = 0; i < 4; i++) {
        string tempStr = "";
        for (; keyInfo[pos] != ','; ++pos) {
            tempStr += keyInfo[pos];
        }
        ++pos;

        int64 Ci = fromStrToInt64(tempStr);
        int64 nRes = PowMod(Ci, secretKey_d, n);
        unsigned short * pRes = (unsigned short*)&nRes;
        if(pRes[1] != 0 || pRes[2] != 0 || pRes[3] != 0) { // error
            perror("sever ServerDecry() err");
            return 0;
        }
        else {
            // pRes[0]是16bit数字，可以转成2个字母
            DesKey += fromShortToString(pRes[0]);
        }
    }
    
    return DesKey;
}