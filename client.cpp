#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>

#include "cs.h"
#include "DefineCode.h"
#include "Des.h"
#include "HelpFunc.h"
#include "Rsa.h"

using namespace std;

string DES_KEY = "";

int sendMsgToServer(sockaddr_in serverAddr, int fd_skt, int KeyAgreement = DATA_EXCHANGE, string msg = "") {
    char cMsg[MSG_SIZE];
    memset(cMsg, 0, sizeof(cMsg));

    if (KeyAgreement == KEY_AGREE_SEND_KEY) { // 密钥协商
        msg = ":" + msg;
        msg = MSG_HEAD_KEY + msg; // 添加头部信息
        for (int i = 0; i < msg.length(); i++) { // string转char[]
            cMsg[i] = msg[i];
        }
        cMsg[msg.size()] = '\0';
    }
    else { // 发送普通对话
        if (DES_KEY == "") {
            perror("client miss DES_KEY");
            return MISS_DES_KEY;
        }

        cin.getline(cMsg, sizeof(cMsg)); // 不用cin，因为不能含空格
        if (strcmp(cMsg, "quit") == 0) {
            return INPUT_QUIT;
        }
        
        cout << "Send message to <" << inet_ntoa(serverAddr.sin_addr) << ">: " << cMsg << endl;

        string encryResult; // 加密结果
        CDesOperate des;
        if (des.Encry(cMsg, DES_KEY, encryResult) != 0) { // 加密
            perror("client sendMsgToServer() err");
            return DES_ENCRY_ERR;
        }
        
        encryResult = ":" + encryResult;
        encryResult = MSG_HEAD_DATA + encryResult; // 加密完毕后添加头部信息

        memset(cMsg, '\0', MSG_SIZE);
        for (int i = 0; i < encryResult.length(); i++) { // 加密结果string转char[]
            cMsg[i] = encryResult[i];
        }
        cMsg[encryResult.size()] = '\0';
    }
    
    if (send(fd_skt, cMsg, strlen(cMsg), 0) < 0) { // send，客户端向服务端发消息
        perror("client sendMsgToServer() - send() err");
        return CLIENT_SEND_ERR;
    }

    return SUCCESS;
}

int recvMsgFromServer(sockaddr_in serverAddr, int fd_skt, int KeyAgreement = DATA_EXCHANGE, string *strSMsg = NULL) {
    char sMsg[MSG_SIZE];
    memset(sMsg, 0, sizeof(sMsg));
    int sLen = recv(fd_skt, sMsg, sizeof(sMsg), 0); // recv，接收服务器发来的消息
    if(sLen <= 0) { 
        perror("client recvMsgFromServer() - recv() err");
        return CLIENT_RECV_ERR;
    }
    sMsg[sLen] = '\0';

    if (KeyAgreement == KEY_AGREE_SEND_KEY) {
        *strSMsg = sMsg;
    }
    else {
        if (DES_KEY == "") {
            perror("client miss DES_KEY");
            return MISS_DES_KEY;
        }

        string decryResult = "";
        CDesOperate des;
        if (des.Decry(sMsg, DES_KEY, decryResult) != 0) { //解密
            perror("client recvMsgFromServer() err");
            return DES_DECRY_ERR;
        }
        
        if (KeyAgreement == KEY_AGREE_CONFIRM) {
            return SUCCESS;
            /*if (!decryResult.compare(SERVER_GET_DES_KEY)) {
                return SUCCESS;
            }
            else {
                perror("client recvMsgFromServer() confirm desKey err");
                return CLIENT_KEY_CONFIRM_ERR;
            }*/
        }

        cout << "Receive message from <" << inet_ntoa(serverAddr.sin_addr) << ">: " 
             << decryResult << endl;
    }
    return SUCCESS;
}

// 秘钥协商：（1）生成随机DES秘钥（2）使用公钥加密DES密钥并发送给服务端
int KeyAgreement(sockaddr_in serverAddr, int fd_skt) {
    CRsaOperate rsa;
    CDesOperate des;
    DES_KEY = CDesOperate::GenerateDesKey();
    string strSMsg;
    if (recvMsgFromServer(serverAddr, fd_skt, KEY_AGREE_SEND_KEY, &strSMsg) != SUCCESS) { // 接收服务器的公钥对
        perror("client KeyAgreement()-recvMsgFromServer()-1 err");
        return CLIENT_KEY_AGRRE_ERR;
    }
    int pos = strSMsg.find(",", 0);
    int64 e = fromStrToInt64(strSMsg.substr(0, pos));
    int64 n = fromStrToInt64(strSMsg.substr(pos + 1, strSMsg.size()));
    string encryDesKey = rsa.ClientEncry(DES_KEY, e, n);
    
    if (sendMsgToServer(serverAddr, fd_skt, KEY_AGREE_SEND_KEY, encryDesKey) != SUCCESS) { // 给服务器发送加密过的DES秘钥
        perror("client KeyAgreement() err");
        return CLIENT_KEY_AGRRE_ERR;
    }

    if (recvMsgFromServer(serverAddr, fd_skt, KEY_AGREE_CONFIRM) != SUCCESS) { // 接收服务器的确认DES接收成功
        perror("client KeyAgreement()-recvMsgFromServer()-2 err");
        return CLIENT_KEY_AGRRE_ERR;
    }

    return SUCCESS;
}

int client() {
    sockaddr_in serverAddr; // 一个将来与套接字绑定的结构体
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_port = (PORT); // 从客户端的PORT端口接收服务器信息
    serverAddr.sin_family = AF_INET; // 协议簇，AF_INET表示TCP/IP协议   
    cout << "Please input the server address: (输入1连接默认服务器)" << endl;
    char sAddr[20];
    cin >> sAddr;

    if (strcmp(sAddr, "1") == 0) {
        if(inet_pton(AF_INET, DEFAULT_SERVER, (void *)&serverAddr.sin_addr) <= 0) {
            perror("client inet_pton() err");
            return CLIENT_INETPTON_ERR;
        }
    }
    else {
        if(inet_pton(AF_INET, DEFAULT_SERVER, (void *)&serverAddr.sin_addr) <= 0) {
            perror("client inet_pton() err");
            return CLIENT_INETPTON_ERR;
        }
    }

    int fd_skt = socket(AF_INET, SOCK_STREAM, 0); // socket函数新建套接字fd_skt
    if (fd_skt < 0) {
        perror("client socket() err");
        return CLIENT_SOCKET_ERR;
    }

   if (connect(fd_skt, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) { // connect向服务器发起连接请求
	    perror("client connect() err");       
        return CLIENT_CONNECT_ERR;
    }

    if (KeyAgreement(serverAddr, fd_skt) != SUCCESS) { // 密钥协商过程
        return CLIENT_KEY_AGRRE_ERR;
    }

    cout << "Connect Success! \nBegin to chat..." << endl;
    cin.ignore(1024,'\n'); // 去除上一个cin残留在缓冲区的\n
    while(1) {
        if (int code = sendMsgToServer(serverAddr, fd_skt) != 0) { // 给服务器发消息
            break;
        }
        if (recvMsgFromServer(serverAddr, fd_skt) != 0) { //接收服务器消息
            break;
        }
    }
    cout << "--- client end ---" << endl;
    close(fd_skt); // 服务器会recv err: SUCCESS，从而结束连接
}
