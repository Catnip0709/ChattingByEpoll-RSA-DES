#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <fcntl.h>

#include "cs.h"
#include "DefineCode.h"
#include "Des.h"
#include "Rsa.h"

using namespace std;

struct clientInfo {
    int fd;
    sockaddr_in* clientAddr;
    RSAKeyPair keyPair;
    string DES_KEY = "";
    bool KeyAgreement = true;
};

clientInfo *cInfo; // TODO::暂未实现服务器一对多

int sendMsgToClient(clientInfo *cInfo, int KeyAgreement = DATA_EXCHANGE, string key = "") {
    char sMsg[MSG_SIZE];
    memset(sMsg, 0, sizeof(sMsg));
    
    if (KeyAgreement == KEY_AGREE_SEND_KEY) { // 发送RSA公钥对
        for (int j = 0; j < key.size(); ++j) { // 加密结果string转char[]
            sMsg[j] = key[j];
        }
        sMsg[key.size()] = '\0';
    }
    else { // 发送普通数据信息
        if (cInfo->DES_KEY == "") {
            perror("server miss DES_KEY");
            return MISS_DES_KEY;
        }
        if (KeyAgreement == DATA_EXCHANGE) {
            int count = 0, sum = 0;
            while((count = read(STDIN_FILENO, sMsg, MSG_SIZE)) > 0) {
                sum += count;
            }
            if (count == -1 && errno != EAGAIN){
                perror("server sendMsgToClient() read error");
                return SERVER_READ_ERR;
            }
            sMsg[sum - 1] = '\0'; // 将末尾多余的\n置为\0
            cout << "Send message to <" << inet_ntoa(cInfo->clientAddr->sin_addr) << ">: " 
                 << sMsg << endl;
        }
        else { // 秘钥协商结束，服务器给客户端发送协商成功的信息
            strcpy(sMsg, SERVER_GET_DES_KEY);
        }

        if (strcmp(sMsg, "quit") == 0) {
            return INPUT_QUIT;
        }

        string encryResult; // 加密结果
        CDesOperate des;
        if (des.Encry(sMsg, cInfo->DES_KEY, encryResult) != 0) { // 加密
            perror("encry err");
            return DES_ENCRY_ERR;
        }
        memset(sMsg, '\0', MSG_SIZE);
        for (int j = 0; j < encryResult.length(); ++j) { // 加密结果string转char[]
            sMsg[j] = encryResult[j];
        }
        sMsg[encryResult.size()] = '\0';
    }

    if (send(cInfo->fd, sMsg, strlen(sMsg), 0) <= 0) { 
        // send()将服务器的消息发给客户端
        perror("server send err");
        return SERVER_SEND_ERR;
    }
    
    return SUCCESS;
}

int recvMsgFromClient(clientInfo *cInfo) {
    char* clientAddr = inet_ntoa(cInfo->clientAddr->sin_addr);

    char cMsg[MSG_SIZE];
    memset(cMsg, 0, sizeof(cMsg));
    int cLen = 0, count = 0;
    while((count = recv(cInfo->fd, cMsg, sizeof(cMsg), 0)) > 0){ 
        // recv将收到的信息存在cMsg中
        // ET模式（边缘触发），需要一次将缓存中的数据通过while循环读取完毕
        cLen += count;
    }
    cMsg[cLen] = '\0';

    int KeyAgreement = DATA_EXCHANGE;    
    // 截取消息头部，判断是密钥协商阶段还是互通消息阶段，并截掉头部
    if (cMsg[0] == 'k' && cMsg[1] == 'e' && cMsg[2] == 'y') {
        KeyAgreement = KEY_AGREE_SEND_KEY; 
        strncpy(cMsg, cMsg + 4, sizeof(cMsg));
        CRsaOperate rsa;
        cInfo->DES_KEY = rsa.ServerDecry(cMsg, cInfo->keyPair.secretKey_d, cInfo->keyPair.n);
    }
    else if (cMsg[0] == 'd' && cMsg[1] == 'a' && cMsg[2] == 't' && cMsg[3] == 'a') {
        strncpy(cMsg, cMsg + 5, sizeof(cMsg));
    }
    else {
        perror("server recvMsgFromClient() header format err");
        return SERVER_HEADER_FORMAT;
    }

    if (KeyAgreement == DATA_EXCHANGE) { // cs对话
        if (cInfo->DES_KEY == "") {
            perror("server miss DES_KEY");
            return MISS_DES_KEY;
        }
        string decryResult = "";
        CDesOperate des;
        if (des.Decry(cMsg, cInfo->DES_KEY, decryResult) != 0) { //解密
            perror("decry err");
            return DES_DECRY_ERR;
        }

        cout << "Receive message from <" << clientAddr << ">: "
             << decryResult << endl;
    }

    return SUCCESS;
}

int server() {
    struct epoll_event events[MAX_LINE]; // epoll数据结构

    struct sockaddr_in serverAddr; // 一个将来与套接字绑定的结构体
    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_port = PORT; // 从服务器的PORT端口接收客户端信息
    serverAddr.sin_family = AF_INET; // 协议簇，AF_INET表示TCP/IP协议
    serverAddr.sin_addr.s_addr = htonl(INADDR_ANY); // 指定接收的信息来自于某个IP，这里随意

    int fd_skt = socket(AF_INET, SOCK_STREAM, 0); // socket函数新建套接字fd_skt
    if (fd_skt < 0) {
        perror("server socket err");
        return SERVER_SOCKET_ERR;
    }
     
    int fd_ep = epoll_create(EPOLL_SIZE);  // 创建epoll的句柄，fd_ep是epoll的文件描述符
    if (fd_ep < 0) { // 若成功返回一个大于0的值，表示 epoll 实例；出错返回-1
        perror("server epoll_create err");
        return SERVER_EPOLL_CREAT_ERR;
    }

    struct epoll_event ep_event, ep_input; // 针对监听的fd_skt，创建2个epollevent
    fcntl(fd_skt, F_SETFL, O_NONBLOCK); // 设置非阻塞
    ep_event.data.fd = fd_skt;
    ep_event.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_skt, &ep_event) < 0) { // 注册epoll事件
        // 参数3：需要监听的fd，参数4：告诉内核需要监听什么事
        perror("server epoll_ctl-1 error!\n");
        return SERVER_EPOLL_CTL_ERR;
    }

    // 给fd_ep绑定监听标准输入的文件描述符（为了实现全双工）
    fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
    ep_input.data.fd  = STDIN_FILENO;
    ep_input.events = EPOLLIN | EPOLLET;
    if (epoll_ctl(fd_ep, EPOLL_CTL_ADD, STDIN_FILENO, &ep_input) < 0) {
        perror("server epoll_ctl-2 error");
        return SERVER_EPOLL_CTL_ERR;
    }

    if (bind(fd_skt, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0 ) { //bind绑定套接字与serverAddr
        perror("server bind err");
        return SERVER_BIND_ERR;
    }
    
    if (listen(fd_skt, MAX_LINE) < 0) { // listen监听套接字fd_skt
        perror("server listen err");
        return SERVER_LISTEN_ERR;
    }
    
    cout << "Listening..." << endl;
    cin.ignore(1024,'\n');
    while(1) {
        int eventNum = epoll_wait(fd_ep, events, MAX_LINE, EPOLL_TIMEOUT);   
        //参数2：epoll将发生的事件复制到events数组中。events不可以是空指针，内核只负责把数据复制到数组中，不会在用户态中分配内存，效率很高。
        //参数3: 返回的events的最大个数，如果最大个数大于实际触发的个数，则下次epoll_wait的时候仍然可以返回
        //返回值：大于0表示事件的个数；等于0表示超时；小于0表示出错。
        
        for (int i = 0; i < eventNum; ++i) {
            if (events[i].data.fd == fd_skt) { // 有新的连接
                sockaddr_in* clientAddr = new sockaddr_in();
                socklen_t length = sizeof(clientAddr);
                int fd_client = accept(fd_skt, (struct sockaddr*)clientAddr, &length);
                // accept接收连接请求：程序在此阻塞直至产生第一次握手
                // 接收到的信息存于第二第三个参数中
                // 返回值是新的文件描述符，用于后续read/recv和write/send调用

                if (fd_client < 0) {
                    perror("server accept err");
                    continue;
                }
                // 生成RSA公钥/私钥对
                RSAKeyPair keyPair;
                CRsaOperate rsa;
                while(1) { // 可能生成失败（由于采用随机数生成），循环直到生成成功
                    if(rsa.NewRsaKeyPair(keyPair) == SUCCESS) {
                        break;
                    }
                }

                cInfo = new clientInfo();
                cInfo->fd = fd_client;
                cInfo->clientAddr = clientAddr;
                cInfo->keyPair = keyPair;

                fcntl(fd_client, F_SETFL, O_NONBLOCK);
                struct epoll_event new_client_event;
                new_client_event.events = EPOLLIN | EPOLLET;
                new_client_event.data.ptr = cInfo; // new_client_event.data是union类型
                
                // 注册epoll事件，让epoll监听这个客户端发来的消息
                if (epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_client, &new_client_event) < 0) { 
                    perror("server KeyAgreement() epoll_ctl-1 error");
                    return SERVER_EPOLL_CTL_ERR;
                }

                // 将公钥对发给客户端
                if (sendMsgToClient(cInfo, KEY_AGREE_SEND_KEY, keyPair.en) != SUCCESS) {
                    perror("server KeyAgreement() sendMsgToClient-1 error");
                    return SERVER_SEND_ERR;
                }

                cout << "server: got connection from " << inet_ntoa((*clientAddr).sin_addr)
                     << ", port " << PORT
                     << ", socket " << fd_client << endl;
            }
            else if (events[i].events == EPOLLIN) { // 接收到数据，读socket
                if (events[i].data.fd == STDIN_FILENO) { // 标准输入
                    // TODO::暂未实现服务器一对多
                    int KeyAgreement = DATA_EXCHANGE;
                    if (int code = sendMsgToClient(cInfo, KeyAgreement) != SUCCESS) { // 给客户端发消息
                        if (code == INPUT_QUIT) { // 服务器选择结束当前对话
                            close(cInfo->fd);
                        }
                        continue;
                    }
                }
                else { // TCP连接发来的数据
                    clientInfo *cInfo = (clientInfo*)events[i].data.ptr;
                    if (cInfo == NULL) {
                        perror("server cInfo NULL");
                        continue;
                    }
                    if (cInfo->KeyAgreement) { // 密钥协商阶段
                        if (recvMsgFromClient(cInfo) != SUCCESS) { // 收到使用公钥加密的DES密钥
                            perror("server recvMsgFromClient error");
                            return SERVER_RECV_ERR;
                        }
                        if (sendMsgToClient(cInfo, KEY_AGREE_CONFIRM) != SUCCESS) {
                            // 将成功得到DES秘钥的消息发给客户端
                            perror("server sendMsgToClient-2 error");
                            return SERVER_SEND_ERR;
                        }
                        cInfo->KeyAgreement = false; // 密钥协商结束
                        cout << "Begin to chat..." << endl;
                    }
                    else { // 普通数据交互阶段
                        recvMsgFromClient(cInfo); // 接收客户端消息
                    }
                }
            }
        }
    }
    cout << "-- server end --" << endl;
    close(fd_skt);
    return SUCCESS;
}