// 业务值定义
#define EPOLL_SIZE              256
#define MAX_LINE                20
#define PORT                    9977
#define MSG_SIZE                4096
#define DEFAULT_SERVER          "127.0.0.1"
#define EPOLL_TIMEOUT           -1
#define int64                   unsigned long long int
#define MSG_HEAD_KEY            "key"  // 客户端发给服务器的消息头部1
#define MSG_HEAD_DATA           "data" // 客户端发给服务器的消息头部2
#define SERVER_GET_DES_KEY      "GetKeySuccess"

#define DATA_EXCHANGE           100 // 不处于密钥协商状态，处于数据交换状态
#define KEY_AGREE_SEND_KEY      101 // 密钥协商状态中发送公钥对
#define KEY_AGREE_CONFIRM       102 // 密钥协商状态中确认成功接收DES秘钥

// 返回码定义
#define SUCCESS                 0

#define INPUT_QUIT              2000
#define MISS_DES_KEY            2001

#define SERVER_SOCKET_ERR       3000
#define SERVER_BIND_ERR         3001
#define SERVER_LISTEN_ERR       3002
#define SERVER_ACCEPT_ERR       3003 
#define SERVER_RECV_ERR         3004
#define SERVER_SEND_ERR         3005
#define SERVER_EPOLL_CREAT_ERR  3006
#define SERVER_KEY_AGRRE_ERR    3007
#define SERVER_HEADER_FORMAT    3008
#define SERVER_EPOLL_CTL_ERR    3010
#define SERVER_READ_ERR         3011

#define CLIENT_INETPTON_ERR     1010
#define CLIENT_SOCKET_ERR       1011
#define CLIENT_CONNECT_ERR      1012
#define CLIENT_SEND_ERR         1013
#define CLIENT_RECV_ERR         1014
#define CLIENT_KEY_AGRRE_ERR    1015
#define CLIENT_KEY_CONFIRM_ERR  1016
#define CLIENT_EPOLL_CREAT_ERR  1017
#define CLIENT_EPOLL_CTL_ERR    1018
#define CLIENT_READ_ERR         1019

#define DES_ERR_BIT             1020
#define INIT_REPLACE_IP         1021 // 初始置换IP
#define INVERSE_REPLACE_IP      1022 // 逆初始置换IP
#define DES_ENCRY_ERR           1023 // 加密失败
#define DES_DECRY_ERR           1024 // 解密失败

#define RSA_KEY_PAIR_ERR        1040 // 服务器端生成RSA公私钥对失败