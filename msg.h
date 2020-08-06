/*
 * msg.h
 *
 *  Created on: 2019-12-26
 *      Author: zhtro
 *
 *      在标准socket上包装一层基于消息的应用层,可用于添加TLS
 *      消息格式如下：
 *      | len(4B) |  type(2B) | id(2B) | data |
 *
 *      1.所有api都是异步的,回调函数都是在线程环境中运行，所以不能阻塞
 *      2.可以在这一层中继续添加TLS，ID到IP的解析等协议
 *      3.依赖于Collections-C库 https://github.com/zhtroy/Collections-C
 *
 *
 *
 */

#ifndef MSG_H_
#define MSG_H_

#include "netmain.h"
#include "stdint.h"

//=============config start===================
#define USE_MBEDTLS   0
#define MSG_MAX_DATA_SIZE (256)
#define MSG_MAX_MSG_PER_SOCKET (64)   //一个socket上可以注册的接收事件数量
#define MSG_SUB_NET "192.168.127"     //不用加括号

//=============config end===================


/*
 * callback defines
 */
typedef int(*cb_msgrecved)(uint16_t id, void* pData, int size);
/*服务端*/
typedef int(*cb_servernewclient)(SOCKET s, uint16_t id);   //有新的客户端连入
typedef int(*cb_serverdelclient)(SOCKET s, uint16_t id);   //某一客户端断开连接

/*客户端*/
typedef int(*cb_clientconnected)(SOCKET s, uint16_t peerid, uint16_t port);   //连接成功
typedef int(*cb_clientdisconnected)(SOCKET s, uint16_t peerid);   			//连接断开
typedef int(*cb_clientconnectfailed)(SOCKET s, uint16_t peerid, int errno);   			//连接失败

//===========struct start==============//
#pragma pack(1)
typedef struct msg_packet_s
{
	int len;     //消息数据长度
    int type;  //消息类型
    uint16_t id;  //车辆ID
    uint8_t data[MSG_MAX_DATA_SIZE];  //消息数据
}msg_packet_t;
#pragma pack()

typedef struct msg_client_conf
{
	cb_clientconnected on_connected;
	cb_clientdisconnected on_disconnected;
	cb_clientconnectfailed on_connectfailed;
	int connect_retrys;
}msg_client_conf_t;

typedef struct msg_server_conf
{
	cb_servernewclient on_newclient;
	cb_serverdelclient on_delclient;
}msg_server_conf_t;

//===========struct end==============//

enum msg_stat {
    MSG_OK                   	     = 0,

    //内存分配错误
    MSG_ERROR_ALLOC                  = 1,

    //socket已经被关闭
    MSG_ERROR_SOCKET_CLOSED          = 2,

    //注册的回调函数超过最大量，修改MSG_MAX_MSG_PER_SOCKET
    MSG_ERROR_CALLBACK_OVERFLOW      = 3,

    //msg 模块没有初始化
    MSG_ERROR_NOT_INITED             = 4,

    //msg 模块重复初始化
    MSG_ERROR_REINIT                 = 5
};

#define MSG_PACKET_MAX_SIZE (sizeof(msg_packet_t))
#define MSG_HEADER_SIZE (MSG_PACKET_MAX_SIZE-MSG_MAX_DATA_SIZE)



//========API start===========================//
extern int msg_listen(uint16_t port, int maxclients, msg_server_conf_t* pserverconf );
extern int msg_dial(uint16_t peerid, uint16_t port, msg_client_conf_t* pclientconf);
extern int msg_close(SOCKET s);
extern int msg_send(SOCKET s, int type, const void *pData, int len);
extern int msg_register_cb(SOCKET s, int evt, cb_msgrecved cb);
extern cb_msgrecved msg_get_cb(SOCKET s, int evt);
extern int msg_init(uint16_t myAddr);
extern int msg_teardown();
extern void msg_id2ip(uint16_t id, char * ip);
extern uint16_t msg_ip2id(const char* ip);
extern void msg_serverconf_init(msg_server_conf_t * pconf);
extern void msg_clientconf_init(msg_client_conf_t * pconf);
//========API end===========================//

#endif /* MSG_H_ */
