/*
 * msgtest.c
 *
 *  Created on: 2019-12-30
 *      Author: zhtro
 */

#define LOG_TAG    "msg"
#define LOG_LVL     ELOG_LVL_DEBUG

#include "elog.h"

#include "msg.h"
#include "stdio.h"
#include <xdc/runtime/Memory.h>
#include <ti/sysbios/knl/Task.h>

#define MSGTEST_HELLO_SERVER (1)
#define MSGTEST_HELLO_CLIENT (2)

static SOCKET _clients=NULL;

static int on_servermsg(uint16_t id, void* pData, int size)
{
	//printf("SERVER: recved msg: id %x  size %d  msg %s\n",id, size, (char*) pData);

	return 1;
}

static int on_serverconnect(SOCKET s, uint16_t id)   //服务端：有新的客户端连入
{
	//printf("SERVER: client connected: socket 0x%x id %x\n",(UINT32)s,id);

	msg_register_cb(s,MSGTEST_HELLO_CLIENT,on_servermsg);

	char hello[] = "hello i am server";
	msg_send(s,MSGTEST_HELLO_SERVER,hello,sizeof(hello));
	//printf("SERVER: send: %s\n",hello);

	return 1;
}

static int on_clientmsg(uint16_t id, void* pData, int size)
{
	//printf("CLIENT: recved msg: id %x  size %d  msg %s\n",id, size, (char*) pData);

	return 1;
}

static int on_clientconnected(SOCKET s, uint16_t peerid, uint16_t port)   //客户端：连接成功
{
	//printf("CLIENT: connected: socket 0x%x peerid %x port %d\n",(UINT32)s,peerid,port);

	_clients = s;
	if(msg_register_cb(s,MSGTEST_HELLO_SERVER,on_clientmsg)!=MSG_OK)
	{
		//printf("CLIENT: register MSGTEST_HELLO_SERVER failed\n");
	}

	char hello[] = "hello i am client";
	msg_send(s,MSGTEST_HELLO_CLIENT,hello,sizeof(hello));
	//printf("CLIENT: send: %s\n",hello);
	return 1;
}
void msgtestclient(uint16_t myid, uint16_t peerid,uint16_t port)
{
	msg_init(myid);
	msg_client_conf_t cconf;
	msg_clientconf_init(&cconf);
	cconf.on_connected = on_clientconnected;
	msg_dial(peerid,port,&cconf);
	//printf("CLIENT: connecting to : id %x port %d\n",peerid, port);
}


void msgtestserver(uint16_t myid, uint16_t port)
{
	msg_init(myid);

	msg_server_conf_t sconf;
	msg_serverconf_init(&sconf);
	sconf.on_newclient = on_serverconnect;
	msg_listen(port,20,&sconf);
	//printf("SERVER: listening on : id %x port %d\n",myid, port);
}

void msgtestTask(UINT32 myid, UINT32 port)
{
	log_d("=============LOOPBACK test start=============");
//	//printf("=============LOOPBACK test start=============\n");
	msg_teardown();
	Task_sleep(1000);

	Memory_Stats beforestatus;
	Memory_Stats afterstatus;
	Memory_getStats(NULL, &beforestatus);

//	//printf("memory:total:%d\tfree:%d\tlargest free:%d\n"
//			,status.totalSize
//			,status.totalFreeSize
//			,status.largestFreeSize);

	msgtestserver(myid,port);

	for(int i=0;i<500;i++)
	{
		log_d("\n---test %d---\n",i);
		msgtestclient(myid,myid,port);
		Task_sleep(200);
		msg_close(_clients);
		Task_sleep(200);
	}


	msg_teardown();
	Task_sleep(1000);

	Memory_getStats(NULL, &afterstatus);

	log_d("BEFORE:memory:total:%d\tfree:%d\tlargest free:%d\n"
			,beforestatus.totalSize
			,beforestatus.totalFreeSize
			,beforestatus.largestFreeSize);

	log_d("AFTER memory:total:%d\tfree:%d\tlargest free:%d\n"
			,afterstatus.totalSize
			,afterstatus.totalFreeSize
			,afterstatus.largestFreeSize);



	log_d("=============LOOPBACK test end=============\n");
//	//printf("=============LOOPBACK test end=============\n");

}
void msgtestloopback(uint16_t myid, uint16_t port)
{
	HANDLE h =0;
	h=TaskCreate(msgtestTask, "msgtestTask" , OS_TASKPRINORM, 0x1000, myid, port, 0);
}

