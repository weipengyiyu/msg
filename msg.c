/*
 * msg.c
 *
 *  Created on: 2019-12-26
 *      Author: zhtro
 */

#define LOG_TAG    "msg"
#define LOG_LVL     ELOG_LVL_INFO

#include "elog.h"
#include "msg.h"
#include "netmain.h"
#include <ti/ndk/inc/tools/console.h>
#include "string.h"
#include "assert.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "hashtable.h"
#include "array.h"
#include "list.h"
#include <ti/sysbios/knl/Mailbox.h>
#include <ti/sysbios/BIOS.h>



typedef struct msg_server
{
	uint16_t port;
	HANDLE hDaemon;
	msg_server_conf_t serverconf;
}msg_server_t;

typedef struct msg_client
{
	uint16_t peerid;
	uint16_t port;
	msg_client_conf_t clientconf;
}msg_client_t;

typedef struct socket_context
{
	SOCKET s;
	int evtpool[MSG_MAX_MSG_PER_SOCKET];
	int evtcount;
	HashTable* cbs;
	Mailbox_Handle sendmb;
}socket_context_t;

enum LeaveState{
	normal,
	disconnect,
	connectfail
};
/*
 * 动态分配
 */
static List* _serverlist = 0;  //list of msg_server_t
//static List* _clientlist;  //list of msg_client_t
static Array * _daemonarray=0;
/*
 * 键是socket 值是socket_context_t
 * 比较器使用指针比较
 */
static HashTable* _sockettable=0;

/*
 * 动态分配  end======================
 */


static uint16_t _myaddr=0;
static uint16_t _inited = 0;

static void task_send(UINT32 arg0, UINT32 arg1);
static int dtask_server_recv( SOCKET s, UINT32 arg );
static void task_client_recv(UINT32 arg0,UINT32 arg1 );

#define _CHECK_INIT if(!_inited) return MSG_ERROR_NOT_INITED

static int hashintkeycmp(const void* a ,const void * b)
{
	if(*((int*)a) == *((int*)b))
	{
		return 0;
	}
	else
	{
		return -1;
	}
}

static int hashpointerkeycmp(const void* a ,const void * b)
{
	if(a==b)
	{
		return 0;
	}
	else
	{
		return -1;
	}
}

static void _socketcontext_free(socket_context_t *psocketcon)
{
	if(!psocketcon)
		return;

	if(psocketcon->cbs)
	{
		hashtable_destroy(psocketcon->cbs);
		psocketcon->cbs = NULL;
	}

	if(psocketcon->sendmb)
	{
		Mailbox_delete(&psocketcon->sendmb);
	}
	psocketcon->s = INVALID_SOCKET;
	psocketcon->evtcount = 0;
	free(psocketcon);
}

static socket_context_t * _socketcontext_new(SOCKET s)
{
	socket_context_t * psocketcon = malloc(sizeof(socket_context_t));

	memset(psocketcon,0, sizeof(socket_context_t));

	psocketcon->s = s;

	//init hashtable
	HashTableConf htc;

	// Initialize all fields to default values
	hashtable_conf_init(&htc);


	htc.hash        = GENERAL_HASH;
	htc.key_length  = sizeof(int);   //evt is int
	htc.key_compare = hashintkeycmp;

	if(hashtable_new_conf(&htc, &(psocketcon->cbs))!=CC_OK)
	{
		log_e("fail to alloc cbs\n");
		free(psocketcon);
		return NULL;
	}

	/*
	 * send mailbox
	 */
	psocketcon->sendmb = Mailbox_create(sizeof(msg_packet_t),8,NULL,NULL);

	return psocketcon;
}

static int _msg_sendpacket(SOCKET s, msg_packet_t * packet)
{
	assert(_myaddr!=0);

    return send(s, packet,packet->len+MSG_HEADER_SIZE,0);
}

/*返回-1表示错误*/
static int _msg_recvpacket(SOCKET s, msg_packet_t* msg)
{
	assert(_myaddr!=0);

	int ret,recvedlen=0,totallen;
	char * pbuff = (char*) msg;

	ret = recv(s,msg,sizeof(int),0);
	if(ret<0)
	{
		log_i("_msg_recvpacket error on @%x :(%d)\n",s,fdError());
		return ret;
	}
	if(ret==0)
	{
		log_i("_msg_recvpacket @%x closed ",s);
		return ret;
	}

	recvedlen += ret;
	totallen = msg->len + MSG_HEADER_SIZE;

	//接收长度防护
	if(totallen>MSG_PACKET_MAX_SIZE)
	{
		log_e("_msg_recvpacket @%x len=%d >%d",s,totallen,MSG_PACKET_MAX_SIZE);
		return -1;
	}

	while(recvedlen< totallen )
	{
		ret = recv(s,&pbuff[recvedlen],totallen-recvedlen,0 );
		if(ret<0)
		{
			log_i("_msg_recvpacket error @%x :(%d)\n",s,fdError());
			return ret;
		}
		if(ret==0)
		{
			log_i("_msg_recvpacket @%x closed ",s);
			return ret;
		}
		recvedlen+=ret;
	}
	return recvedlen;
}

static void task_client_recv(UINT32 arg0,UINT32 arg1 )
{
    SOCKET  s;
    struct  sockaddr_in SinDst;
    int           ret;
    char IPstr[16];
    msg_client_t *client = (msg_client_t *) arg0;
    msg_packet_t msg;
    cb_msgrecved cb;
    char name[128];
    char ipstr[16];
    HANDLE hsend= NULL;
    int keepalive;
	struct linger so_linger;
	socket_context_t* psocketcon = NULL;
	IPN IPAddr;
	int connect_count = 0;
	int err;
	enum LeaveState leave_state = normal;


    // 为任务分配文件描述符并打开一个会话
    fdOpenSession(TaskSelf());

    msg_id2ip(client->peerid, IPstr);

	// 创建套接字
	s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(s == INVALID_SOCKET)
	{
		log_e("failed socket create (%d)\n", fdError());
		goto leave;
	}

	 //创建socket context
	if(hashtable_get(_sockettable,s,(void*)&psocketcon) != CC_OK)
	{
		psocketcon = _socketcontext_new(s);
		hashtable_add(_sockettable,s, psocketcon);
	}
	else
	{
		// 如果这里的s 在 _sockettable中有
		log_e("impossible: client @%x already in _sockettable", s);
	    if(client->clientconf.on_connectfailed !=NULL)
	    {
	    	client->clientconf.on_connectfailed(s,client->peerid,-99);
	    }
	    return;
	}

	// IP 地址
	mmZeroInit(&SinDst, sizeof(struct sockaddr_in));

	msg_id2ip(client->peerid, ipstr);
    if(!ConStrToIPN(ipstr, &IPAddr))
    	log_e("Invalid address\n\n");

    SinDst.sin_family      = AF_INET;
    SinDst.sin_addr.s_addr = IPAddr;
    SinDst.sin_port        = htons(client->port);

    keepalive = 1;             // 打开keepalive探测
	setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive, sizeof (keepalive) );

	//套接字关闭后保持1s
	so_linger.l_onoff = TRUE;
	so_linger.l_linger = 10;
	setsockopt(s, SOL_SOCKET , SO_LINGER, (void*)&so_linger, sizeof(so_linger)	);


	log_i("client connecting to 0x%x:%d @%x",client->peerid, client->port,s);
	// 建立连接
    while(connect_count < client->clientconf.connect_retrys)
    {
    	log_w("%dth connect",connect_count);
		if(connect(s, (PSA) &SinDst, sizeof(SinDst)) < 0)
		{
			err = fdError();
			log_e("failed connect (%d) @%x\n", err,s);
		}
		else
		{
			break;
		}
    	connect_count++;
    }

    if(connect_count >= client->clientconf.connect_retrys)
    {
    	leave_state = connectfail;
		goto leave;
    }
    else
    {
		log_i("client connected to 0x%x:%d @%x",client->peerid, client->port,s);
		if(client->clientconf.on_connected != NULL)
		{
			client->clientconf.on_connected(s,client->peerid, client->port);
		}
    }


	//创建发送线程
	sprintf(name,"client_send_to:0x%x:%d",client->peerid,client->port);
	hsend = TaskCreate(task_send, name, OS_TASKPRINORM, 0x1000, (UINT32)psocketcon, 0, 0);


	// recv loop
	for(;;)
	{
		ret = _msg_recvpacket(s, &msg);

		if( ret > 0 )
		{
			cb = msg_get_cb(s,msg.type);
			if(cb!=NULL)
			{
				cb(msg_ip2id(ipstr),msg.data,msg.len);
			}
			else
			{
				log_w("client @%x recv :unregistered msg 0x%x from 0x%x|%d\n",s, msg.type,client->peerid,client->port);
			}
		}
		/* If the connection got an error or disconnect, close */
		else
		{
	    	leave_state = disconnect;
	    	goto leave;
		}
	}

leave:

	if(hsend)
	{
		log_i("delete sender task:%x",hsend);
		fdCloseSession(hsend);
		TaskDestroy(hsend);
	}
	if(psocketcon)
	{
		//从全局表中删除并释放内存
		hashtable_remove(_sockettable,s, NULL);
		_socketcontext_free(psocketcon);
	}

	switch(leave_state)
	{
		case disconnect:
			if(client->clientconf.on_disconnected !=NULL)
			{
				client->clientconf.on_disconnected(s,client->peerid);
			}
			log_i("client disconnect from 0x%x:%d  @%x", client->peerid, client->port,s);
			break;

		case connectfail:
			if(client->clientconf.on_connectfailed !=NULL)
			{
				client->clientconf.on_connectfailed(s,client->peerid,err);
			}
			break;
	}

	if(s != INVALID_SOCKET)
	{
		fdClose( s );
		log_i(" =======fdclose  @%x (%d)====", s ,fdError());
	}

	free(client);

	// 关闭文件会话
	fdCloseSession(TaskSelf());


}
/*
 *
 * 退出时不关闭socket ,因为recv线程负责关闭
 * */
static void task_send(UINT32 arg0, UINT32 arg1)
{
	socket_context_t* psocketcon = (socket_context_t*) arg0;
	msg_packet_t packet;
	int ret;
	Mailbox_Handle sendmb = psocketcon->sendmb;
	SOCKET s =psocketcon->s;

	fdOpenSession(TaskSelf());

	for(;;)
	{
		if(!psocketcon->sendmb)
		{
			log_e("psocketcon->sendmb none");
			break;
		}
		Mailbox_pend(psocketcon->sendmb,(Ptr *)&packet, BIOS_WAIT_FOREVER);
		ret = _msg_sendpacket(psocketcon->s, &packet);
		if(ret<0)
		{
			log_i("task_send @%x  error code:%d\n",psocketcon->s, fdError());
			break;
		}

		if(ret == 0)
		{
			log_i("task_send @%x closed error code:%d\n",psocketcon->s, fdError());
		}

	}

    /* This task is killed by the system - here, we block */
    TaskBlock( TaskSelf() );
}

/*
 *  dtask_server线程负责接收数据，再另外开启一个定时发送线程
 */

/* Returns "1" if socket 's' is still open, and "0" if its been closed */
static int dtask_server_recv( SOCKET s, UINT32 arg )
{
    int            i,ret;
    struct sockaddr_in sa;
    int addr_len;
    char name[128];
    msg_server_t * server;
    msg_packet_t msg;
    cb_msgrecved cb;
    char ipstr[16];
    uint16_t peerid;
    HANDLE hsend=NULL;
    int keepalive;
	struct linger so_linger;

	server = (msg_server_t *)arg;

	//检查daemon上的连接数
	//this is a hack, see daemon.c line 52 DREC definitions
	uint32_t maxSpawn = ((uint32_t*)server->hDaemon)[11];
	uint32_t tasksSpawned = ((uint32_t*)server->hDaemon)[13];
	log_d("daemon 0x%x: connections: %d",server->hDaemon, tasksSpawned);
	if( tasksSpawned >= maxSpawn )
	{
		log_e("daemon 0x%x: connections:%d >= max:%d",server->hDaemon, tasksSpawned,maxSpawn);
	}

    //创建socket context
    socket_context_t* psocketcon;
	if(hashtable_get(_sockettable,s,(void*)&psocketcon) != CC_OK)
	{
		psocketcon = _socketcontext_new(s);
		hashtable_add(_sockettable,s, psocketcon);
	}
	else
	{
		log_e("impossible: server @%x already in _sockettable", s);
		goto leave;
	}

    i = 1;
    setsockopt( s, IPPROTO_TCP, TCP_NOPUSH, &i, 4 );

    keepalive = 1;             // 打开keepalive探测
	setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, (void *)&keepalive, sizeof (keepalive) );

	//套接字关闭后保持1s

	so_linger.l_onoff = TRUE;
	so_linger.l_linger = 10;
	setsockopt(s, SOL_SOCKET , SO_LINGER, (void*)&so_linger, sizeof(so_linger)	);




    //创建发送线程
    addr_len = sizeof(sa);
    getpeername(s, (PSA) &sa, &addr_len);
    inet_ntop(sa.sin_family,&(sa.sin_addr),ipstr,16);
    peerid = msg_ip2id(ipstr);
    sprintf(name,"server_send_to:0x%x:%d",peerid,ntohs(sa.sin_port));

    hsend=TaskCreate(task_send, name, OS_TASKPRINORM, 0x1000, (UINT32) psocketcon, 0, 0);

    //回调
    if(server->serverconf.on_newclient !=NULL)
    {
    	server->serverconf.on_newclient(s,peerid);
    }
	log_i("server accept connection from:0x%x:%d  @%x",peerid, server->port, s);

    for(;;)
    {
    	ret = _msg_recvpacket(s, &msg);

        if( ret > 0 )
        {
        	cb = msg_get_cb(s,msg.type);
        	if(cb!=NULL)
        	{
        		cb(peerid,msg.data,msg.len);
        	}
        	else
        	{
        		log_w("server @%x recv :unregistered msg 0x%x from 0x%x|%d\n",s, msg.type,peerid, server->port);
        	}
        }
        /* If the connection got an error or disconnect, close */
        else
        {
		    break;
        }

    }

leave:

	if(hsend)
	{
		log_d("delete sender task:%x",hsend);
		fdCloseSession(hsend);
		TaskDestroy(hsend);
	}

	if(psocketcon)
	{
		//从全局表中删除并释放内存
		hashtable_remove(_sockettable,s, NULL);
		_socketcontext_free(psocketcon);
	}

	if(server->serverconf.on_delclient !=NULL)
	{
		server->serverconf.on_delclient(s,peerid);
	}
	log_i("server close connection from:0x%x on port:%d  @%x",peerid, server->port, s);

	if(s != INVALID_SOCKET)
	{
		fdClose( s );
	    log_i(" =======fdclose  @%x (%d)====", s ,fdError());
	}

    /* Return "0" since we closed the socket */
    return(0);
}


//API

int msg_listen(uint16_t port, int maxclients, msg_server_conf_t* pserverconf )
{
	_CHECK_INIT;
	msg_server_t *server = malloc(sizeof(msg_server_t)) ;
	memset(server,0, sizeof(msg_server_t));

	server->port = port;
	memcpy(&server->serverconf , pserverconf, sizeof(msg_server_conf_t));

	list_add_(_serverlist, server);

	log_i("server listening on port:%d",port);
	HANDLE d = DaemonNew(SOCK_STREAM, 0, port, dtask_server_recv, OS_TASKPRINORM, OS_TASKSTKHIGH, (UINT32)server, maxclients);
	server->hDaemon = d;
	if(d)
	{
		array_add(_daemonarray,d);
		return MSG_OK;
	}
	else
	{
		return MSG_ERROR_ALLOC;
	}
}

void msg_stoplisten(uint16_t port)
{
	//TODO: list_remove_()  from _serverlist
	//TODO: stop _daemon
}

int msg_dial(uint16_t peerid, uint16_t port, msg_client_conf_t* pclientconf)
{
	_CHECK_INIT;

	msg_client_t *client = malloc(sizeof(msg_client_t));
	memset(client,0, sizeof(msg_client_t));

	//不设置connect_retrys ,使用默认值1
	if(0==pclientconf->connect_retrys)
	{
		pclientconf->connect_retrys = 1;
	}
	memcpy(&client->clientconf , pclientconf, sizeof(msg_client_conf_t));
	client->peerid = peerid;
	client->port = port;

    TaskCreate(task_client_recv, "client_recv" , OS_TASKPRINORM, 0x1000, (UINT32)client, 0, 0);

	return MSG_OK;
}


/* ARGSUSED */
static void ShutdownTask( UINT32 arg )
{
	SOCKET s = (SOCKET) arg;
	int err;
    fdOpenSession( TaskSelf() );

    fdClose( s);

    err = fdError();
    log_i(" =======fdclose  @%x (%d)====", s ,err);

    fdCloseSession( TaskSelf() );
    TaskExit();
}

/*
 * 关闭一个msg通道 ,异步
 */
int msg_close(SOCKET s)
{
	_CHECK_INIT;
	socket_context_t * psocketcon;

	if(hashtable_get(_sockettable,s, (void*)&psocketcon) != CC_OK)
	{
		log_e("msg_close:@%x not in _sockettable",s);
		return 	MSG_ERROR_SOCKET_CLOSED;
	}

	TaskCreate( ShutdownTask, "ShutdownTask", OS_TASKPRINORM, 0x1000, (UINT32)s,0, 0 );

	return MSG_OK;
}
/*
 * 发送一条消息
 */
int msg_send(SOCKET s, int type, const void *pData, int len)
{
	_CHECK_INIT;
	socket_context_t * psocketcon;
	msg_packet_t packet;
	int ret;

	if(hashtable_get(_sockettable,s,(void*)&psocketcon) != CC_OK)
	{
		//socket not open
		return MSG_ERROR_SOCKET_CLOSED;
	}
	packet.len = len;
	packet.type = type;
	memcpy(packet.data, pData, len);
	ret = Mailbox_post(psocketcon->sendmb, (Ptr) &packet,BIOS_NO_WAIT);
	if(ret==FALSE)
	{
		return MSG_ERROR_ALLOC;
	}
	return MSG_OK;
}



/*
 * 注册接收到消息后的回调函数
 * 回调函数在task 上下文中执行
 */
int msg_register_cb(SOCKET s, int evt, cb_msgrecved cb)
{
	_CHECK_INIT;

	socket_context_t* psocketcon;
	if(hashtable_get(_sockettable,s,(void*)&psocketcon) != CC_OK)
	{
		log_e("register_cb: @%x closed",s);
		return MSG_ERROR_SOCKET_CLOSED;
	}

	if(psocketcon->evtcount >= MSG_MAX_MSG_PER_SOCKET-1)
	{
		return MSG_ERROR_CALLBACK_OVERFLOW;
	}
	psocketcon->evtpool[psocketcon->evtcount] = evt;

	hashtable_add(psocketcon->cbs,&psocketcon->evtpool[psocketcon->evtcount],cb);
	psocketcon->evtcount++;

	return MSG_OK;
}

cb_msgrecved msg_get_cb(SOCKET s, int evt)
{
	if(!_inited) return NULL;

	socket_context_t* psocketcon;
	if(hashtable_get(_sockettable,s,(void*)&psocketcon) == CC_OK)
	{
		if(psocketcon->cbs)
		{
			cb_msgrecved cb;
			if(hashtable_get(psocketcon->cbs,  &evt,(void*) &cb) == CC_OK)
			{
				return cb;
			}
			else
			{
				log_w(" @%x :unregistered msg type 0x%x\n",s, evt);
				return NULL;
			}
		}
		else
		{
			log_e("@%x cbs none",s);
			return NULL;
		}
	}
	else
	{
		log_w("@%x is not in _sockettable",s);
		return NULL;
	}
}


int msg_init(uint16_t myAddr)
{
	int ret;

	_myaddr = myAddr;

	if(_inited)
	{
		return MSG_ERROR_REINIT;
	}

	_inited = 1;

	if(list_new(&_serverlist)!=CC_OK)
	{
		ret= MSG_ERROR_ALLOC;
		goto fail;
	}
	/*
	if(list_new(&_clientlist)!=CC_OK)
	{
		return MSG_FAIL;
	}
	*/


	//_sockettable
	HashTableConf htc;

	hashtable_conf_init(&htc);

	htc.hash        = POINTER_HASH;
	htc.key_length  = sizeof(SOCKET);
	htc.key_compare = hashpointerkeycmp;

	if(hashtable_new_conf(&htc, &_sockettable) != CC_OK)
	{
		ret= MSG_ERROR_ALLOC;
		goto fail;
	}

	if(array_new(&_daemonarray)!= CC_OK)
	{
		ret = MSG_ERROR_ALLOC;
		goto fail;
	}

	log_i("\n\n=====msg_init======\n\n");

	return MSG_OK;

fail:
	msg_teardown();

	return ret;
}

/*
 * 关闭msg模块,释放内存
 */
int msg_teardown()
{
	_CHECK_INIT;

	log_i("\n<<<<<<<msg_teardown start<<<<<<<\n");

	if(_sockettable)
	{
		/*不能在foreach中修改容器自身（msg_close就会修改_sockettable）
		hashtable_foreach_key(_sockettable,msg_close); */
		Array * socketarray = NULL;
		hashtable_get_keys(_sockettable, &socketarray);
		if(socketarray)
		{
			ARRAY_FOREACH(s,socketarray,{
							log_i("clean socket %x",s);
							msg_close(s);
						})
			array_destroy(socketarray);
		}

		hashtable_destroy(_sockettable);
		_sockettable = 0;
	}
	if(_daemonarray)
	{
		ARRAY_FOREACH(val,_daemonarray,
				{
						log_i("free daemon %x",val);
						DaemonFree(val);
				})
		array_destroy(_daemonarray);
		_daemonarray = 0;
	}

	if(_serverlist)
	{
		LIST_FOREACH(val, _serverlist,
				{
					free(val);
				})
		list_destroy(_serverlist);
		_serverlist = 0;
	}

	_inited = 0;
	_myaddr = 0;

	log_i("\n<<<<<<<msg_teardown end<<<<<<<\n");

	return MSG_OK;
}
void msg_id2ip(uint16_t id, char * ipstr)
{
	sprintf(ipstr,MSG_SUB_NET".%d", *(uint8_t*) &id);
}

static char _ipstr[16];
uint16_t msg_ip2id(const char* ip)
{
	memcpy(_ipstr, ip, sizeof(_ipstr));
	char *token = strtok(_ipstr,".");
	char *last;
	uint16_t id;
	uint16_t iptail;

	id = 0x6000;
	while (token != NULL)
	{
		last = token;
		token = strtok(NULL, ".");
	}
	iptail = atoi(last);
	return id|iptail;
}


void msg_serverconf_init(msg_server_conf_t * pconf)
{
	memset(pconf,0 ,sizeof(msg_server_conf_t));
}
void msg_clientconf_init(msg_client_conf_t * pconf)
{
	memset(pconf,0 ,sizeof(msg_client_conf_t));
}



