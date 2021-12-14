#include "../SimpleWebSocket.h"
#include <stdio.h>

static int stop = 0;

static int count = 0;
static void sws_client_dummy_io_msg_call(SimpleWebSocket *sws,
                        void *data, size_t len, int type)
{
    printf("recv mssage %s\n", (char*)data);
	count ++;
}

static int my_send_function(SimpleWebSocket *sws){
	int ret;
	char buf[1024] = {0};
	ret = sprintf(buf,"hello client send data num: %d\n",count);
	ret = simple_websocket_send(sws, buf, ret, SWS_DATA_TYPE_TEXT_FRAME);
	return ret;
}

int main(){
	SimpleWebSocket *sws = simple_websocket_create(SWS_TYPE_CLIENT);
	sws->io.message = sws_client_dummy_io_msg_call;
	sws_socket fd = simple_websocket_connect(sws, "rtc.studease.cn", 443, 0 );
	if(fd == INVALID_SOCKET){
		printf("connect error\n");
		goto done;
	}

	int ret = simple_websocket_request_handshake(sws, "wss://rtc.studease.cn/rtc/sig", 
							"", "rtc.studease.cn", 13);
	
	if(ret < 0){
		printf("send handshake request error\n");
		goto done;
	}



	while (!stop)
	{
		int ret = simple_websocket_recv(sws);
		if(ret < 0){
			stop = 1;
			printf("recv mssage error\n");
			continue;
		}
		ret = my_send_function(sws);
		if(ret < 0){
			stop = 1;
			printf("send message error\n");
			continue;
		}
	}
	
	done:
	simple_websocket_destroy(sws);
	return 0;
}