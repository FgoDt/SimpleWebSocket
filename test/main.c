#include "../SimpleWebSocket.h"
#include <stdio.h>

static int stop = 0;

static int count = 0;
static void sws_client_dummy_io_msg_call(SimpleWebSocket *sws,
                        void *data, size_t len, int type)
{
    printf("recv mssage %s\n", (char*)data);
	char buf[1024] = {0};
	int ret = sprintf(buf,"hello client send data num: %d\n",count);
	simple_websocket_send(sws, buf, ret, SWS_DATA_TYPE_TEXT_FRAME);
	printf("send func done\n");
	count ++;
}

int main(){
	SimpleWebSocket *sws = simple_websocket_create(SWS_TYPE_CLIENT);
	sws->io.message = sws_client_dummy_io_msg_call;
	int fd = simple_websocket_connect(sws, "localhost", 8080, 0 );

	int ret = simple_websocket_request_handshake(sws, "/hellows", 
							"", "localhost", 13);



	while (!stop)
	{
		int ret = simple_websocket_recv(sws);
		if(ret < 0){
			stop = 1;
			printf("recv mssage error\n");
		}
		printf("retry\n");
		usleep(1000*10);
	}
	

	printf("connect fd:%d ret:%d\n", fd, ret);
	return 0;
}