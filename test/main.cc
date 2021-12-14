#include "rtc_base/strings/json.h"
#include <stdio.h>
extern "C"{
	#include "../SimpleWebSocket.h"
}

static int stop = 0;

static int count = 0;
static void sws_client_dummy_io_msg_call(SimpleWebSocket *sws,
                        void *data, size_t len, int type)
{
    printf("recv mssage %s\n", (char*)data);
	count ++;
}



int main(){
	SimpleWebSocket *sws = simple_websocket_create(SWS_TYPE_CLIENT);
	sws->io.message = sws_client_dummy_io_msg_call;
	sws_socket fd = simple_websocket_connect(sws, "rtc.studease.cn", 443, 1 );
	if(fd == SWS_INVALID_SOCKET){
		printf("connect error\n");
	}

	int ret = simple_websocket_request_handshake(sws, "/rtc/sig", 
							"", "rtc.studease.cn", 13);
	
	if(ret < 0){
		printf("send handshake request error\n");
	}


    Json::StyledWriter writer;
    Json::Value jmessage;
    jmessage["type"] = "connect";
    jmessage["chan"] = 0;
    jmessage["sn"] = 0;
    Json::Value data;
    data["token"] = "";
    jmessage["data"] = data;
    auto connect = writer.write(jmessage);
	printf("send data: %s\n",connect.c_str());
	ret = simple_websocket_get_handshake_response(sws);
		
	ret = simple_websocket_send(sws, (void*)connect.c_str(), connect.length(), SWS_DATA_TYPE_TEXT_FRAME);
	if(ret < 0){
		stop = 1;
		printf("send message error\n");
	}
	
	while (!stop)
	{
		int ret = simple_websocket_recv(sws);
		if(ret < 0){
			stop = 1;
			printf("recv mssage error\n");
			continue;
		}
	}
	
	simple_websocket_destroy(sws);
	return 0;
}