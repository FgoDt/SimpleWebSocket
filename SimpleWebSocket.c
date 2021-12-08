#include "SimpleWebSocket.h"
#include <assert.h>


static const char* handshake_request_fmt_str = 
"GET %s HTTP/1.1\r\n"
"Host: %s\r\n"
"Upgrade: websocket\r\n"
"Connection: Upgrade\r\n"
"Sec-WebSocket-Key: %s\r\n"
"Sec-WebSocket-Version: %d\r\n";

int simple_websocket_connect(SimpleWebSocket *sws, const char* host, int port, int ssl)
{
    int ret = 0;
    assert(sws!=NULL);
    sws->fd = socket(AF_INET, SOCK_STREAM, 0);
    if(sws->fd < 0){
        printf("sws error on create socket\n");
        return -1;
    }

    struct sockaddr_in servaddr;
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_port = htons(port);

	struct hostent *hostinfo = gethostbyname(host);
	if (hostinfo == NULL || hostinfo->h_length <= 0)
	{
		printf("sws error can not find host for addr: %s\n", host);
		goto fail;
	}

#if _WIN32
	servaddr.sin_addr.S_un.S_addr = *(u_long*)hostinfo->h_addr_list[0];
#else
	servaddr.sin_addr.s_addr = *(u_long*)hostinfo->h_addr_list[0];
#endif

	ret = connect(sws->fd, (struct sockaddr*)&servaddr, sizeof(servaddr));
	if (ret != 0) {
		int err = SWSGetLastError();
		printf("connect server: %s error\n", host);
		goto fail;
	}

    #ifdef SWS_SSL
    if(ssl == 1){
        SSL_library_init();
        SSLeay_add_ssl_algorithms();
        SSL_load_error_strings();
        const SSL_METHOD *method = TLSv1_2_client_method();
        sws->ssl_ctx = SSL_CTX_new(method);
        sws->ssl = SSL_new(sws->ssl_ctx);
        if(!sws->ssl){
            printf("sws error ssl new \n");
            log_ssl();
            fflush(stdout);
            goto fail;
        }
        SSL_set_fd(sws->ssl, sws->fd);
        int err = SSL_connect(ssl);
        if(err <= 0){
            printf("sws error ssl connect\n");
            log_ssl();
            fflush(stdout);
            goto fail;
        }
    }
    #endif

	return sws->fd;

fail:
    sws_socket_close(sws->fd);
    sws->fd = INVALID_SOCKET;
    return INVALID_SOCKET;
}

int simple_websocket_recv(SimpleWebSocket *sws, unsigned char* data, int len, int flags)
{
    assert(sws == NULL);
    assert(data == NULL);
}

int simple_websocket_send_handshake_request(SimpleWebSocket *sws ,const char* path, 
    const char* extra_header, const char* host, int ws_version, int flags)
{
    assert(sws == NULL);

}