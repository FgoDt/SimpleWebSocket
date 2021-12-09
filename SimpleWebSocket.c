#include "SimpleWebSocket.h"
#include <assert.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/rand.h>


static const char* ws_magic_str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

static const char* handshake_request_fmt_str = 
"GET %s HTTP/1.1\r\n"
"Host: %s\r\n"
"Upgrade: websocket\r\n"
"Connection: Upgrade\r\n"
"Sec-WebSocket-Key: %s\r\n"
"Sec-WebSocket-Version: %d\r\n"
"%s"
"\r\n";

typedef struct SimpleWebSocketFrame SimpleWebSocketFrame;

struct SimpleWebSocketFrame{
    uint8_t FIN;
    uint8_t opcode;
    uint8_t MASK;
    uint64_t payload_len;
    uint8_t mask_key[4];
    void *payload;
};

#pragma region dummy io
static int sws_client_dummy_io_recv(SimpleWebSocket *sws,
                        void *data, size_t len, int flags)
{
    int ret = 0;
    if(sws->use_ssl){
        ret = SSL_read(sws->ssl, data, len);
    }else{
        ret = recv(sws->fd, data, len, flags);
    }
    return ret;
}

static int sws_client_dummy_io_send(SimpleWebSocket *sws,
                        void *data, size_t len, int flags)
{
    int ret = 0;
    if(sws->use_ssl){
        ret = SSL_write(sws->ssl,data, len);
    }else{
        ret = send(sws->fd, data, len, flags);
    }
    return ret;
}

static void sws_client_dummy_io_msg_call(SimpleWebSocket *sws,
                        void *data, size_t len, int type)
{
    printf("recv mssage %s\n", (char*)data);
}
#pragma endregion dummy io

#pragma region handshake

static void sws_generate_sec_ws_key(char** key)
{
    BIO *bmem, *b64;
    BUF_MEM *bbuf;
    unsigned char buf[16];
    RAND_bytes(buf, 16);
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, buf, 16);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bbuf);
    *key = malloc(bbuf->length+1);
    (*key)[bbuf->length] = 0;
    memcpy((*key), bbuf->data, bbuf->length);
    BIO_set_close(b64, BIO_NOCLOSE);
    BIO_free_all(b64);
    return;
}

static void sws_cal_sha1_then_base64(char* dst, char* src)
{

}


static int sws_client_do_handshake(SimpleWebSocket *sws)
{
    assert(sws != NULL);
    assert(sws->sec_ws_key != NULL);

    
}

#pragma endregion handshake

SimpleWebSocket* simple_websocket_create(SimpleWebSocketType type)
{
    SimpleWebSocket *sws = malloc(sizeof(*sws));
    memset(sws, 0, sizeof(*sws));
    sws->type = type;
    return sws;
}

int simple_websocket_connect(SimpleWebSocket *sws, 
                            const char* host, 
                            int port, int ssl)
{
    assert(sws!=NULL);
    int ret = 0;

    sws->io.message = sws_client_dummy_io_msg_call;
    sws->io.recv = sws_client_dummy_io_recv;
    sws->io.send = sws_client_dummy_io_send;

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

#ifdef _WIN32
	servaddr.sin_addr.S_un.S_addr = *(u_long*)hostinfo->h_addr_list[0];
#else
	servaddr.sin_addr.s_addr = *(u_long*)hostinfo->h_addr_list[0];
#endif

	ret = connect(sws->fd, (struct sockaddr*)&servaddr, sizeof(servaddr));
	if (ret != 0) {
		int err = SWSGetLastError();
		printf("connect server: %s error code: %d\n", host, err);
		goto fail;
	}

    if(ssl == 1){
        SSL_library_init();
        SSLeay_add_ssl_algorithms();
        SSL_load_error_strings();
        const SSL_METHOD *method = DTLS_client_method();
        sws->ssl_ctx = SSL_CTX_new(method);
        sws->ssl = SSL_new(sws->ssl_ctx);
        if(!sws->ssl){
            printf("sws error ssl new \n");
            //log_ssl();
            fflush(stdout);
            goto fail;
        }
        SSL_set_fd(sws->ssl, sws->fd);
        int err = SSL_connect(sws->ssl);
        if(err <= 0){
            printf("sws error ssl connect\n");
            //log_ssl();
            fflush(stdout);
            goto fail;
        }
    }

	return sws->fd;

fail:
    sws_socket_close(sws->fd);
    sws->fd = INVALID_SOCKET;
    return INVALID_SOCKET;
}

int simple_websocket_recv(SimpleWebSocket *sws)
{
    assert(sws != NULL);
    //return sws->io.recv(sws)
    return -1;
}

int simple_websocket_send(SimpleWebSocket *sws, void *data, int len, int flags)
{
    assert(sws != NULL);
    return sws->io.send(sws, data, len, flags);
}

int simple_websocket_request_handshake(SimpleWebSocket *sws ,
    const char* path, const char* extra_header, const char* host, 
    int ws_version)
{
    assert(sws != NULL);
    //make sure enought space to format data
    int msg_total_len = strlen(handshake_request_fmt_str) + strlen(path) 
    + strlen(host) + strlen(extra_header) + 100;
    char *data = malloc(msg_total_len);
    memset(data, 0, msg_total_len);
    int ret = sprintf(data, handshake_request_fmt_str, path, host, 
                        "abcdef",ws_version,extra_header);
    printf("request:\n%s\n", data);
    simple_websocket_send(sws, (void*)data,ret, 0);
    return -1;
}