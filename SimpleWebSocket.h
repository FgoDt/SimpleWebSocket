#ifndef __SIMPLE_WEBSOCKET_H__
#define __SIMPLE_WEBSOCKET_H__
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <WinSock2.h>
#define sws_socket SOCKET
#define sws_time clock
#define sws_socket_close closesocket
#define sws_export __declspec(dllexport)
#define SWSEWOULDBLOCK WSAEWOULDBLOCK 
#define SWSESHUTDOWN WSAESHUTDOWN
#define SWSENOTCONN WSAENOTCONN
#define SWSGetLastError() WSAGetLastError()
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#define sws_time sws_linux_time
#define sws_socket int
#define SWS_INVALID_SOCKET -1
#define SWSEWOULDBLOCK EWOULDBLOCK
#define SWSESHUTDOWN ESHUTDOWN
#define SWSENOTCONN ENOTCONN
#define SWSGetLastError() errno
#define sws_socket_close close
#define sws_export 
#endif 



#include <openssl/ssl.h>
#include <openssl/err.h>

typedef struct SimpleWebSocket SimpleWebSocket;

typedef struct SimpleWebSocketFrame SimpleWebSocketFrame;

typedef struct SimpleWebSocketIO
{
    int(*recv)(SimpleWebSocket *sws, void *data, size_t len, int flags);
    int(*send)(SimpleWebSocket *sws, void *data, size_t len, int flags);
    void(*message)(SimpleWebSocket *sws,void* data, size_t len, int type);
}SimpleWebSocketIO;

enum SimpleWebSocketDataType{
    SWS_DATA_TYPE_CONTINUATION_FRAME,
    SWS_DATA_TYPE_TEXT_FRAME,
    SWS_DATA_TYPE_BINARY_FRAME,
    SWS_DATA_TYPE_CONNECTION_CLOSE = 0x8,
    SWS_DATA_TYPE_PING,
    SWS_DATA_TYPE_PONG,
};

enum SimpleWebSocketState{
    SWS_STATE_CONNECTING,
    SWS_STATE_HANDSHAKE,
    SWS_STATE_TRANSPORTING,
    SWS_STATE_CLOSE,
};

enum SimpleWebSocketType{
    SWS_TYPE_SERVER,
    SWS_TYPE_CLIENT
};

enum SimpleWebSocketFrameStage{
    SWS_FRAME_STAGE_RECV_HEADER,
    SWS_FRAME_STAGE_PARSE_HEADER,
    SWS_FRAME_STAGE_RECV_EXTRA_LEN,
    SWS_FRAME_STAGE_PARSE_EXTRA_LEN,
    SWS_FRAME_STAGE_RECV_MASK,
    SWS_FRAME_STAGE_PARSE_MASK,
    SWS_FRAME_STAGE_RECV_PAYLOAD,
    SWS_FRAME_STAGE_PARSE_PAYLOAD,
    SWS_FRAME_STAGE_SEND_HEADER,
    SWS_FRAME_STAGE_SEND_MASK,
    SWS_FRAME_STAGE_SEND_PAYLOAD,
    SWS_FRAME_STAGE_DONE,
};

typedef enum SimpleWebSocketFrameStage SimpleWebSocketFrameStage;


typedef enum SimpleWebSocketDataType SimpleWebSocketDataType;

typedef enum SimpleWebSocketState SimpleWebSocketState;

typedef enum SimpleWebSocketType SimpleWebSocketType;




struct SimpleWebSocket{
    void* usr_data;

    char* host;
    int port;

    //header
    char* sec_ws_key;
    char* sec_ws_accept;
    char* remote_sec_ws_accept;

    SimpleWebSocketState state;
    SimpleWebSocketType type;

    //interface
    SimpleWebSocketIO io;

    //frame
    SimpleWebSocketFrame *r_frame;//recv frame
    SimpleWebSocketFrame *s_frame;//send frame

    //client data
    sws_socket fd;
    int use_ssl;
    SSL_CTX *ssl_ctx;
    SSL *ssl;
};

SimpleWebSocket* simple_websocket_create(SimpleWebSocketType type);

void simple_websocket_destroy(SimpleWebSocket *sws);

void simple_websocket_close(SimpleWebSocket *sws);

int simple_websocket_recv(SimpleWebSocket*sws);

int simple_websocket_send(SimpleWebSocket *sws, void *data, int len, 
                                                SimpleWebSocketDataType type);

/**
 * client function
 * SimpleWebSocket open a socket connect
 * SimpleWebSocket just connect to host
 * @param sws SimpleWebSocket context
 * @param host server host name
 * @param port server port
 * @param ssl 1 for use ssl connect
 * @return socket fd error return INVALID_SOCKET
 **/
sws_socket simple_websocket_connect(SimpleWebSocket *sws, const char* host,
                                                            int port, int ssl);

/**
 * client function
 * SimpleWebSocket request handshake message to server
 **/
int simple_websocket_request_handshake(SimpleWebSocket *sws ,const char* path, 
        const char* extra_header, const char* host, int ws_version);

/**
 * server function
 * SimpleWebSocket response handshake message to client
 **/
int simple_websocket_response_handshake(SimpleWebSocket *sws,
                            const char* sec_ws_key, const char* extra_header);

#endif