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
#define INVALID_SOCKET -1
#define SWSEWOULDBLOCK EWOULDBLOCK
#define SWSESHUTDOWN ESHUTDOWN
#define SWSENOTCONN ENOTCONN
#define SWSGetLastError() errno
#define sws_socket_close close
uint64_t sws_linux_time();
#define sws_export 
#endif 



#define SWS_SSL

#ifdef SWS_SSL
    #include <openssl/ssl.h>
    #include <openssl/err.h>
#endif

typedef void(*simple_websocket_frame_call)(struct SimpleWebSocket *sws,unsigned char* data, void *usr_data, int type);

typedef struct SimpleWebSocket{
    int state;
    simple_websocket_frame_call call;
    //client data
    sws_socket fd;
    int use_ssl;
    #ifdef SWS_SSL
        SSL_CTX *ssl_ctx;
        SSL *ssl;
    #endif
}SimpleWebSocket;

SimpleWebSocket* simple_websocket_new();

void simple_websocket_destroy(SimpleWebSocket *sws);

void simple_websocket_close(SimpleWebSocket *sws);

void simple_websocket_recive_remote_data(SimpleWebSocket *sws, unsigned char* data, int len);

void simple_websocket_send_local_data(SimpleWebSocket *sws, unsigned char* data, int len);

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
sws_socket simple_websocket_connect(SimpleWebSocket *sws, const char* host, int port, int ssl);

/**
 * SimpleWebSocket Recv data from remote socket
 * @param sws SimpleWebSocket context
 * @param data recv data
 * @param len recv data can write length
 * @param flags recv function flag
 * @return data recv length
 **/
int simple_websocket_recv(SimpleWebSocket *sws, unsigned char* data, int len, int flags);

/**
 * SimpleWebSocket Send data to remote socket
 * @param sws SimpleWebSocket context
 * @param data send data
 * @param len send data can read length
 * @param flags send fucntion flag
 * @return data send length
 **/
int simple_websocket_send(SimpleWebSocket *sws, unsigned char* data, int len, int flags);

int simple_websocket_send_handshake_request(SimpleWebSocket *sws ,const char* path, 
    const char* extra_header, const char* host, int ws_version, int flags);

int simple_websocket_response_handshake(SimpleWebSocket *sws, const char* web_sec, const char* extra_header, int len);

#endif