#include "SimpleWebSocket.h"
#include <assert.h>
#include <openssl/bio.h>
#include <openssl/sha.h>
#include <openssl/rand.h>


static const char* ws_magic_str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

static sws_base64_enc_func sws_custom_base64_func = NULL;

static const char* handshake_request_fmt_str = 
"GET %s HTTP/1.1\r\n"
"Host: %s\r\n"
"Upgrade: websocket\r\n"
"Connection: Upgrade\r\n"
"Sec-WebSocket-Key: %s\r\n"
"Sec-WebSocket-Version: %d\r\n"
"%s"
"\r\n";

#define WS_MAX_HEADER_LEN 10


struct SimpleWebSocketFrame{
    uint8_t FIN;
    uint8_t opcode;
    uint8_t MASK;
    uint64_t payload_len;
    uint64_t rw_loc;
    uint32_t header_len;
    uint8_t header[WS_MAX_HEADER_LEN];
    uint8_t mask_key[4];
    SimpleWebSocketFrameStage stage;
    void *payload;
    int need_free_payload;
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

#ifdef SWS_CUSTOM_BASE64
#else
static void sws_bytes_to_base64(char** str, const void *bytes, int len)
{
    BIO *bmem, *b64;
    BUF_MEM *bbuf;
    b64 = BIO_new(BIO_f_base64());
    bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(b64, bytes, len);
    BIO_flush(b64);
    BIO_get_mem_ptr(b64, &bbuf);
    *str = malloc(bbuf->length+1);
    (*str)[bbuf->length] = 0;
    memcpy((*str), bbuf->data, bbuf->length);
    BIO_set_close(b64, BIO_NOCLOSE);
    BIO_free_all(b64);
    return;
}
#endif

static void sws_generate_sec_ws_key(char** key)
{
    unsigned char buf[16];
    RAND_bytes(buf, 16);
    #ifdef SWS_CUSTOM_BASE64
        sws_custom_base64_func(key, buf, 16);
    #else
        sws_bytes_to_base64(key,buf, 16);
    #endif
    return;
}

static void sws_cal_sha1_then_base64(char** dst, char* src)
{
    unsigned char tmp[SHA_DIGEST_LENGTH] = {0};
    SHA_CTX ctx;
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, src, strlen(src));
    SHA1_Update(&ctx, ws_magic_str, strlen(ws_magic_str));
    SHA1_Final(tmp,&ctx);
     #ifdef SWS_CUSTOM_BASE64
        sws_custom_base64_func(dst, src, 16);
    #else
        sws_bytes_to_base64(dst, src, 16);
    #endif
    
    return;
}

static int sws_get_http_header_key_val(char** key, char** val, char* line)
{
    char *tkey = NULL;
    char *tval = NULL;
    int key_len = 0;
    int val_len = 0;
    int parse_key = 1;
    int len = strlen(line);
    for(int i = 0; i < len; i++){
        char c = line[i];
        if(c == ':'){
            parse_key = 0;
            continue;
        }
        if(c == '\r' && i < len-1 && line[i+1] == '\n'){
            break;
        }
        if(parse_key)
        {
            if(tkey == NULL)
            {
                tkey = line+i;
            }
            key_len++;
        }else{
            if(tval == NULL && c != ' '){
                tval = line+i;
            }
            val_len++;
        }
    }
    if(key_len <= 0 || val_len <= 0){
        return -1;
    }
    *key = malloc(key_len+1);
    *val = malloc(val_len+1);
    (*key)[key_len] = 0;
    (*val)[val_len] = 0;
    memcpy(*key, tkey, key_len);
    memcpy(*val, tval, val_len);
    return 0;
}

static void sws_client_get_handshake_response(SimpleWebSocket *sws)
{
    int lrlnlrln_status = 0;
    int header_len = 0;
    int header_buf_max = 1400;
    char *header = malloc(header_buf_max);
    char *line = NULL;
    while (lrlnlrln_status < 4)
    {
        int ret = sws->io.recv(sws, header+header_len, 1, 0);
        if(ret < 0){
            printf("read header error\n");
            break;
        }
        if(line == NULL){
            line = header + header_len;
        }
        switch (lrlnlrln_status)
        {
        case 0:
            if(header[header_len] == '\r'){
                lrlnlrln_status++;
            }else{
                lrlnlrln_status = 0;
            }
            break;
        case 1:
            if(header[header_len] == '\n'){
                lrlnlrln_status++;
                header[header_len] = 0;
                char* key = NULL;
                char* val = NULL;
                int ret = sws_get_http_header_key_val(&key,&val, line);
                if(ret >= 0)
                {
                    printf("%s:%s\n",key, val);
                    if(!strcmp(key, "Sec-WebSocket-Accept"))
                    {
                        sws->remote_sec_ws_accept = val;
                        free(key);
                    }else{
                        free(key);
                        free(val);
                    }
                }
                header[header_len] = '\n';
                line = NULL;
            }else{
                lrlnlrln_status = 0;
            }
            break;
        case 2:
            if(header[header_len] == '\r'){
                lrlnlrln_status++;
            }else{
                lrlnlrln_status = 0;
            }
            break;
        case 3:
            if(header[header_len] == '\n'){
                lrlnlrln_status++;
            }else{
                lrlnlrln_status = 0;
            }
            break;
        
        default:
            break;
        }
    
        header_len ++;
        if(header_len == header_buf_max){
            header = realloc(header, header_buf_max + header_len);
            header_buf_max += header_len;
        }
    }
    header[header_len] = 0;
    printf("\nresponse header:%s\n",header);
    
}

static int sws_client_do_handshake(SimpleWebSocket *sws)
{
    assert(sws != NULL);
    assert(sws->sec_ws_key != NULL);
    int cal_str_len = strlen(sws->sec_ws_key) + strlen(ws_magic_str);
    char* buf = malloc(cal_str_len+1);
    buf[cal_str_len] = 0;
    memcpy(buf, sws->sec_ws_key, strlen(sws->sec_ws_key));
    memcpy(buf+strlen(sws->sec_ws_key),ws_magic_str, strlen(ws_magic_str));
    sws_cal_sha1_then_base64(&sws->sec_ws_accept, sws->sec_ws_key);
    free(buf);
    sws_client_get_handshake_response(sws);
    if(sws->remote_sec_ws_accept == NULL){
        printf("can not find Sec-WebSocket-Accept\n");
        return -1;
    }
    if(strcmp(sws->remote_sec_ws_accept, sws->sec_ws_accept) != 0){
        return 0;
    }else{
        printf("handshake error bad Sec-WebSocket-Accept response\n");
    }

    return -1;
}

#pragma endregion handshake

#pragma region transport

SimpleWebSocketFrame* sws_frame_alloc(void)
{
    SimpleWebSocketFrame *frame = malloc(sizeof(*frame));
    if(frame == NULL){
        return NULL;
    }
    memset(frame, 0, sizeof(*frame));
    //basic header len
    frame->header_len = 2;
    return frame;
}

void sws_frame_free(SimpleWebSocketFrame *f)
{
    if(!f){
        return;
    }
    if(f->payload && f->need_free_payload == 1){
        free(f->payload);
    }
    free(f);
}

static int sws_recv_frame_basic_header(SimpleWebSocket* sws, 
                                        SimpleWebSocketFrame *frame)
{
    int want = frame->header_len - frame->rw_loc;
    int ret = sws->io.recv(sws, frame->header + frame->rw_loc, want, 0);
    if(ret <= 0){
        return ret;
    }
    frame->rw_loc += ret;
    return ret;
}

static int sws_recv_frame_mask(SimpleWebSocket* sws, 
                                        SimpleWebSocketFrame *frame)
{
    int want = 4 - frame->rw_loc;
    int ret = sws->io.recv(sws, frame->mask_key + frame->rw_loc, want, 0);
    if(ret <= 0){
        return ret;
    }
    frame->rw_loc += ret;
    return ret;
}

static int sws_recv_frame_payload(SimpleWebSocket *sws,
                                        SimpleWebSocketFrame *frame)
{
    if(frame->payload == NULL)
    {
        frame->payload = malloc(frame->payload_len);
        frame->need_free_payload = 1;
    }

    int want = frame->payload_len - frame->rw_loc;
    int ret = sws->io.recv(sws, frame->payload + frame->rw_loc, want, 0);
    if(ret <= 0){
        return ret;
    }
    frame->rw_loc += ret;
    return ret;
}

static void sws_recv_parse_payload(SimpleWebSocket* sws, 
                                        SimpleWebSocketFrame *frame)
{
    if(1 != frame->MASK){
        return;
    }
    for (uint64_t i = 0; i < frame->payload_len; i++)
    {
        int j = i % 4;
        ((uint8_t*)(frame->payload))[i] = 
                    ((uint8_t*)frame->payload)[i] ^ frame->mask_key[j];
    }
}

static int sws_get_piple_line(SimpleWebSocket *sws)
{
    int ret;
    assert(sws != NULL);
    assert(sws->r_frame != NULL);
    SimpleWebSocketFrame *frame = sws->r_frame;
    while (1)
    {
        switch (frame->stage)
        {
        case SWS_FRAME_STAGE_RECV_HEADER:
        {
            ret = sws_recv_frame_basic_header(sws, frame);
            if(ret <= 0){
                return ret;
            }
            if(frame->rw_loc < 2){
                return ret;
            }
            frame->rw_loc = 0;
            frame->stage++;
        }
            break;
        case SWS_FRAME_STAGE_PARSE_HEADER:
        {
            frame->FIN = (frame->header[0] >> 7) & 0x1;
            frame->opcode = frame->header[0] & 0xf;
            frame->MASK = (frame->header[1] >> 7) & 0x1;
            frame->payload_len = (frame->header[1])&0x7f;
            if(frame->MASK == 1){
                frame->header_len += 4;
            }
            if(frame->payload_len == 126){
                frame->header_len += 2;
                //reset rw_loc we want more data in header
                frame->rw_loc = 2;
            }else if(frame->payload_len == 127){
                frame->header_len += 8;
                //reset rw_loc we want more data in header
                frame->rw_loc = 2;
            }
            frame->stage++;
        }
            break;
        case SWS_FRAME_STAGE_RECV_EXTRA_LEN:
        { 
            if(frame->payload_len == 126 || frame->payload_len == 127){
                ret = sws_recv_frame_basic_header(sws, frame);
                if(ret <= 0){
                    return ret;
                }
                if(frame->rw_loc < frame->header_len){
                    return ret;
                }
            }
            frame->rw_loc = 0;
            frame->stage++;
        }
            break;
        case SWS_FRAME_STAGE_PARSE_EXTRA_LEN:
        {
            int offset = 2;
            uint64_t len = 0;
            if(frame->payload_len == 126){
                len = ((int)(frame->header[offset++]) << 8);
                len += frame->header[offset++];
                frame->payload_len = len;
            }else if(frame->payload_len == 127){
                len = ((uint64_t)(frame->header[offset++]) << 56);
                len += ((uint64_t)(frame->header[offset++]) << 48);
                len += ((uint64_t)(frame->header[offset++]) << 40);
                len += ((uint64_t)(frame->header[offset++]) << 32);
                len += ((uint64_t)(frame->header[offset++]) << 24);
                len += ((uint64_t)(frame->header[offset++]) << 16);
                len += ((uint64_t)(frame->header[offset++]) << 8);
                len += ((uint64_t)(frame->header[offset++]));
                frame->payload_len = len;
            }
            frame->rw_loc = 0;
            frame->stage++;
        }
            break;
        case SWS_FRAME_STAGE_RECV_MASK:
        {
            if(frame->MASK){
                ret = sws_recv_frame_mask(sws, frame);
                if(ret <= 0){
                    return ret;
                }
                if(frame->rw_loc < 4){
                    return ret;
                }
            }
            frame->rw_loc = 0;
            frame->stage++;
        }
            break;
        case SWS_FRAME_STAGE_PARSE_MASK:
            frame->stage++;
            break;
        case SWS_FRAME_STAGE_RECV_PAYLOAD:
        {
            ret = sws_recv_frame_payload(sws, frame);
            if(ret <= 0){
                return ret;
            }
            if(frame->rw_loc < frame->payload_len){
                return ret;
            }
            frame->rw_loc = 0;
            frame->stage++;
        }
            break;
        case SWS_FRAME_STAGE_PARSE_PAYLOAD:
        {
            sws_recv_parse_payload(sws, frame);
            sws->io.message(sws, frame->payload, frame->payload_len, frame->opcode);
            frame->rw_loc = 0;
            frame->stage++;
            break;
        }

        case SWS_FRAME_STAGE_SEND_HEADER:
            frame->stage++;
            break;
        case SWS_FRAME_STAGE_SEND_MASK:
            frame->stage++;
            break;
        case SWS_FRAME_STAGE_SEND_PAYLOAD:
            frame->stage++;
            break;
        case SWS_FRAME_STAGE_DONE:
            frame->stage++;
            uint64_t ret = frame->payload_len;
            sws_frame_free(frame);
            sws->r_frame = NULL;
            return ret;
        default:
            frame->stage++;
            return -1;
        }
    }
}

static int sws_send_frame_header(SimpleWebSocket *sws, 
                                SimpleWebSocketFrame *frame)
{
    int want = frame->header_len - frame->rw_loc;
    int ret = sws->io.send(sws, frame->header + frame->rw_loc, want, 0);
    if(ret <= 0){
        return ret;
    }
    frame->rw_loc += ret;
    return ret;
}

static int sws_send_frame_mask(SimpleWebSocket *sws, 
                                SimpleWebSocketFrame* frame)
{
    int want =  4 - frame->rw_loc;
    int ret = sws->io.send(sws, frame->mask_key + frame->rw_loc, want, 0);
    if(ret <= 0){
        return ret;
    }
    frame->rw_loc += ret;
    return ret;
}

static int sws_send_frame_payload(SimpleWebSocket *sws,
                                    SimpleWebSocketFrame *frame)
{
    int want = frame->payload_len - frame->rw_loc;
    int ret = sws->io.send(sws, frame->payload + frame->rw_loc, want, 0);
    if(ret <= 0){
        return ret;
    }
    frame->rw_loc += ret;
    return ret;
}

static int sws_send_piple_line(SimpleWebSocket *sws)
{
    int ret;
    assert(sws != NULL);
    assert(sws->s_frame != NULL);
    SimpleWebSocketFrame *frame = sws->s_frame;
    while (1)
    {
        switch (frame->stage)
        {

        case SWS_FRAME_STAGE_RECV_HEADER:
            frame->stage++;
            break;
        case SWS_FRAME_STAGE_PARSE_HEADER:
        {
            //our lib always send fin frame
            int offset = 0;
            uint8_t fin_opcode = (1 << 7);
            fin_opcode |= frame->opcode & 0xf;
            frame->header[offset++] = fin_opcode;
            uint8_t mask_len = frame->MASK == 1 ? (frame->MASK << 7) : 0;
            if(frame->payload_len < 126){
                mask_len |= frame->payload_len&0x7f;
                frame->header[offset++] = mask_len;
            }else if (frame->payload_len <= 0xffff){
                //mask_len = 126;
                mask_len |= 126&0x7f;
                frame->header[offset++] = mask_len;
                frame->header[offset++] = (frame->payload_len >> 8) & 0xff;
                frame->header[offset++] = (frame->payload_len >> 0) & 0xff;
            }else if (frame->payload_len <= 0xffffffffffffffff ){
                //mask_len = 127;
                mask_len |= 127&0x7f;
                frame->header[offset++] = mask_len;
                frame->header[offset++] = (frame->payload_len >> 56) & 0xff;
                frame->header[offset++] = (frame->payload_len >> 48) & 0xff;
                frame->header[offset++] = (frame->payload_len >> 40) & 0xff;
                frame->header[offset++] = (frame->payload_len >> 32) & 0xff;
                frame->header[offset++] = (frame->payload_len >> 24) & 0xff;
                frame->header[offset++] = (frame->payload_len >> 16) & 0xff;
                frame->header[offset++] = (frame->payload_len >> 8) & 0xff;
                frame->header[offset++] = (frame->payload_len >> 0) & 0xff;
            }
            frame->rw_loc = offset;
            frame->header_len = offset;
            frame->stage++;
        }
            break;
        case SWS_FRAME_STAGE_RECV_EXTRA_LEN:
            frame->stage++;
            break;
        case SWS_FRAME_STAGE_PARSE_EXTRA_LEN:
            frame->stage++;
            break;
        case SWS_FRAME_STAGE_RECV_MASK:
            frame->stage++;
            break;
        case SWS_FRAME_STAGE_PARSE_MASK:
        {
            if(frame->MASK == 1){
                RAND_bytes(frame->mask_key,4);
            }
            frame->stage++;
        }
            break;
        case SWS_FRAME_STAGE_RECV_PAYLOAD:
               frame->stage++;
            break;
        case SWS_FRAME_STAGE_PARSE_PAYLOAD:
        {
            if(frame->MASK){
                for (size_t i = 0; i < frame->payload_len; i++)
                {
                    uint8_t key = frame->mask_key[i%4];
                    ((uint8_t*)(frame->payload))[i] =  
                                        ((uint8_t*)frame->payload)[i] ^ key;
                }
            }
            frame->stage++;
            //reset rw_loc
            frame->rw_loc = 0;
        }
            break;
        case SWS_FRAME_STAGE_SEND_HEADER:
        {
            ret = sws_send_frame_header(sws, frame);
            if(ret <= 0){
                return ret;
            }else if(frame->rw_loc < frame->header_len){
                return ret;
            }
            frame->stage++;
            //reset rw_loc
            frame->rw_loc = 0;
        }
            break;
        case SWS_FRAME_STAGE_SEND_MASK:
        {
            if(frame->MASK){
                ret = sws_send_frame_mask(sws, frame);
                if(ret <= 0){
                    return ret;
                }
                if(frame->rw_loc < 4){
                    return ret;
                }
            }
            frame->stage++;
            frame->rw_loc = 0;
        }
            break;
        case SWS_FRAME_STAGE_SEND_PAYLOAD:
        {
            ret = sws_send_frame_payload(sws, frame);
            if(ret <= 0){
                return ret;
            }
            if(frame->rw_loc < frame->payload_len){
                return ret;
            }
            frame->stage++;
            frame->rw_loc = 0;
            break;
        }
        case SWS_FRAME_STAGE_DONE:
            frame->stage++;
            uint64_t len = frame->payload_len;
            sws_frame_free(frame);
            sws->s_frame = NULL;
        return len;
        default:
            frame->stage++;
            break;
        }
    }
}

static int sws_get_frame(SimpleWebSocket *sws)
{
    if(sws->r_frame == NULL){
        sws->r_frame = sws_frame_alloc();
        //check again
        if(sws->r_frame == NULL){
            printf("alloc frame error may no mem\n");
            return -1;
        }
    }
    return sws_get_piple_line(sws);
}

static int sws_send_frame(SimpleWebSocket *sws, void *data, int len, 
                                                SimpleWebSocketDataType type)
{
    if(sws->s_frame == NULL){
        sws->s_frame = sws_frame_alloc();
        //check again
        if(sws->s_frame == NULL){
            printf("alloc frame error may no mem\n");
            return -1;
        }
        sws->s_frame->MASK = 1;
    }
    if(sws->s_frame->payload == NULL){
        sws->s_frame->payload = data;
        sws->s_frame->payload_len = len;
        sws->s_frame->opcode = type;
        sws->s_frame->need_free_payload = 0;
    }
    return sws_send_piple_line(sws);
}
#pragma endregion transport

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

    if(sws->io.message == NULL){
        sws->io.message = sws_client_dummy_io_msg_call;
    }
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
        sws->use_ssl = 1;
        SSL_library_init();
        SSLeay_add_ssl_algorithms();
        SSL_load_error_strings();
        const SSL_METHOD *method = TLS_client_method();
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
            err = SSL_get_error(sws->ssl, err);
            if(err == SSL_ERROR_SSL){
                printf("sslerror1: %s\n",ERR_error_string(ERR_get_error(), NULL));
            }
            printf("sslerror2:%s\n",SSL_state_string(sws->ssl));
           
            fflush(stdout);
            goto fail;
        }
    }

	return sws->fd;

fail:
    sws_socket_close(sws->fd);
    sws->fd = SWS_INVALID_SOCKET;
    return SWS_INVALID_SOCKET;
}

int simple_websocket_recv(SimpleWebSocket *sws)
{
    assert(sws != NULL);

    if(sws->state == SWS_STATE_TRANSPORTING){
        return sws_get_frame(sws);
    }else{
        printf("sws recv error, in stage : %d\n",sws->state);
        return -1;
    }
}

int simple_websocket_send(SimpleWebSocket *sws, void *data, int len,
                                                SimpleWebSocketDataType type)
{
    assert(sws != NULL);
    if(sws->state != SWS_STATE_TRANSPORTING){
        printf("bad stage in send function\n");
        return -1;
    }
    return sws_send_frame(sws, data, len, type);
}

int simple_websocket_request_handshake(SimpleWebSocket *sws ,
    const char* path, const char* extra_header, const char* host, 
    int ws_version)
{
    assert(sws != NULL);
    sws->state = SWS_STATE_HANDSHAKE;
    //sws_client_do_handshake(sws);
    sws_generate_sec_ws_key(&sws->sec_ws_key);
    //make sure enought space to format data
    int msg_total_len = strlen(handshake_request_fmt_str) + strlen(path) 
    + strlen(host) + strlen(extra_header) + 100;
    char *data = malloc(msg_total_len);
    memset(data, 0, msg_total_len);
    int ret = sprintf(data, handshake_request_fmt_str, path, host, 
                        sws->sec_ws_key,ws_version,extra_header);
    return sws->io.send(sws, data, ret, 0);
}

int simple_websocket_get_handshake_response(SimpleWebSocket *sws)
{
    int ret = 0;
    assert(sws != NULL);
    if(sws->state == SWS_STATE_HANDSHAKE)
    {
        if(sws->type == SWS_TYPE_CLIENT){
            ret = sws_client_do_handshake(sws);
            sws->state = SWS_STATE_TRANSPORTING;
        }else{
            printf("need upgrade first\n");
            return -1;
        }
       if(ret < 0){
           printf("sws handshake error\n");
            sws->state = SWS_STATE_CLOSE;
           return ret;
       }
       return 0;
    }
    return -1;
}

void simple_websocket_destroy(SimpleWebSocket *sws)
{
    assert(sws != NULL);
    if(sws->r_frame){
        sws_frame_free(sws->r_frame);
    }
    if(sws->s_frame){
        sws_frame_free(sws->s_frame);
    }
    if(sws->sec_ws_accept){
        free(sws->sec_ws_accept);
    }
    if(sws->sec_ws_key){
        free(sws->sec_ws_key);
    }
    if(sws->remote_sec_ws_accept){
        free(sws->remote_sec_ws_accept);
    }
    if(sws->use_ssl == 1){
        if(sws->ssl){
            SSL_clear(sws->ssl);
            SSL_free(sws->ssl);
        }
        if(sws->ssl_ctx){
            SSL_CTX_free(sws->ssl_ctx);
        }
    }
    free(sws);
}

void simple_websocket_set_custom_base64_func(sws_base64_enc_func func)
{
    sws_custom_base64_func = func;
}