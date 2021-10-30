#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "pcap_manager.h"

#define PCAP_MAGIC 0xa1b2c3d4
#define PCAP_SUPPORT_LINK_TYPE 1
#define PCAP_IPV4_PACKET 0x800
#define PCAP_NO_SHARD 0x3fff
#define MAX_PORT_LEN 12
#define MAX_IP_LEN 128
#define MAX_PROTO_LEN 12
#define MAX_COMPAR_LEN 12
#define MAX_registed_hook 10

#define SRC_PORT "sport"
#define DST_PORT "dport"
#define SRC_IP "sip"
#define DST_IP "dip"
#define PROTO "proto"


enum read_state {
    PCAP_READ_DATA,
    PCAP_READ_DONE,
    PCAP_SKIP_PACKET,
    PCAP_READ_FILED,
};

enum ReadType {
    POLL,   // 轮询模式
    FORWARD,// 主动读取
};

typedef struct read_context {
    enum ReadType type;
    enum read_state state;
    pcap_data_t* pdata;
    pcap_handle_t* handle;
    pcap_cb cb;
}read_context_t;

enum filter_type {
    FILTER_SRC_PORT,
    FILTER_DST_PORT,
    FILTER_SRC_IP,
    FILTER_DST_IP,
    FILTER_PROTO,
};

typedef struct registed_hook{
    char name[MAX_COMPAR_LEN];
    compar comp;
} registed_hook_t;

static registed_hook_t registed_hooks[MAX_registed_hook];

static int  __pcap_read_done(read_context_t* ctx);
static void __pcap_read_data(read_context_t* ctx);
static int  __read_packet(read_context_t* ctx);


pcap_handle_t*  pcap_open(const char* file_path, const char* fst_str) {
    pcap_info_st info;
    FILE* fd = fopen(file_path, "rb");
    filter_st* st = NULL;
    // fprintf(stderr, "file info: %s\n", file_path);
	if (fread(&info, sizeof(info), 1, fd) != 1) {
		goto fail;
	}
	
	if (info.magic != PCAP_MAGIC) {
		goto fail;
	}
	
	if (info.linktype != PCAP_SUPPORT_LINK_TYPE) {
		goto fail;
	}

    if (fst_str != NULL) {
        st = filter_init(fst_str);
        if (st == NULL) {
            goto fail;
        }
    }

    for (int i = 0; i < MAX_registed_hook; i++) {
        memset(registed_hooks[i].name, 0, MAX_COMPAR_LEN);
        registed_hooks[i].comp = NULL;
    }
    pcap_handle_t* handle = (pcap_handle_t*)malloc(sizeof(pcap_handle_t));
    handle->pcap_header = info;
    handle->pcap_fd = fd;
    handle->fst = st;
	return handle;

fail:
    fprintf(stderr, "pcap init failed\n");
	fclose(fd); 
	return NULL;
}

void pcap_destory_handle(pcap_handle_t* handle) {
    free(handle);
}

static int __read_packet(read_context_t* ctx) {
    if (ctx->handle->pcap_fd == 0) {
        return -1;
    }

    while (1) {
        // fprintf(stderr, "read packet, state: %d\n", ctx->state);
        switch(ctx->state) {
        case PCAP_READ_DATA:
            __pcap_read_data(ctx);
            break;
        case PCAP_READ_DONE:
            return __pcap_read_done(ctx);
        case PCAP_SKIP_PACKET:
            return 0;
        case PCAP_READ_FILED: 
            return -1;
        }
    }
}

// read_packet
static void __pcap_read_data(read_context_t* ctx) {
    uint32_t len = ctx->handle->pcap_header.snaplen;
    packet_head_st head;
    char data[MAX_PACKET_LEN];
    if (fread(&head, sizeof(head), 1, ctx->handle->pcap_fd) != 1) {
        goto fail;
    }
    if (head.caplen > len || head.caplen > MAX_PACKET_LEN) {
        goto fail;
    }
    
    if (fread(data, 1, head.caplen, ctx->handle->pcap_fd) != head.caplen) {
        goto fail;
    }
	
    char* curr = data;
    l2_head_st *l2hdr = (l2_head_st *)curr;
    curr += sizeof(l2_head_st);
    
    /* 只处理ipv4的包 */
    if (l2hdr->proto != htons(PCAP_IPV4_PACKET)) {
        ctx->state = PCAP_SKIP_PACKET;
        return;
    }
    struct iphdr *iph = (struct iphdr *)curr;
    curr += (iph->ihl * 4);
    
    ctx->pdata->proto = iph->protocol;
    ctx->pdata->saddr = iph->saddr;
    ctx->pdata->daddr = iph->daddr;
    /* 不处理分片包 */
    if (iph->frag_off & htons(PCAP_NO_SHARD)) {
        ctx->state = PCAP_SKIP_PACKET;
        return;
    }
    
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;
    
    if (iph->protocol == IPPROTO_TCP) {
        tcph = (struct tcphdr *)curr;
        curr += (tcph->doff * 4);
        ctx->pdata->source = tcph->source;
        ctx->pdata->dest = tcph->dest;
    } else if (iph->protocol == IPPROTO_UDP) {
        udph = (struct udphdr *)curr;
        curr += (sizeof(struct udphdr));
        ctx->pdata->source = udph->source;
        ctx->pdata->dest = udph->dest;
    } else {
        ctx->state = PCAP_SKIP_PACKET;
        return;
    }
    
    char *udata = curr;
    uint16_t ldata = ntohs(iph->tot_len) - (curr - (char *)iph);
    ctx->state = PCAP_READ_DONE;
    // fprintf(stderr, "read packet data sucess, %d\n", ctx->state);
    return ;
fail:
    // fprintf(stderr, "read packet data failed, %d\n", ctx->state);
    ctx->state = PCAP_READ_FILED;
    return;
}

static enum filter_type __get_filter_type(char* key) {
    if (strcmp(key, SRC_IP) == 0) {
        return FILTER_SRC_IP;
    } else if (strcmp(key, DST_IP) == 0) {
        return FILTER_DST_IP;
    } else if (strcmp(key, SRC_PORT) == 0) {
        return FILTER_SRC_PORT;
    } else if (strcmp(key, DST_PORT) == 0) {
        return FILTER_DST_PORT;
    } else {
        return FILTER_PROTO;
    }
}

// 返回1表示=
static int __equal_value(const char* src, const char* target) {
    int size1 = strlen(src);
    int size2 = strlen(target);   
    if (size1 < size2 - 1) {
        return 0;
    }
    return strncmp(src, target, size2 - 1) == 0;
}

// 返回1表示>
static int __greater_value(const char* src, const char* target) {
    int size1 = strlen(src);
    int size2 = strlen(target);
    if (size1 > size2 - 1) {
        return strncmp(src, target, size2 - 1) > 0;
    } else {
        return strncmp(src, target, size1) > 0;
    }
}

static int __compare_value_with_regex(const char* src, const char* target, filter_st* f) {
    int size1 = strlen(src);
    int size2 = strlen(target);
    assert(size1 >= 1 && size2 >= 1);
    switch (f->type) {
    case FT_EQ:
        return __equal_value(src, target);
    case FT_NE:
        return __equal_value(src, target) == 0;
    case FT_GT:
        return __greater_value(src, target);
    case FT_LT:
        return __greater_value(src, target) == 0 &&
                __equal_value(src, target) == 0;
    case FT_GTE:
        return __greater_value(src, target) || 
                __equal_value(src, target) == 0;
    case FT_LTE:
        return __greater_value(src, target) == 0 ||
                __equal_value(src, target) == 0;
    }
}

static int __compare_value_with_same_length(const char* src, const char* target, filter_st* f) {
    int size1 = strlen(src);
    int size2 = strlen(target);
    assert(size1 >= 1 && size2 >= 1);
    int ret = strcmp(src, target);
    // fprintf(stderr, "src: %s, target: %s, ret: %d\n", src, target, ret);
    switch (f->type) {
    case FT_EQ:
        return ret == 0;
    case FT_NE:
        return ret != 0;
    case FT_GT:
        return ret > 0;
    case FT_LT:
        return ret < 0;
    case FT_GTE:
        return ret >= 0;
    case FT_LTE:
        return ret <= 0;
    }    
}

static int __compare_value_with_diff_length(const char* src, const char* target, filter_st* f) {
    int size1 = strlen(src);
    int size2 = strlen(target);
    assert(size1 >= 1 && size2 >= 1);
    switch (f->type) {
    case FT_EQ:
        return 0;
    case FT_NE:
        return 1;
    case FT_GT:
        return size1 > size2;
    case FT_LT:
        return size1 < size2;
    case FT_GTE:
        return size1 > size2 || strcmp(src, target) >= 0;
    case FT_LTE:
        return size1 < size2 || strcmp(src, target) <= 0;
    } 
}

// 参数： src: pcap 数据 target: 表达式
// 返回值：1 符合表达式 0：不符合表达式
static int __compare_value(const char* src, const char* target, filter_st* f) {
    int size1 = strlen(src);
    int size2 = strlen(target);
    assert(size1 >= 1 && size2 >= 1);
    // case1: 如果带*则另外比较
    if (target[size2 - 1] == '*') {
        return __compare_value_with_regex(src, target, f);
    } else if(size1 == size2) {
        return __compare_value_with_same_length(src, target, f);
    } else { // size1 != size2
        return __compare_value_with_diff_length(src, target, f);    
    }
}

static void __get_port_str(pcap_data_t* pdata, char* data, enum filter_type ft) {
    int port = 0;
    if (ft == FILTER_SRC_PORT) {
        port = ntohs(pdata->source);
        snprintf(data, MAX_PORT_LEN, "%d", port);
    } else {
        port = ntohs(pdata->dest);
        snprintf(data, MAX_PORT_LEN, "%d", port);       
    }
}

static void __get_addr_str(pcap_data_t* pdata, char* data, enum filter_type type) {
    if (type == FILTER_SRC_IP) {
        snprintf(data, MAX_IP_LEN, "%u.%u.%u.%u", NIPQUAD(pdata->saddr));
    } else {
        snprintf(data, MAX_IP_LEN, "%u.%u.%u.%u", NIPQUAD(pdata->daddr));       
    }
}

static void __get_proto_str(pcap_data_t* pdata, char* data) {
    if (pdata->proto == IPPROTO_TCP) {
        snprintf(data, MAX_PROTO_LEN, "%s", "tcp");
    } else if(pdata->proto == IPPROTO_UDP) {
        snprintf(data, MAX_PROTO_LEN, "%s", "udp");
    } else {
        assert(0);
    }
}

static int __check_value(filter_st* f,  pcap_data_t* pdata) {
    char* key = f->s.subject;
    char* value = f->s.value;
    int size = strlen(value);
    char proto_str[MAX_PROTO_LEN];
    char port_str[MAX_PORT_LEN];
    char ip_str[MAX_IP_LEN];
    enum filter_type f_type = __get_filter_type(key);
    switch (f_type) {
    case FILTER_SRC_PORT:
    case FILTER_DST_PORT:
        __get_port_str(pdata, port_str, f_type);
        // fprintf(stderr, "port_str: %s, compare value: %d\n", port_str, __compare_value(port_str, value, f));
        return __compare_value(port_str, value, f);
    case FILTER_SRC_IP:
        __get_addr_str(pdata, ip_str, FILTER_SRC_IP);
        // fprintf(stderr, "src ip: %s  value: %s, value: %d\n", ip_str, value, __compare_value(ip_str, value, f));
        return __compare_value(ip_str, value, f);
    case FILTER_DST_IP:
        __get_addr_str(pdata, ip_str, FILTER_DST_IP);
        return __compare_value(ip_str, value, f);
    case FILTER_PROTO:
        __get_proto_str(pdata, proto_str);
        return __compare_value(proto_str, value, f);
    }
    return 0;
}

static int __check_fst(filter_st* f, int s, pcap_data_t* pdata) {
    // fprintf(stderr, "filter type: %d\n", f->type);
    int ret = 1;
    switch(f->type) {
    case FT_AND:
        ret =  __check_fst(f->m.left, s + 1, pdata) & __check_fst(f->m.right, s + 1, pdata);
        break;
    case FT_OR:
        ret =  __check_fst(f->m.left, s + 1, pdata) | __check_fst(f->m.right, s + 1, pdata); 
        break;
    case FT_NOT:
        ret =  (__check_fst(f->m.left, s + 1, pdata) == 0);
        break;
    case FT_EQ:
    case FT_NE:
    case FT_LT:
    case FT_GT:
    case FT_LTE:
    case FT_GTE:
        ret =  __check_value(f, pdata);
        break;
    }
    // fprintf(stderr, "check value: %d\n", ret);
    return ret;
}

static int __pcap_read_done(read_context_t* ctx) {
    int valid = 1;
    if (ctx->handle->fst) {
        valid = __check_fst(ctx->handle->fst, 0, ctx->pdata);
    }
    if (!valid) {
        return 0;
    }
    if (ctx->type == POLL) {
        ctx->cb(ctx->pdata);   
    }
    return 1;
}

int pcap_process_poll(pcap_handle_t* handle, pcap_data_t* data, pcap_cb cb) {
    while (1) { 
        read_context_t read_ctx;
        read_ctx.pdata = data;
        read_ctx.handle = handle;
        read_ctx.type = POLL;
        read_ctx.state = PCAP_READ_DATA;
        read_ctx.cb = cb;
        int ret = __read_packet(&read_ctx);
        if (ret == -1) {
            break;
        }
    }
}

int pcap_process_forward(pcap_handle_t* handle, pcap_data_t* data) {
    read_context_t read_ctx;
    read_ctx.pdata = data;
    read_ctx.handle = handle;
    read_ctx.type = FORWARD;
    read_ctx.state = PCAP_READ_DATA;
    int ret = __read_packet(&read_ctx);
    if (ret != 1) {
        return 0;
    }
    return 1;
}