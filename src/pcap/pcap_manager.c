#include <string.h>
#include <stdlib.h>
#include <assert.h>

#include "pcap_manager.h"
#include "ldapexpr.h"

#define PCAP_MAGIC 0xa1b2c3d4
#define PCAP_SUPPORT_LINK_TYPE 1
#define PCAP_IPV4_PACKET 0x800
#define PCAP_NO_SHARD 0x3fff
#define MAX_HOOK_NAME_LEN 12
#define MAX_REGISTED_HOOK 10

#define SRC_PORT "sport"
#define DST_PORT "dport"
#define SRC_IP "sip"
#define DST_IP "dip"
#define PROTO "proto"
#define IP "ip"
#define PORT "port"


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

typedef struct registed_hook{
    char hook_name[MAX_HOOK_NAME_LEN];
    hook hook_func;
} registed_hook_t;

registed_hook_t registed_hooks[MAX_REGISTED_HOOK];

static int  __pcap_read_done(read_context_t* ctx);
static void __pcap_read_data(read_context_t* ctx);
static int  __read_packet(read_context_t* ctx);


pcap_handle_t*  pcap_open(const char* file_path, const char* fst_str) {
    pcap_info_st* info = (struct pcap_info_st*)malloc(sizeof(pcap_info_st));
    FILE* fd = fopen(file_path, "rb");
    filter_st* st = NULL;
    if (fd == NULL) {
        goto fail;
    }
    // fprintf(stderr, "file info: %s\n", file_path);
	if (fread(info, sizeof(*info), 1, fd) != 1) {
		goto fail;
	}
	
	if (info->magic != PCAP_MAGIC) {
		goto fail;
	}
	
	if (info->linktype != PCAP_SUPPORT_LINK_TYPE) {
		goto fail;
	}

    if (fst_str != NULL) {
        st = filter_init(fst_str);
        if (st == NULL) {
            goto fail;
        }
    }

    for (int i = 0; i < MAX_REGISTED_HOOK; i++) {
        memset(registed_hooks[i].hook_name, 0, MAX_HOOK_NAME_LEN);
        registed_hooks[i].hook_func = NULL;
    }
    pcap_handle_t* handle = (pcap_handle_t*)malloc(sizeof(pcap_handle_t));
    handle->pcap_header = info;
    handle->pcap_fd = fd;
    handle->fst = st;
	return handle;

fail:
    fprintf(stderr, "pcap init failed\n");
    if (fd) {
	    fclose(fd);
        fd = NULL;
    } 
	return NULL;
}

void pcap_destory_handle(pcap_handle_t* handle) {
    if (handle == NULL) {
        return ;
    }
    if (handle->fst) {
        filter_destroy(handle->fst);
        handle->fst = NULL;
    }
    if (handle->pcap_header) {
        free(handle->pcap_header);
        handle->pcap_header = NULL;
    }
    fclose(handle->pcap_fd);
    free(handle);
    handle = NULL;
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
    uint32_t len = ctx->handle->pcap_header->snaplen;
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

static int __check_value(filter_st* f,  pcap_data_t* pdata) {
    char* key = f->s.subject;
    for (int i = 0; i < MAX_REGISTED_HOOK; i++) {
        if (registed_hooks[i].hook_func == NULL) {
            return 1;
        }
        if (strcmp(key, registed_hooks[i].hook_name) == 0) {
            return registed_hooks[i].hook_func(pdata, f);
        }
    }
    return 1;
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

void pcap_process_poll(pcap_handle_t* handle, pcap_data_t* data, pcap_cb cb) {
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
    if (ret == -1) {
        return ret;
    }
    return 1;
}

int pcap_register(const char* filter_name, hook hk) {
    for (int i = 0; i < MAX_REGISTED_HOOK; i++) {
        if (registed_hooks[i].hook_func == NULL) {
            // fprintf(stderr, "pcap register, filter_name: %s, hk: %p\n", filter_name, hk);
            registed_hooks[i].hook_func = hk;
            memcpy(registed_hooks[i].hook_name, filter_name, strlen(filter_name));
            return 1;
        }
    }
    return 0;
}