#include "filter.h"

#define MAX_PORT_LEN 12
#define MAX_IP_LEN 128
#define MAX_PROTO_LEN 12

enum key_type {
    SRC_TYPE,
    DST_TYPE,
};  

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

static void __get_port_str(pcap_data_t* pdata, char* data, enum key_type ft) {
    int port = 0;
    if (ft == SRC_TYPE) {
        port = ntohs(pdata->source);
        snprintf(data, MAX_PORT_LEN, "%d", port);
    } else {
        port = ntohs(pdata->dest);
        snprintf(data, MAX_PORT_LEN, "%d", port);       
    }
}

static void __get_addr_str(pcap_data_t* pdata, char* data, enum key_type ft) {
    if (ft == SRC_TYPE) {
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

int ip_filter(pcap_data_t* pdata, filter_st* fst) {
    char ip_str[MANX_IP_LEN];
    char* value = f->s.value;
    __get_addr_str(pdata, ip_str, SRC_TYPE);
    int ret = 0;
    ret |= __compare_value(ip_str, value, fst);
    __get_addr_str(pdata, ip_str, DST_TYPE);
    ret |= __compare_value(ip_str, value, fst);
    return ret;
}
int port_filter(pcap_data_t* pdata, filter_st* fst) {
    char port_str[MAX_PORT_LEN];
    char* value = f->s.value;
    __get_port_str(pdata, port_str, SRC_TYPE);
    int ret = 0;
    ret |= __compare_value(port_str, value, fst);
    __get_port_str(pdata, port_str, DST_TYPE);
    ret |= __compare_value(port_str, value, fst);
    return ret;    
}
int proto_filter(pcap_data_t* pdata, filter_st* fst) {
    char proto_str[MAX_PORT_LEN];
    char* value = f->s.value;
    __get_proto_str(pdata, proto_str, SRC_TYPE);
    int ret = 0;
    ret |= __compare_value(proto_str, value, fst);
    return ret;      
}
int sip_filter(pcap_data_t* pdata, filter_st* fst) {
    char ip_str[MANX_IP_LEN];
    char* value = f->s.value;
    __get_addr_str(pdata, ip_str, SRC_TYPE);
    int ret = 0;
    ret |= __compare_value(ip_str, value, fst);
    return ret;  
}
int dip_filter(pcap_data_t* pdata, filter_st* fst) {
    char ip_str[MANX_IP_LEN];
    char* value = f->s.value;
    __get_addr_str(pdata, ip_str, DST_TYPE);
    int ret = 0;
    ret |= __compare_value(ip_str, value, fst);
    return ret;      
}
int sport_filter(pcap_data_t* pdata, filter_st* fst) {
    char port_str[MAX_PORT_LEN];
    char* value = f->s.value;
    __get_port_str(pdata, port_str, SRC_TYPE);
    int ret = 0;
    ret |= __compare_value(port_str, value, fst);
    return ret;
}
int dport_filter(pcap_data_t* pdata, filter_st* fst) {
    char port_str[MAX_PORT_LEN];
    char* value = f->s.value;
    __get_port_str(pdata, port_str, DST_TYPE);
    int ret = 0;
    ret |= __compare_value(port_str, value, fst);
    return ret;    
}