#ifndef PCAP_MANAGER_H
#define PCAP_MANAGER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "ldapexpr.h"

#define MAX_PACKET_LEN 65536


/* pcap头部信息 */
typedef struct pcap_info_st {
	uint32_t magic;				/* 主标识:a1b2c3d4 */
	uint16_t version_major;		/* 主版本号 */
	uint16_t version_minor;		/* 次版本号 */
	uint32_t thiszone;			/* 区域时间0 */
	uint32_t sigfigs;			/* 时间戳0 */
	uint32_t snaplen;			/* 数据包最大长度 */
	uint32_t linktype;			/* 链路层类型 */
} pcap_info_st;

/* pcap每包头部 */
typedef struct packet_head_st {
	uint32_t gmt_sec;			/* 时间戳，秒部分 */
	uint32_t gmt_msec;			/* 时间戳，微秒部分 */
	uint32_t caplen;			/* 被抓取部分的长度 */
	uint32_t len;				/* 数据包原长度 */
} packet_head_st;

/* 二层头，ethhdr，为了避免引入linux/if_ether.h，这里单独定义 */
typedef struct l2_head_st {
	char dest[6];				/* 目的mac地址 */
	char source[6];				/* 源mac地址 */
	uint16_t proto;				/* 三层协议 */
} l2_head_st;

#define NIPQUAD(addr) \
	((const unsigned char *)&addr)[0], \
	((const unsigned char *)&addr)[1], \
	((const unsigned char *)&addr)[2], \
	((const unsigned char *)&addr)[3]

typedef struct pacp_data {
	uint8_t proto;
	uint16_t source;
	uint16_t dest;
	uint32_t saddr;
	uint32_t daddr;
}pcap_data_t;

typedef struct pcap_handle {
	FILE* pcap_fd;
	filter_st* fst;
	pcap_info_st pcap_header;
}pcap_handle_t;

typedef void (*pcap_cb)(pcap_data_t* pcap_data);
typedef void (*compar)(pcap_data_t* pcap_data);
// 对外暴露的接口
pcap_handle_t* pcap_open(const char* file_path, const char* fst_str);
int  pcap_process_poll(pcap_handle_t* handle, pcap_data_t* data, pcap_cb cb);
int  pcap_process_forward(pcap_handle_t* handle, pcap_data_t* data);
void pcap_destory_handle(pcap_handle_t* handle);

// pcap_request_init
// pcap_destory_request

// 内部实现接口
// int  __read_packet(pcap_request_t request);
// void __process_pcap_with_poll(pcap_request_t request);
// void __process_pcap_with_forward(pcap_request_t request);

// // read_packet
// void __pcap_raed_data(read_context_t ctx);
// void __pacp_read_done(read_context_t ctx);



#endif