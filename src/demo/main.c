#include <stdio.h>
#include "pcap_manager.h"
#include "filter.h"
#include "ldapexpr.h"

static void print_packet(pcap_data_t* data)
{
	printf("%s, %u.%u.%u.%u:%u->%u.%u.%u.%u:%u\n", data->proto == IPPROTO_TCP ? "TCP":"UDP", 
			NIPQUAD(data->saddr), ntohs(data->source), 
			NIPQUAD(data->daddr), ntohs(data->dest));
}

// ip/port/proto
int main(int argc, char **argv)
{
	char* filter_str = NULL;
	if (argc < 2 || argc > 3) {
		fprintf(stderr, "Usage: %s <pcap file> <filter>\n", argv[0]);
		return -1;
	}
	if (argc > 2) {
		filter_str = argv[2];
	}

	pcap_handle_t* handle;
	handle = pcap_open(argv[1], filter_str);
	if (handle == NULL) {
		fprintf(stderr, "Pcap init failed\n");
		return -1;
	}
	
	// 注册比较函数
	int ret;
	ret = pcap_register("ip", ip_filter);
	ret = pcap_register("port", port_filter);
	ret = pcap_register("proto", proto_filter);  
    ret = pcap_register("sport", sport_filter);
    ret = pcap_register("dport", dport_filter);
    ret = pcap_register("sip", sip_filter);
    ret = pcap_register("dip", dip_filter);  	
	pcap_data_t data;
	// read POLL
	pcap_process_poll(handle, &data, print_packet);

	// destory
	pcap_destory_handle(handle);
}
