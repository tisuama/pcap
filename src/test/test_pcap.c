// #ifdef XTEST
#include <stdio.h>
#include <stdlib.h>
#include "pcap_manager.h"
#include "filter.h"
#include "ldapexpr.h"
#include "xtest.h"

void SetUp() {}
void TearDown() {}

static void print_packet(pcap_data_t* data)
{
	printf("%s, %u.%u.%u.%u:%u->%u.%u.%u.%u:%u\n", data->proto == IPPROTO_TCP ? "TCP":"UDP", 
			NIPQUAD(data->saddr), ntohs(data->source), 
			NIPQUAD(data->daddr), ntohs(data->dest));
}

TEST_F(TEST_PCAP, pcap_open, SetUp, TearDown) {
    pcap_handle_t* handle;
    handle = pcap_open("./data/1.pcap", NULL);
    ASSERT_TRUE(handle != NULL);
    pcap_destory_handle(handle);
    handle = pcap_open("./data/2.pcap", NULL);
    ASSERT_TRUE(handle == NULL);
    pcap_destory_handle(handle);
    handle = pcap_open("./data/1.pcap", "(&(src_port>2000)(&(!(src_port=2140))(proto=udp)))");
    ASSERT_TRUE(handle != NULL);
    pcap_destory_handle(handle);
    handle = pcap_open("./data/1.pcap", "(&(src_port>2000)&!(src_port=2140))(proto=udp)))");
    ASSERT_TRUE(handle == NULL);
    pcap_destory_handle(handle);
}

TEST_F(TEST_PCAP, pcap_register, SetUp, TearDown) {
    int ret;
    ret = pcap_register("ip", ip_filter);
    ASSERT_EQ(ret, 1);
}

TEST_F(TEST_PCAP, pcap_process_poll, SetUp, TearDown) {
	pcap_handle_t* handle;
	handle = pcap_open("./data/1.pcap", "(&(src_port>2000)(&(!(src_port=2140))(proto=udp)))");

    int ret;
	ret = pcap_register("ip", ip_filter);
    ASSERT_EQ(ret, 1);
	ret = pcap_register("port", port_filter);
    ASSERT_EQ(ret, 1);
	ret = pcap_register("proto", proto_filter);  
    ASSERT_EQ(ret, 1);
    ret = pcap_register("sport", sport_filter);
    ASSERT_EQ(ret, 1);
    ret = pcap_register("dport", dport_filter);
    ASSERT_EQ(ret, 1);
    ret = pcap_register("sip", sip_filter);
    ASSERT_EQ(ret, 1);
    ret = pcap_register("dip", dip_filter);  
    ASSERT_EQ(ret, 1);

    pcap_data_t data;
    pcap_process_poll(handle, &data, print_packet);

	// destory
	pcap_destory_handle(handle);
}

TEST_F(TEST_PCAP, pcap_process_with_forward, SetUp, TearDown) {
	pcap_handle_t* handle;
	handle = pcap_open("./data/1.pcap", "(&(src_port>2000)(&(!(src_port=2140))(proto=udp)))");
	
    int ret;
	ret = pcap_register("ip", ip_filter);
    ASSERT_EQ(ret, 1);
	ret = pcap_register("port", port_filter);
    ASSERT_EQ(ret, 1);
	ret = pcap_register("proto", proto_filter);  
    ASSERT_EQ(ret, 1);
    ret = pcap_register("sport", sport_filter);
    ASSERT_EQ(ret, 1);
    ret = pcap_register("dport", dport_filter);
    ASSERT_EQ(ret, 1);
    ret = pcap_register("sip", sip_filter);
    ASSERT_EQ(ret, 1);
    ret = pcap_register("dip", dip_filter);  
    ASSERT_EQ(ret, 1);

    pcap_data_t data;
    ret = pcap_process_forward(handle, &data);
    ASSERT_EQ(ret, 1);
	// destory
	pcap_destory_handle(handle);    
}

int main(int argc, char* argv[]) {
    return xtest_start_test(argc, argv);
}



// #endif