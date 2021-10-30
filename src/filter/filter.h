#ifndef FILTER_H
#define FILTER_Hs


struct pcap_data_t;
struct filter_st;
int ip_filter(pcap_data_t* pdata, filter_st* fst);
int port_filter(pcap_data_t* pdata, filter_st* fst);
int proto_filter(pcap_data_t* pdata, filter_st* fst);
int sip_filter(pcap_data_t* pdata, filter_st* fst);
int dip_filter(pcap_data_t* pdata, filter_st* fst);
int sport_filter(pcap_data_t* pdata, filter_st* fst);
int dport_filter(pcap_data_t* pdata, filter_st* fst);

#endif