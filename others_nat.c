#include <rte_eal.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_arp.h>
#include <rte_icmp.h>
#include <rte_ip.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_byteorder.h>
#include "nat_learning.h"

#define BURST_SIZE 			32
#define ARP 					0x0806
#define ICMP 					1
#define TCP 					0x6
#define UDP 					0X11

int 					down_stream_others(void);
int 					up_stream_others(void);

int down_stream_others(void)
{
	uint64_t 			total_tx;
	struct rte_mbuf 	*single_pkt, *pkt[BURST_SIZE];
	struct rte_ether_hdr *eth_hdr;
	struct rte_arp_hdr 	*arphdr;
	struct rte_ipv4_hdr 	*ip_hdr;
	struct rte_icmp_hdr 	*icmphdr;
	struct rte_udp_hdr 	*udphdr;
	struct rte_tcp_hdr 	*tcphdr;
	uint16_t 			ori_port_id;
	uint16_t 			nb_rx, nb_tx;

	for(;;) {
		total_tx = 0;
		nb_rx = rte_eth_rx_burst(1,0,pkt,BURST_SIZE);
		if (nb_rx == 0)
			continue;
		for(int i=0;i<nb_rx;i++) {
			single_pkt = pkt[i];
			rte_prefetch0(rte_pktmbuf_mtod(single_pkt, void *));
			eth_hdr = rte_pktmbuf_mtod(single_pkt,struct rte_ether_hdr*);
			if (unlikely(eth_hdr->ether_type == rte_cpu_to_be_16(ARP))) {
				rte_memcpy(eth_hdr->dst_addr.addr_bytes,eth_hdr->src_addr.addr_bytes,6);
				rte_memcpy(eth_hdr->src_addr.addr_bytes,mac_addr[1],6);
				arphdr = (struct rte_arp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr));
				if (arphdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST) && arphdr->arp_data.arp_tip == ip_addr[1]) {
					rte_memcpy(arphdr->arp_data.arp_tha.addr_bytes,arphdr->arp_data.arp_sha.addr_bytes,6);
					rte_memcpy(arphdr->arp_data.arp_sha.addr_bytes,mac_addr[1],6);
					arphdr->arp_data.arp_tip = arphdr->arp_data.arp_sip;
					arphdr->arp_data.arp_sip = ip_addr[1];
					arphdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
					rte_eth_tx_burst(1,0,&single_pkt,1);
				}
				else if (arphdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)) {
					for(int j=0; j<65536; j++) {
						if (arphdr->arp_data.arp_sip == addr_table[j].dst_ip) {
							if (addr_table[j].is_fill == 0) {
								rte_memcpy(addr_table[j].dst_mac,arphdr->arp_data.arp_sha.addr_bytes,ETH_ALEN);
								addr_table[j].is_fill = 1;
							}
						}
					}
					rte_pktmbuf_free(single_pkt);
				}
				else
					rte_pktmbuf_free(single_pkt);
				continue;
			}
			ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr));
			single_pkt->l2_len = sizeof(struct rte_ether_hdr);
			single_pkt->l3_len = sizeof(struct rte_ipv4_hdr);
			ip_hdr->hdr_checksum = 0;
			icmphdr = (struct rte_icmp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
			switch(ip_hdr->next_proto_id) {
				case ICMP:
					single_pkt->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
					ori_port_id = rte_be_to_cpu_16(icmphdr->icmp_ident);
					rte_memcpy(eth_hdr->dst_addr.addr_bytes,addr_table[ori_port_id].mac_addr,6);
					rte_memcpy(eth_hdr->src_addr.addr_bytes,mac_addr[0],6);
					ip_hdr->dst_addr = addr_table[ori_port_id].src_ip;
					icmphdr->icmp_ident = addr_table[ori_port_id].port_id;
					addr_table[ori_port_id].is_alive = 60;

					icmphdr->icmp_cksum = 0;
					icmphdr->icmp_cksum = get_checksum(icmphdr,single_pkt->data_len - sizeof(struct rte_ipv4_hdr));
					pkt[total_tx++] = single_pkt;
					puts("nat mapping at port 1");
					break;
				case UDP :
					single_pkt->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_UDP_CKSUM;
					udphdr = (struct rte_udp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
					ori_port_id = rte_be_to_cpu_16(udphdr->dst_port);
					rte_memcpy(eth_hdr->dst_addr.addr_bytes,addr_table[ori_port_id].mac_addr,6);
					rte_memcpy(eth_hdr->src_addr.addr_bytes,mac_addr[0],6);
					ip_hdr->dst_addr = addr_table[ori_port_id].src_ip;
					//ip_hdr->src_addr = ip_addr[0];
					udphdr->dst_port = addr_table[ori_port_id].port_id;
					addr_table[ori_port_id].is_alive = 300;

					udphdr->dgram_cksum = 0;
					pkt[total_tx++] = single_pkt;
					break;
				case TCP :
					single_pkt->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM;
					tcphdr = (struct rte_tcp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));				
					ori_port_id = rte_be_to_cpu_16(tcphdr->dst_port);
					rte_memcpy(eth_hdr->dst_addr.addr_bytes,addr_table[ori_port_id].mac_addr,6);
					rte_memcpy(eth_hdr->src_addr.addr_bytes,mac_addr[0],6);
					ip_hdr->dst_addr = addr_table[ori_port_id].src_ip;
					tcphdr->dst_port = addr_table[ori_port_id].port_id;
					addr_table[ori_port_id].is_alive = 300;

					tcphdr->cksum = 0;
					pkt[total_tx++] = single_pkt;
					break;
				default:
					rte_pktmbuf_free(single_pkt);
			}
		}
		if (likely(total_tx > 0)) {
			nb_tx = rte_eth_tx_burst(0, 0,pkt, total_tx);
			if (unlikely(nb_tx < total_tx)) {
				uint16_t buf;
				for(buf = nb_tx; buf < total_tx; buf++)
					rte_pktmbuf_free(pkt[buf]);
			}
		}
	}
	return 0;
}

int up_stream_others(void)
{
	uint64_t 			total_tx;
	struct rte_mbuf 	*single_pkt, *pkt[BURST_SIZE];
	struct rte_arp_hdr 	*arphdr;
	struct rte_ether_hdr *eth_hdr;
	struct rte_ipv4_hdr 	*ip_hdr;
	struct rte_icmp_hdr 	*icmphdr;
	struct rte_udp_hdr 	*udphdr;
	struct rte_tcp_hdr 	*tcphdr;
	uint32_t 			new_port_id;
	int 				i;
	uint16_t 			nb_rx, nb_tx;

	for(;;) {
		total_tx = 0;
		nb_rx = rte_eth_rx_burst(0,0,pkt,BURST_SIZE);
		if (nb_rx == 0)
			continue;
		for(i=0; i<nb_rx; i++) {
			single_pkt = pkt[i];
			rte_prefetch0(rte_pktmbuf_mtod(single_pkt, void *));
			eth_hdr = rte_pktmbuf_mtod(single_pkt,struct rte_ether_hdr*);
			if (eth_hdr->ether_type == rte_cpu_to_be_16(ARP)) {
				rte_memcpy(eth_hdr->dst_addr.addr_bytes,eth_hdr->src_addr.addr_bytes,6);
				rte_memcpy(eth_hdr->src_addr.addr_bytes,mac_addr[0],6);
				arphdr = (struct rte_arp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr));
				if (unlikely(arphdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST) && arphdr->arp_data.arp_tip == ip_addr[0])) {
					rte_memcpy(arphdr->arp_data.arp_tha.addr_bytes,arphdr->arp_data.arp_sha.addr_bytes,6);
					rte_memcpy(arphdr->arp_data.arp_sha.addr_bytes,mac_addr[0],6);
					arphdr->arp_data.arp_tip = arphdr->arp_data.arp_sip;
					arphdr->arp_data.arp_sip = ip_addr[0];
					arphdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
					rte_eth_tx_burst(0,0,&single_pkt,1);
				}
				else
					rte_pktmbuf_free(single_pkt);
				continue;	
			}
			else {
				ip_hdr = (struct rte_ipv4_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr));
				single_pkt->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM;
				single_pkt->l2_len = sizeof(struct rte_ether_hdr);
				single_pkt->l3_len = sizeof(struct rte_ipv4_hdr);
				ip_hdr->hdr_checksum = 0;

				switch (ip_hdr->next_proto_id) {
					case ICMP:
					 	icmphdr = (struct rte_icmp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
					 	nat_icmp_learning(eth_hdr,ip_hdr,icmphdr,&new_port_id);
					 	addr_table[new_port_id].is_alive = 60;
						if (unlikely(new_port_id == -1)) {
							rte_pktmbuf_free(single_pkt);
							break;
						}
					 	rte_memcpy(eth_hdr->dst_addr.addr_bytes,addr_table[new_port_id].dst_mac,6);
						rte_memcpy(eth_hdr->src_addr.addr_bytes,mac_addr[1],6);
						ip_hdr->src_addr = ip_addr[1];
						icmphdr->icmp_ident = rte_cpu_to_be_16(new_port_id);
						icmphdr->icmp_cksum = 0;
						icmphdr->icmp_cksum = get_checksum(icmphdr,single_pkt->data_len - sizeof(struct rte_ipv4_hdr));
						  
						pkt[total_tx++] = single_pkt;

						break;
					case UDP :

						single_pkt->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_UDP_CKSUM;
						udphdr = (struct rte_udp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
		 				nat_udp_learning(eth_hdr,ip_hdr,udphdr,&new_port_id);
						if (unlikely(new_port_id == -1)) {
							rte_pktmbuf_free(single_pkt);
							break;
						}
		 				addr_table[new_port_id].is_alive = 300;
					
		 				rte_memcpy(eth_hdr->dst_addr.addr_bytes,addr_table[new_port_id].dst_mac,6);
						rte_memcpy(eth_hdr->src_addr.addr_bytes,mac_addr[1],6);
						ip_hdr->src_addr = ip_addr[1];
						udphdr->src_port = rte_cpu_to_be_16(new_port_id);
						udphdr->dgram_cksum = 0;

						pkt[total_tx++] = single_pkt;
						break;
					case TCP :
						single_pkt->ol_flags |= RTE_MBUF_F_TX_IPV4 | RTE_MBUF_F_TX_IP_CKSUM | RTE_MBUF_F_TX_TCP_CKSUM;
						tcphdr = (struct rte_tcp_hdr *)(rte_pktmbuf_mtod(single_pkt, unsigned char *) + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
						nat_tcp_learning(eth_hdr,ip_hdr,tcphdr,&new_port_id);
						addr_table[new_port_id].is_alive = 300;
						if (unlikely(new_port_id == -1)) {
							rte_pktmbuf_free(single_pkt);
							break;
						}
						rte_memcpy(eth_hdr->dst_addr.addr_bytes,addr_table[new_port_id].dst_mac,6);
						rte_memcpy(eth_hdr->src_addr.addr_bytes,mac_addr[1],6);
						ip_hdr->src_addr = ip_addr[1];
						tcphdr->src_port = rte_cpu_to_be_16(new_port_id);
						tcphdr->cksum = 0;

						pkt[total_tx++] = single_pkt;
						break;
					default:
						  rte_pktmbuf_free(single_pkt);
						  puts("recv other packet");
						;
				}
			}
		}
		if (likely(total_tx > 0)) {
			nb_tx = rte_eth_tx_burst(1,0,pkt,total_tx);
			// printf("total_tx: %d\n",nb_tx);
			if (unlikely(nb_tx < total_tx)) {
				uint16_t buf;
				for(buf=nb_tx; buf<total_tx; buf++)
					rte_pktmbuf_free(pkt[buf]);
			}
		}
	}
	return 0;

}
