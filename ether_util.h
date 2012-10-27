/**
 * @file ether_util.h
 * @brief header file of utility functions of the ethernet
 * @author Ayumu Koujiya
 *
 * This source code is public domain.
 */
#ifndef ETHER_UTIL_H_
#define ETHER_UTIL_H_

#include "netinet/in.h"
#include "netinet/ip_icmp.h"

extern int conv_macaddress_str_to_bin(const char *optarg, unsigned char macaddress[6]);
extern int get_interface_index(const char* devicename);
extern int get_interface_ipaddress(const char* devicename, struct sockaddr_in* addr);
extern int get_mac_address(const char* ifname, unsigned char macaddress[6]);
extern unsigned short calc_ipchksum(const void* data, size_t size);
extern int l2_socket(int ifidx);
extern int sendto_icmp_ipv4_l2(
		int ifidx, int sock, 
		const unsigned char dst_mac[6], const unsigned char src_mac[6],
		const struct sockaddr_in* dst_ip, const struct sockaddr_in* src_ip,
		const struct icmphdr* in_icmp, size_t icmp_len);

#endif

