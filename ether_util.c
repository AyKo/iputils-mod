/**
 * @file ether_util.c
 * @brief utility functions of the ethernet
 * @author Ayumu Koujiya
 *
 * This souce code is public domain.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h> 
#include <linux/if_arcnet.h> 
#include <linux/version.h>
#include <netinet/ip_icmp.h>

/** MAC Address string to binary
 * @param optarg string of macaddress as XX:XX:XX:XX:XX:XX
 * @param macaddress binary of macadress
 * @return 0:failure 1:success
 */
int conv_macaddress_str_to_bin(const char *optarg, unsigned char macaddress[6])
{
	int i, v;
	char xstr[3] = {};

	/* macaddress length check : len(XX:XX:XX:XX:XX:XX)=17 */
	if (strlen(optarg) != 17) {
		return 0;
	}

	for (i = 0; i < 6; i++, optarg+=3) {
		/* check format */
		int isok = isxdigit(optarg[0]) && isxdigit(optarg[1]) &&
			(i == 5 ? 1 : optarg[2]==':' || optarg[2]=='-');
		if (! isok) {
			return 0;
		}
		/* convert string to binary */
		xstr[0] = optarg[0];
		xstr[1] = optarg[1];
		if (sscanf(xstr, "%2x", &v) == 1) {
			macaddress[i] = v & 0xffu;
		} else {
			return 0;
		}
	}

	return 1;
}

/** Get interface index by device name
 * @param devicename device name such "eth0"
 * @return interface index, -1:failure 
 */
int get_interface_index(const char* devicename)
{
	struct ifreq ifr;
	int s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (s == -1) {
		return -1;
	}
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, devicename, IFNAMSIZ);
	if (ioctl(s, SIOCGIFINDEX, &ifr) == -1) {
		printf("SIOCGIFINDEX: fail ioctl errno=%d\n", errno);
		close(s);
		return -1;
	}
	close(s);
	return ifr.ifr_ifindex;
}

/** Get interface index by device name
 * @param devicename device name such "eth0"
 * @return interface index, -1:failure 
 */
int get_interface_ipaddress(const char* devicename, struct sockaddr_in* addr)
{
	struct ifreq ifr;
	int s = 0;

	s = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, devicename, IFNAMSIZ-1);
	if (ioctl(s, SIOCGIFADDR, &ifr) == -1) {
		printf("SIOCGIFADDR: fail ioctl errno=%d\n", errno);
		close(s);
		return -1;
	}
	close(s);

	memcpy(addr, &ifr.ifr_ifru.ifru_addr, sizeof(*addr));
	return 0;
}

/** Get mac address by device name
 * @param devicename device name such "eth0"
 * @param[out] macaddress
 * @return 0:success -1:failure
 */
int get_mac_address(const char* ifname, unsigned char macaddress[6])
{
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		return -1;
	}

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

	if (ioctl(fd, SIOCGIFHWADDR, &ifr) != 0) {
		close(fd);
		return -1;
	}

	close(fd);

	memcpy(macaddress, ifr.ifr_hwaddr.sa_data, 6);

	return 0;
}

/** Calculate checksum of the IP header
 * @param data pointer to the ip header
 * @param size byte size
 * @return checksum
 */
unsigned short calc_ipchksum(const void* data, size_t size)
{
	uint32_t n = 0;
	const uint16_t* word = data;

	for (; size > 1; size -= 2, ++word) {
		n += *word;
	}
	if (size == 1) {
		uint8_t a = *((uint8_t*) word);
		/* C Programming FAQs(by Steve Summit)*/
		int x=1; // 0x00000001
		if (*(char*)&x) {
			/* little endian. memory image 01 00 00 00 */
			n += a;
		}else{
			/* big endian. memory image 00 00 00 01 */
			n += a << 8;
		}
	}

	n = (n >> 16) + (n & 0xffff);
	n = (n >> 16) + (n & 0xffff);
	return ~n;
}

/** Initialize layer2 socket
 * @param ifidx interface index
 * @return file descriptor, -1:failure 
 */
int l2_socket(int ifidx)
{
	int s;
	struct sockaddr_ll sll;

	s = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP));
	if (s == -1) {
		return -1;
	}

	memset(&sll, 0xff, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_ALL);
	sll.sll_ifindex = ifidx;
	if (bind(s, (struct sockaddr *)&sll, sizeof sll) == -1) {
		close(s);
		return -1;
	}
	
	return s;
}

/** Transmission frame at layer 2
 * @param ifidx interface index
 * @param sock layer2 socket
 * @param data data to be send
 * @param len data length
 * @return sendto()'s return value
 */
int sendto_l2(int ifidx, int sock, const void* data, size_t len)
{
	struct sockaddr_ll sll;

	memset(&sll, 0, sizeof(sll));
	sll.sll_ifindex = ifidx;
	return sendto(sock, data, len, 0, (struct sockaddr *)&sll, sizeof(sll));
}


/** Transmission ICMP by sendto_l2
 * @param sock l2 raw socket
 * @param dst_mac destination mac address
 * @param src_mac source mac address
 * @param src_ip source ip address
 * @param dst_ip destination ip address
 * @param in_icmp ICMP date
 * @param len in_icmp length
 * @return sendto_l2()'s return value
 */
int sendto_icmp_ipv4_l2(
		int ifidx, int sock, 
		const unsigned char dst_mac[6], const unsigned char src_mac[6],
		const struct sockaddr_in* dst_ip, const struct sockaddr_in* src_ip,
		const struct icmphdr* in_icmp, size_t icmp_len)
{
	void* mem = malloc(sizeof(struct ethhdr) + sizeof(struct iphdr) + icmp_len);
	struct ethhdr* ether = mem;
	struct iphdr* ip = (struct iphdr*) (ether + 1);
	struct icmphdr* icmp = (struct icmphdr*) (ip + 1);
	int result = 0, ret_errno = 0;
	static int id_base = 0;

	memcpy(ether->h_dest, dst_mac, 6);
	memcpy(ether->h_source, src_mac, 6);
	ether->h_proto = htons(ETHERTYPE_IP);

	ip->ihl = 5;
	ip->version = 4;
	ip->tos = 0;
	ip->tot_len = htons(ip->ihl*4 + icmp_len);
	ip->id = htons(id_base++);
	ip->frag_off = htons(0x4000);	/* Don't Fragment */
	ip->ttl = 128;
	ip->protocol = 1;
	ip->check = 0;
	ip->saddr = src_ip->sin_addr.s_addr;
	ip->daddr = dst_ip->sin_addr.s_addr;

	memcpy(icmp, in_icmp, icmp_len);

	ip->check = calc_ipchksum(ip, ip->ihl*4);

	result = sendto_l2(ifidx, sock, ether, sizeof(struct ethhdr) + sizeof(struct iphdr) + icmp_len);
	ret_errno = errno;

	free(mem);

	errno = ret_errno;
	return result;
}

