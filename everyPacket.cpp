#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "common.h"
#include "ssh.cpp"
#include "bitcoin.cpp"
#include "wordpress.cpp"



void everyPacketHandler(u_char *args, const struct pcap_pkthdr* header, const u_char* packet) {
    // https://www.devdungeon.com/content/using-libpcap-c
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        return;
    }

    const u_char *ip_header;
    const u_char *tcp_header;
    const u_char *payload;

    int ethernet_header_length = 14; 
    int ip_header_length;
    int tcp_header_length;
    int payload_length;

    ip_header = packet + ethernet_header_length;
    ip_header_length = ((*ip_header) & 0x0F);
    ip_header_length = ip_header_length * 4;
    
    u_char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_TCP) {
        //printf("Not a TCP packet. Skipping...\n\n");
        return;
    }

    tcp_header = packet + ethernet_header_length + ip_header_length;
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    tcp_header_length = tcp_header_length * 4;

    int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;
    payload_length = header->caplen - (ethernet_header_length + ip_header_length + tcp_header_length);
    payload = packet + total_headers_size;

    char srcIp[16]; 
    char dstIp[16]; 
    sprintf(srcIp, "%d.%d.%d.%d", (unsigned char)(ip_header[12]), (unsigned char)(ip_header[13]), (unsigned char)(ip_header[14]), (unsigned char)(ip_header[15]));
    sprintf(dstIp, "%d.%d.%d.%d", (unsigned char)(ip_header[16]), (unsigned char)(ip_header[17]), (unsigned char)(ip_header[18]), (unsigned char)(ip_header[19]));
    uint16_t srcPort = uint16_t((unsigned char)(tcp_header[0]) << 8 | (unsigned char)(tcp_header[1]));
    uint16_t dstPort = uint16_t((unsigned char)(tcp_header[2]) << 8 | (unsigned char)(tcp_header[3]));



    if (payload_length > 0) {
        // SSH
        if(memcmp(payload, "SSH-", 4) == 0){
            if(handleSSH(srcIp, srcPort, dstIp, dstPort, payload, payload_length)) {
                return;
            }
        }

        // Bitcoin
        if(memcmp(payload, "\xf9\xbe\xb4\xd9", 4) == 0) {
            if(handleBitcoin(srcIp, srcPort, dstIp, dstPort, payload, payload_length)) {
                return;
            }
        }

        // Web
        if((memcmp(payload, "POST ", 5) == 0) || (memcmp(payload, "GET ", 4) == 0) || (memcmp(payload, "HTTP ", 5) == 0) ||
        (memcmp(payload, "OPTIONS ", 8) == 0) || (memcmp(payload, "UPLOAD ", 7) == 0) || (memcmp(payload, "TRACE ", 6) == 0) ) {
            if(handleWordpress(srcIp, srcPort, dstIp, dstPort, payload, payload_length)) {
                return;
            }
        }


        /*
        for(int i=0; i<4; i++) {
            printf("%.2X ", (unsigned char)(tempPointer[0 + i]));
        }
        */
    }
}