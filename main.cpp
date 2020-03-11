#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>

char myIp[16];


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
            if(memcmp(myIp, dstIp, sizeof(myIp)) == 0) {
                char sshVersion[256];
                memset(&sshVersion, 0, sizeof(sshVersion));

                const u_char *temp_pointer = payload;
                int byte_count = 0;
                while (byte_count < payload_length && byte_count < sizeof(sshVersion)) {
                    if((uint8_t)*temp_pointer == 13 || (uint8_t)*temp_pointer == 10) {
                        break;
                    }
                    else{
                        temp_pointer++;
                        byte_count++;
                    }
                }

                memcpy(sshVersion, payload, byte_count);

                char dataToWrite[256];
                sprintf(dataToWrite, "%s:%d:%s\n", srcIp, srcPort, sshVersion); 

                FILE* pFile = fopen("ssh.txt", "a");
                fwrite(dataToWrite, sizeof(char), strlen(dataToWrite), pFile);
                fclose(pFile);
            }

        }

        // Bitcoin
        if(memcmp(payload, "\xf9\xbe\xb4\xd9", 4) == 0) {
            if(memcmp(myIp, dstIp, sizeof(myIp)) == 0) {
                const u_char *tempPointer = payload + 4;
                int tempLength = payload_length - 4;

                // Version packet
                if(memcmp(tempPointer, "version", 7) == 0 && tempLength >= 20) {
                    tempPointer += 12;  tempLength -= 12;
                    tempPointer += 8;   tempLength -= 8; // Skip payload length and checksum

                    if(tempLength >= 4) {
                        char userAgent[17]; memset(&userAgent, 0, sizeof(userAgent));
                        char relayFlag[3];  memset(&relayFlag, 0, sizeof(relayFlag));
                        unsigned int protocolVersion = (unsigned int)( (unsigned char)(tempPointer[3]) << 24 | (unsigned char)(tempPointer[2]) << 16 | (unsigned char)(tempPointer[1]) << 8 | (unsigned char)(tempPointer[0]) );
                        tempPointer += 4; tempLength -= 4;

                        tempPointer += 8;   tempLength -= 8; // Skip node services
                        tempPointer += 8;   tempLength -= 8; // Skip timestamp
                        tempPointer += 26;  tempLength -= 26; // Skip reveiving address
                        tempPointer += 26;  tempLength -= 26; // Skip emiting address
                        tempPointer += 8;   tempLength -= 8; // Skip random nounce

                        // User agent
                        if(tempLength >= 1) {
                            unsigned char userAgentLength = (unsigned char)(tempPointer[0]);
                            tempPointer += 1; tempLength -= 1;
                            if(tempLength >= userAgentLength) {
                                memcpy(userAgent, tempPointer, userAgentLength);
                                tempPointer += 16; tempLength -= 16;

                                tempPointer += 4; tempLength -= 4; // Skip last block

                                // Relay flag
                                if(tempLength >= 1) {
                                    sprintf(relayFlag, "%.2X", tempPointer[0]);
                                }
                            }
                        }


                        char dataToWrite[256];
                        sprintf(dataToWrite, "%s:%d:%d:%s:%s\n", srcIp, srcPort, protocolVersion, userAgent, relayFlag); 
                        FILE* pFile = fopen("bitcoin.txt", "a");
                        fwrite(dataToWrite, sizeof(char), strlen(dataToWrite), pFile);
                        fclose(pFile);
                    }
                }      

                /*
                for(int i=0; i<4; i++) {
                    printf("%.2X ", (unsigned char)(tempPointer[0 + i]));
                }
                */
            }
            return;
        }
    }
}

int main(int argc, char **argv) {
    if(argc < 3) {
        printf("%s <interface> <yourIpAddress>", argv[0]);
        return 1;
    }
    sprintf(myIp, "%s", argv[2]);

    pcap_t *handle;
    char error_buffer[PCAP_ERRBUF_SIZE];
    char *device = argv[1];
    int snapshot_len = 1028;
    int promiscuous = 0;
    int timeout = 1000;

    handle = pcap_open_live(device, snapshot_len, promiscuous, timeout, error_buffer);
    pcap_loop(handle, 0, everyPacketHandler, NULL);
    pcap_close(handle);
    return 0;
}
