#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <iostream>

#include "common.h"
#include "everyPacket.cpp"

int main(int argc, char **argv) {
    char fileName[256];
    char error_buffer[PCAP_ERRBUF_SIZE];

    if(argc < 3) {
        printf("%s <filename> <yourIpAddress>", argv[0]);
        return 1;
    }

    sprintf(fileName, "%s", argv[1]);
    sprintf(myIp, "%s", argv[2]);

    pcap_t *handle = pcap_open_offline(fileName, error_buffer);
    if (handle == NULL) {
        std::cout << "pcap_open_live() failed: " << error_buffer << std::endl;
        return 1;
    }
    if (pcap_loop(handle, 0, everyPacketHandler, NULL) < 0) {
        std::cout << "pcap_loop() failed: " << pcap_geterr(handle);
        return 1;
    }
    std::cout << "capture finished" << std::endl;
    pcap_close(handle);
    return 0;
}