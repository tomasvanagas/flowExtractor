#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "common.h"
#include "everyPacket.cpp"


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