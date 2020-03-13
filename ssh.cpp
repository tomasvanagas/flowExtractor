#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "common.h"

bool handleSSH(char *srcIp, int srcPort, char *dstIp, int dstPort, const u_char *payload, int payload_length) {
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

        FILE* pFile = fopen("./captured/ssh.txt", "a");
        fwrite(dataToWrite, sizeof(char), strlen(dataToWrite), pFile);
        fclose(pFile);
    }
    return true;
}