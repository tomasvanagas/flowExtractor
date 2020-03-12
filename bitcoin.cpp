#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "common.h"

char myIp[16];

bool handleBitcoin( char *srcIp, int srcPort, char *dstIp, int dstPort, const u_char *payload, int payload_length) {
    if(memcmp(myIp, dstIp, sizeof(myIp)) == 0) {
        const u_char *tempPointer = payload + 4;
        int tempLength = payload_length - 4;

        // Version packet
        if(memcmp(tempPointer, "version", 7) == 0 && tempLength >= 20) {
            tempPointer += 12;  tempLength -= 12;
            tempPointer += 8;   tempLength -= 8; // Skip payload length and checksum

            if(tempLength >= 4) {
                char userAgent[256]; memset(&userAgent, 0, sizeof(userAgent));
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
                        tempPointer += userAgentLength; tempLength -= userAgentLength;

                        tempPointer += 4; tempLength -= 4; // Skip last block

                        // Relay flag
                        if(tempLength >= 1) {
                            sprintf(relayFlag, "%.2X", tempPointer[0]);
                        }
                    }
                }


                char dataToWrite[256];
                sprintf(dataToWrite, "%s:%d:%d:%s:%s\n", srcIp, srcPort, protocolVersion, userAgent, relayFlag); 
                FILE* pFile = fopen("./captured/bitcoin.txt", "a");
                fwrite(dataToWrite, sizeof(char), strlen(dataToWrite), pFile);
                fclose(pFile);
            }
        }      
    }
    return true;
}