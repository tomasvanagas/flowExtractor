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

map<string, map<string, string> > sessionStringsVnc;
map<string, map<string, int> > sessionIntsVnc;


bool handleVnc(char *srcIp, int srcPort, char *dstIp, int dstPort, const u_char *payload, int payload_length) {

    // server --> client
    if(memcmp(myIp, dstIp, sizeof(myIp)) == 0) {
        char sessionName[22] = { 0 };
        sprintf(sessionName, "%s:%d", dstIp, dstPort);


        if(memcmp(payload, "RFB 003.00", 10) == 0) {
            // 1 --> Server version
            char serverVersion[12] = { 0 };
            memcpy(serverVersion, payload, 11);

            sessionStringsVnc[sessionName]["serverVersion"] = serverVersion;
            sessionStringsVnc[sessionName]["clientVersion"] = "";
            sessionStringsVnc[sessionName]["serverSecurityTypes"] = "";
            sessionStringsVnc[sessionName]["clientSecurityChoice"] = "";
            sessionStringsVnc[sessionName]["serverSecurityChallenge"] = "";
            sessionStringsVnc[sessionName]["clientSecuritySolution"] = "";

            //printf("%s\n-------\n", serverVersion);
            return true;
        }
        else if(strlen(sessionStringsVnc[sessionName]["serverVersion"].c_str()) > 0) {
            if(strlen(sessionStringsVnc[sessionName]["clientVersion"].c_str()) > 0) {
                if(strlen(sessionStringsVnc[sessionName]["serverSecurityTypes"].c_str()) == 0) {

                    // 3 --> Security types suported by server
                    char securityTypeCount = payload[0];
                    if(securityTypeCount < 10 && securityTypeCount > 0) {
                        if(payload_length - 1 == securityTypeCount) {
                            
                            char securityTypes[1024] = { 0 }; 
                            for(int i=1; i<payload_length; i++) {
                                sprintf(securityTypes, "%s%.2X ", securityTypes, (unsigned char)(payload[0 + i]));
                            }

                            sessionStringsVnc[sessionName]["serverSecurityTypes"] = securityTypes;
                            //printf("%s\n", securityTypes);
                            return true;
                        }
                    }

                }
                else {
                    if(strlen(sessionStringsVnc[sessionName]["clientSecurityChoice"].c_str()) > 0) {
                        if(strlen(sessionStringsVnc[sessionName]["serverSecurityChallenge"].c_str()) == 0) {
                            if(strlen(sessionStringsVnc[sessionName]["clientSecuritySolution"].c_str()) == 0) {
                                if(payload_length == 16) {

                                    // 5 --> Security challenge from server
                                    char securityChallenge[33] = { 0 }; 
                                    for(int i=0; i<payload_length; i++) {
                                        sprintf(securityChallenge, "%s%.2x", securityChallenge, (unsigned char)(payload[0 + i]));
                                    }
                                    //printf("%s\n", securityChallenge);
                                    sessionStringsVnc[sessionName]["serverSecurityChallenge"] = securityChallenge;
                                    return true;

                                }
                            }
                        }
                        else {   
                            if(strlen(sessionStringsVnc[sessionName]["clientSecuritySolution"].c_str()) > 0) {
                                if(memcmp(payload, "\x00\x00\x00", 3) == 0) {
                                    // 7 --> Auth response from server

                                    for(int i=0; i<4; i++) {
                                        printf("%.2x ", (unsigned char)(payload[0 + i]));
                                    }

                                    if(payload[3] > 2) {
                                        char authResponseString[256] = { 0 };
                                        memcpy(authResponseString, payload + 4, payload[3]);
                                        printf("%s", authResponseString);
                                    }

                                    printf("\n");


                                    // 8 --> Auth successful
                                    if(memcmp(payload, "\x00\x00\x00\x00", 4) == 0) {
                                        char dataToWrite[2048] = { 0 };
                                        sprintf(dataToWrite, "%s:%d: %s:%s:%s:%s:%s:%s:%s\n",   srcIp, 
                                                                                                srcPort, 
                                                                                                sessionStringsVnc[sessionName]["serverVersion"].c_str(), 
                                                                                                sessionStringsVnc[sessionName]["clientVersion"].c_str(),
                                                                                                sessionStringsVnc[sessionName]["serverSecurityTypes"].c_str(),
                                                                                                sessionStringsVnc[sessionName]["clientSecurityChoice"].c_str(),
                                                                                                sessionStringsVnc[sessionName]["serverSecurityChallenge"].c_str(),
                                                                                                sessionStringsVnc[sessionName]["serverSecurityTypes"].c_str(),
                                                                                                sessionStringsVnc[sessionName]["clientSecuritySolution"].c_str()
                                                                                            );
                                        FILE* pFile = fopen("./captured/vnc.txt", "a");
                                        fwrite(dataToWrite, sizeof(char), strlen(dataToWrite), pFile);
                                        fclose(pFile);
                                    }

                                    sessionStringsVnc[sessionName]["serverVersion"] = "";
                                    sessionStringsVnc[sessionName]["clientVersion"] = "";
                                    sessionStringsVnc[sessionName]["serverSecurityTypes"] = "";
                                    sessionStringsVnc[sessionName]["clientSecurityChoice"] = "";
                                    sessionStringsVnc[sessionName]["serverSecurityChallenge"] = "";
                                    sessionStringsVnc[sessionName]["clientSecuritySolution"] = "";
                                    return true;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // client --> server
    else {
        char sessionName[22] = { 0 };
        sprintf(sessionName, "%s:%d", srcIp, srcPort);

        if(strlen(sessionStringsVnc[sessionName]["serverVersion"].c_str()) > 0) {
            if(strlen(sessionStringsVnc[sessionName]["clientVersion"].c_str()) == 0) {
                
                if(memcmp(payload, "RFB 003.00", 10) == 0) {
                    // 2 --> Client version
                    char clientVersion[12] = { 0 };
                    memcpy(clientVersion, payload, 11);
                    sessionStringsVnc[sessionName]["clientVersion"] = clientVersion;
                    //printf("%s\n-------\n", clientVersion);
                    return true;
                }

            }
            else {

                if(strlen(sessionStringsVnc[sessionName]["serverSecurityTypes"].c_str()) > 0) {
                    if(strlen(sessionStringsVnc[sessionName]["clientSecurityChoice"].c_str()) == 0) {
                        if(payload_length == 1) {

                            // 4 --> Client security choice
                            char clientSecurityChoice[3] = { 0 };
                            sprintf(clientSecurityChoice, "%.2X", (unsigned char)(payload[0]) );
                            sessionStringsVnc[sessionName]["clientSecurityChoice"] = clientSecurityChoice;
                            //printf("%s\n", clientSecurityChoice);
                            return true;

                        }
                    }
                    else {
                        if(strlen(sessionStringsVnc[sessionName]["serverSecurityChallenge"].c_str()) != 0) {
                            if(strlen(sessionStringsVnc[sessionName]["clientSecuritySolution"].c_str()) == 0) {
                                if(payload_length == 16) {

                                    // 6 --> Security response from client
                                    char securityResponse[33] = { 0 }; 
                                    for(int i=0; i<payload_length; i++) {
                                        sprintf(securityResponse, "%s%.2x", securityResponse, (unsigned char)(payload[0 + i]));
                                    }
                                    sessionStringsVnc[sessionName]["clientSecuritySolution"] = securityResponse;
                                    //printf("%s\n", securityResponse);
                                    return true;

                                }
                            }
                        }
                    }
                }
            }
        }
    }
    return false;
}