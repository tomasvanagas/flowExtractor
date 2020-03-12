#include <stdio.h>
#include <map>
#include <iostream>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#include "common.h"

using namespace std;

map<string, map<string, string>> sessionStrings;
map<string, map<string, int>> sessionInts;



bool handleWordpress(char *srcIp, int srcPort, char *dstIp, int dstPort, const u_char *payload, int payload_length) {
    // https://github.com/nodejs/http-parser
    
    sessionStrings["1.1.1.1"]["key1"] = "value1";

    sessionInts["1.1.1.1"]["key1"] = 1;


    if(memcmp(myIp, srcIp, sizeof(myIp)) == 0) {
        if(memcmp(payload, "POST ", 5) == 0) {

        }
    }
    else {
        if(memcmp(payload, "HTTP ", 5) == 0) {
            
        }
    }
    return false;
}