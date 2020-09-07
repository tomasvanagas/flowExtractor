#include <stdio.h>
#include <map>
#include <iostream>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <ctype.h>

#include "httpparser/request.h"
#include "httpparser/httprequestparser.h"
#include "httpparser/response.h"
#include "httpparser/httpresponseparser.h"

#include "common.h"

using namespace std;
using namespace httpparser;

//map<string, map<string, string> > sessionStrings;
//map<string, map<string, int> > sessionInts;






bool handleHTTP(char *srcIp, int srcPort, char *dstIp, int dstPort, const u_char *payload, int payload_length) {
    // https://github.com/nodejs/http-parser

    if(memcmp(myIp, srcIp, sizeof(myIp)) == 0) {
        char sessionName[22] = { 0 };
        sprintf(sessionName, "%s:%d", dstIp, dstPort);

        if(memcmp(payload, "GET /", 5) == 0) {
            char text[payload_length + 1];
            memset(&text, 0, sizeof(text));
            memcpy(text, payload, payload_length);

            Request request;
            HttpRequestParser parser;
            HttpRequestParser::ParseResult res = parser.parse(request, text, text + sizeof(text));
            if(res == HttpRequestParser::ParsingCompleted) {
                char host[256] = { 0 };

                for(std::vector<Request::HeaderItem>::const_iterator it = request.headers.begin(); it != request.headers.end(); ++it) {
                    if(it->name.compare("Host") == 0) {
                        char visitedUrl[2048] = { 0 };
                        sprintf(visitedUrl, "http://%s%s\n", it->value.c_str(), request.uri.c_str());
                        
                        FILE* pFile = fopen("./captured/visitedUrls.txt", "a");
                        fwrite(visitedUrl, sizeof(char), strlen(visitedUrl), pFile);
                        fclose(pFile);

                        //sessionStrings[sessionName]["Host"] = it->value.c_str();
                        break;
                    }
                }

                

            }
            return true;
        }
    }
    else {
        if(memcmp(payload, "HTTP", 4) == 0) {
            /*
            char sessionName[22] = { 0 };
            sprintf(sessionName, "%s:%d", srcIp, srcPort);

            
            if(strlen(sessionStrings[sessionName]["Host"].c_str())!=0) {
                
                char text[payload_length + 1];
                memset(&text, 0, sizeof(text));
                memcpy(text, payload, payload_length);

                Response response;
                HttpResponseParser parser;

                HttpResponseParser::ParseResult res = parser.parse(response, text, text + sizeof(text));

                if( res == HttpResponseParser::ParsingCompleted ) {
                    
                    char host[256] = { 0 };

                    
                    for(std::vector<Response::HeaderItem>::const_iterator it = response.headers.begin(); it != response.headers.end(); ++it) {
                        if(it->name.compare("Host") == 0) {
                            if(sessionStrings[sessionName]["Host"].compare(it->value) != 0) {
                                break;
                            }   
                        }
                        else if(it->name.compare("Set-Cookie") == 0) {
                            
                            if(strncmp(it->value.c_str(), "wordpress_logged_in", sizeof("wordpress_logged_in")-1) == 0) {
                                char dataToWrite[2048];
                                sprintf(dataToWrite, "%s:%s:%s\n", sessionStrings[sessionName]["Host"].c_str(), sessionStrings[sessionName]["log"].c_str(), sessionStrings[sessionName]["pwd"].c_str() );

                                FILE* pFile = fopen("./captured/wordpress.txt", "a");
                                fwrite(dataToWrite, sizeof(char), strlen(dataToWrite), pFile);
                                fclose(pFile);
                                return true;
                            }
                        }
                    }
                }
            }
            */
        }
    }
    return false;
}