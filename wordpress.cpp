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

map<string, map<string, string> > sessionStrings;
map<string, map<string, int> > sessionInts;


void urldecode2(char *dst, const char *src) {
    char a, b;
    while (*src) {
            if ((*src == '%') &&
                ((a = src[1]) && (b = src[2])) &&
                (isxdigit(a) && isxdigit(b))) {
                    if (a >= 'a')
                            a -= 'a'-'A';
                    if (a >= 'A')
                            a -= ('A' - 10);
                    else
                            a -= '0';
                    if (b >= 'a')
                            b -= 'a'-'A';
                    if (b >= 'A')
                            b -= ('A' - 10);
                    else
                            b -= '0';
                    *dst++ = 16*a+b;
                    src+=3;
            } else if (*src == '+') {
                    *dst++ = ' ';
                    src++;
            } else {
                    *dst++ = *src++;
            }
    }
    *dst++ = '\0';
}





bool handleWordpress(char *srcIp, int srcPort, char *dstIp, int dstPort, const u_char *payload, int payload_length) {
    // https://github.com/nodejs/http-parser
    
    //sessionStrings["1.1.1.1"]["key1"] = "value1";
    //sessionInts["1.1.1.1"]["key1"] = 1;

    if(memcmp(myIp, srcIp, sizeof(myIp)) == 0) {
        char sessionName[22] = { 0 };
        sprintf(sessionName, "%s:%d", dstIp, dstPort);

        if(memcmp(payload, "POST /wp-login", 14) == 0) {
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
                        sessionStrings[sessionName]["Host"] = it->value.c_str();
                        break;
                    }
                }


                char httpPostArgs[2048] = { 0 };
                sprintf(httpPostArgs, "%s&", request.content.data());
                //printf("%s\n", request.content.data());
                char* argumentStart = httpPostArgs;
                for (char* pointer = httpPostArgs; pointer[0]!='\0'; pointer++) {
                    if(pointer[0] == '&') {
                        char argumentPair[256] = { 0 };
                        memcpy(argumentPair, argumentStart, pointer - argumentStart);

                        for (char* pointer2 = argumentPair; pointer2[0]!='\0'; pointer2++) {
                            if(pointer2[0] == '=') {
                                char key[256] = { 0 }, value[256] = { 0 };
                                memcpy(key, argumentPair, pointer2 - argumentPair);
                                urldecode2(key, key);

                                pointer2++;
                                memcpy(value, pointer2, strlen(pointer2));
                                urldecode2(value, value);

                                if(strcmp(key, "log") == 0 || strcmp(key, "pwd") == 0) {
                                    sessionStrings[sessionName][key] = value;


                                    if(strcmp(key, "pwd") == 0) {
                                        char dataToWrite[2048] = { 0 };
                                        sprintf(dataToWrite, "%s:%s:%s\n", sessionStrings[sessionName]["Host"].c_str(), sessionStrings[sessionName]["log"].c_str(), sessionStrings[sessionName]["pwd"].c_str() );

                                        FILE* pFile = fopen("./captured/wordpressTested.txt", "a");
                                        fwrite(dataToWrite, sizeof(char), strlen(dataToWrite), pFile);
                                        fclose(pFile);
                                    }

                                }
                                break;
                            }
                        }

                        argumentStart = pointer + 1;
                    }
                } 
            }
            return 1;
        }
    }
    else {
        if(memcmp(payload, "HTTP", 4) == 0) {
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
                                break;
                            }
                        }
                    }
                }
            }
        }
    }
    return false;
}