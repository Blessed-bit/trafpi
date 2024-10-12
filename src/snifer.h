#ifndef SNIFER_H
#define SNIFER_H

#define size_1024 1024
#define size_512 512
#define size_256 256
#define size_128 128
#define size_64 64
#define size_32 32

#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h> 
#include <string.h>

void initSniffer(char name[size_32]);
void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet);
//void checkPort(const struct ip *ipHeader, const u_char *packet, struct result *findPacket);

struct result{
    int len;
    char protocol[size_32];
    char ipSender[INET_ADDRSTRLEN];
    char ipRecipient[INET_ADDRSTRLEN];
    uint16_t portSender;
    uint16_t portRecipient;
};


#endif