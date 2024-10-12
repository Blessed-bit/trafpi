#include "snifer.h"

void checkPort(const struct ip *ipHeader, const u_char *packet, struct result *findPacket){
    if(ipHeader->ip_p == IPPROTO_TCP){
        const struct tcphdr *tcpHeader = (const struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        findPacket->portSender = ntohs(tcpHeader->th_sport);
        findPacket->portRecipient = ntohs(tcpHeader->th_dport);
        strcpy(findPacket->protocol, "TCP");
        
    }else if(ipHeader->ip_p == IPPROTO_UDP){
        const struct tcphdr *udpHeader = (const struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        strcpy(findPacket->protocol, "UDP");
        findPacket->portSender = ntohs(udpHeader->th_sport);
        findPacket->portRecipient = ntohs(udpHeader->th_dport);
    }
}


void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    const struct ether_header *ethernetHeader;
    const struct ip *ipHeader;
    struct result findPacket;
    
    ethernetHeader = (struct ether_header *)packet;
    ipHeader = (struct ip *)(packet + sizeof(struct ether_header));

    char srcIP[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ipHeader->ip_src), findPacket.ipSender, sizeof(srcIP));
    inet_ntop(AF_INET, &(ipHeader->ip_dst), findPacket.ipRecipient, sizeof(srcIP));

    checkPort(ipHeader, packet, &findPacket);
    
    printf("[%s] packet find:\n packet len: %d bites\n packet ip sender = %s:%d\n packet ip recipient: %s:%d\n\n", findPacket.protocol, pkthdr->len, findPacket.ipSender, findPacket.portSender, findPacket.ipRecipient, findPacket.portRecipient);

}


void initSniffer(char name[size_32]){
    char *dev = name;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr header;

    if (dev == NULL){
        printf("this monitor don't find");
        exit(0);
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("couldn't open device %s: %s\n", dev, errbuf);
        exit(0);
    }
    pcap_loop(handle, 0, packetHandler, NULL);

    
}


#undef size_1024
#undef size_512
#undef size_256
#undef size_128
#undef size_64
#undef size_32