#include "snifer.h"


void checkPort(const struct ip *ipHeader, const u_char *packet, struct result *findPacket){
    if(ipHeader->ip_p == IPPROTO_TCP){
        const struct tcphdr *tcpHeader = (const struct tcphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        findPacket->portSender = ntohs(tcpHeader->th_sport);
        findPacket->portRecipient = ntohs(tcpHeader->th_dport);
        strcpy(findPacket->protocol, "TCP");
        
    }else if(ipHeader->ip_p == IPPROTO_UDP){
        const struct udphdr *udpHeader = (const struct udphdr *)(packet + sizeof(struct ether_header) + sizeof(struct ip));
        strcpy(findPacket->protocol, "UDP");
        findPacket->portSender = ntohs(udpHeader->uh_sport);
        findPacket->portRecipient = ntohs(udpHeader->uh_dport);
    }
}


void packetHandlerNotSave(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    const struct ether_header *ethernetHeader;
    const struct ip *ipHeader;
    struct result findPacket;
    time_t mytime = time(NULL);
    struct tm *now = localtime(&mytime);
    
    ethernetHeader = (struct ether_header *)packet;
    ipHeader = (struct ip *)(packet + sizeof(struct ether_header));

    char srcIP[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ipHeader->ip_src), findPacket.ipSender, sizeof(srcIP));
    inet_ntop(AF_INET, &(ipHeader->ip_dst), findPacket.ipRecipient, sizeof(srcIP));

    checkPort(ipHeader, packet, &findPacket);
    
    printf("[%d:%d:%d] [%s] packet find:\n packet len = %d bites\n packet ip sender = %s:%d\n packet ip recipient = %s:%d\n", now->tm_hour, now->tm_min, now->tm_sec, findPacket.protocol,  pkthdr->len, findPacket.ipSender, findPacket.portSender, findPacket.ipRecipient, findPacket.portRecipient);
    printf(" MAC recipient = %02x:%02x:%02x:%02x:%02x:%02x\n", ethernetHeader->ether_dhost[0],ethernetHeader->ether_dhost[1],ethernetHeader->ether_dhost[2],ethernetHeader->ether_dhost[3],ethernetHeader->ether_dhost[4],ethernetHeader->ether_dhost[5]);
    printf(" MAC sender = %02x:%02x:%02x:%02x:%02x:%02x\n\n", ethernetHeader->ether_shost[0],ethernetHeader->ether_shost[1],ethernetHeader->ether_shost[2],ethernetHeader->ether_shost[3],ethernetHeader->ether_shost[4],ethernetHeader->ether_shost[5]);

}


void packetHandlerSave(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    FILE *file = fopen("sniff.txt", "a");
    const struct ether_header *ethernetHeader;
    const struct ip *ipHeader;
    struct result findPacket;
    time_t mytime = time(NULL);
    struct tm *now = localtime(&mytime);
    
    ethernetHeader = (struct ether_header *)packet;
    ipHeader = (struct ip *)(packet + sizeof(struct ether_header));

    if(file == NULL){
        printf("error: not create file");
        exit(0);
    }

    char srcIP[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ipHeader->ip_src), findPacket.ipSender, sizeof(srcIP));
    inet_ntop(AF_INET, &(ipHeader->ip_dst), findPacket.ipRecipient, sizeof(srcIP));

    checkPort(ipHeader, packet, &findPacket);

    fprintf(file, "[%d:%d:%d] [%s] packet find:\n packet len = %d bites\n packet ip sender = %s:%d\n packet ip recipient = %s:%d\n", now->tm_hour, now->tm_min, now->tm_sec, findPacket.protocol,  pkthdr->len, findPacket.ipSender, findPacket.portSender, findPacket.ipRecipient, findPacket.portRecipient);
    fprintf(file, " MAC recipient = %02x:%02x:%02x:%02x:%02x:%02x\n", ethernetHeader->ether_dhost[0],ethernetHeader->ether_dhost[1],ethernetHeader->ether_dhost[2],ethernetHeader->ether_dhost[3],ethernetHeader->ether_dhost[4],ethernetHeader->ether_dhost[5]);
    fprintf(file, " MAC sender = %02x:%02x:%02x:%02x:%02x:%02x\n\n", ethernetHeader->ether_shost[0],ethernetHeader->ether_shost[1],ethernetHeader->ether_shost[2],ethernetHeader->ether_shost[3],ethernetHeader->ether_shost[4],ethernetHeader->ether_shost[5]);
    fclose(file);

    printf("[%d:%d:%d] [%s] packet find:\n packet len = %d bites\n packet ip sender = %s:%d\n packet ip recipient = %s:%d\n", now->tm_hour, now->tm_min, now->tm_sec, findPacket.protocol,  pkthdr->len, findPacket.ipSender, findPacket.portSender, findPacket.ipRecipient, findPacket.portRecipient);
    printf(" MAC recipient = %02x:%02x:%02x:%02x:%02x:%02x\n", ethernetHeader->ether_dhost[0],ethernetHeader->ether_dhost[1],ethernetHeader->ether_dhost[2],ethernetHeader->ether_dhost[3],ethernetHeader->ether_dhost[4],ethernetHeader->ether_dhost[5]);
    printf(" MAC sender = %02x:%02x:%02x:%02x:%02x:%02x\n\n", ethernetHeader->ether_shost[0],ethernetHeader->ether_shost[1],ethernetHeader->ether_shost[2],ethernetHeader->ether_shost[3],ethernetHeader->ether_shost[4],ethernetHeader->ether_shost[5]);

}


void initSniffer(char name[size_32], int status){
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
    
    switch(status){
        case 0:
            pcap_loop(handle, 0, packetHandlerNotSave, NULL);
            break;
        case 1:
            pcap_loop(handle, 0, packetHandlerSave, NULL);
            break;

        default:
            printf("error");
    }
}


#undef size_1024
#undef size_512
#undef size_256
#undef size_128
#undef size_64
#undef size_32