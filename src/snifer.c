#include "snifer.h"

void packetHandler(u_char *userData, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    const struct ether_header *ethernetHeader;
    const struct ip *ipHeader;
    
    ethernetHeader = (struct ether_header *)packet;
    ipHeader = (struct ip *)(packet + sizeof(struct ether_header));
    char srcIP[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &(ipHeader->ip_src), srcIP, sizeof(srcIP));

    printf("packet find: %d bites\npacket ip = %s\n\n", pkthdr->len, srcIP);

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

void findMonitor(){
    FILE *fp;
    char buffer[1024];
    fp = popen("ls /sys/class/net", "r");

    while (fgets(buffer, 1024, fp) != NULL) {
        printf("%s", buffer);
    }
}


#undef size_1024
#undef size_512
#undef size_256
#undef size_128
#undef size_64
#undef size_32