#include "src/snifer.h"
#include "src/help.h"
#include <string.h>

int main(int argc, char* argv[]) {
    if(argc == 1){
        printf("help");
    } 

    if(argc >= 2 && strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0){
        printHelp();
    }

    if(argc >= 2 && strcmp(argv[1], "-c") == 0 || strcmp(argv[1], "--start") == 0){
        if (argc >= 3){
            initSniffer(argv[2]);
        }else{
            printf("please write system monitor\n<wlan0>");
        }
    }

    if(argc >= 2 && strcmp(argv[1], "-f") == 0 || strcmp(argv[1], "--find") == 0){
        findMonitor();
    }

    return 0;

}