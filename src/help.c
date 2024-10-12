#include "help.h"
#include <stdio.h>

void printHelp(void){
    printf("hello bro, command:\n");
    printf("-h, --help = main command's\n");
    printf("-с <name network monitor>, --start <name network monitor> = start program\n");
    printf("-s <sample>, --sample <sample> = sniffing template\n");
    printf("-f, --find = find network monitors");
}