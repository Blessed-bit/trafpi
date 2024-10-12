#include "findMonitor.h"

void findMonitor(){
    FILE *fp;
    char buffer[1024];
    fp = popen("ls /sys/class/net", "r");

    while (fgets(buffer, 1024, fp) != NULL) {
        printf("%s", buffer);
    }

    fclose(fp);
}