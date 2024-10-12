Trafpi Sniffer:
Description

This is a network sniffer project that captures and analyzes network packets. It is designed to be used for educational purposes and can be used to learn about network protocols and packet analysis.
Features

    Captures and analyzes network packets
    Supports multiple network protocols (e.g. TCP, UDP, ICMP)
    Provides detailed information about each packet (e.g. source and destination IP addresses, port numbers, packet length)
    Allows users to filter packets based on specific criteria (e.g. protocol, source IP address)
    Supports multiple network interfaces (e.g. wlan0, eth0)
    Provides a command-line interface to start the packet capture process and find available network interfaces

Usage

To use the network sniffer, follow these steps:

    Compile the project using a C compiler (e.g. gcc)
    Run the network sniffer using the command-line interface (e.g. ./sniffer -c wlan0)
    Select the network interface to capture packets from (e.g. wlan0, eth0)
    Start the packet capture process

Commands

    -h, --help: displays the help menu
    -c <name network monitor>, --start <name network monitor>: starts the packet capture process on the specified network interface
    -f, --find: finds available network interfaces
    -s <sample>, --sample <sample>: sniffs a template (not implemented)

Files

    snifer.h: header file for the network sniffer project
    snifer.c: implementation file for the network sniffer project
    help.h: header file for the help menu
    help.c: implementation file for the help menu

License

The network sniffer project is licensed under the MIT License.
Contributing

Contributions to the network sniffer project are welcome. If you would like to contribute, please fork the repository and submit a pull request.
Acknowledgments

The network sniffer project was inspired by the following projects:

    tcpdump: a command-line packet capture and analysis tool
    Wireshark: a graphical packet capture and analysis tool
