# winsock_packetcapture
Alpha version of packet capture without using proxy using Winsock

## Alpha Release
This program can receive all IP packets of the specified interface by specifying SIO_RCVALL with WSAIoctl function on WinSock 's raw socket (Raw Socket). If NIC supports promiscuous mode, it will activate promiscuous mode.

## How to Use
It only supports Windows. Download the binary from the release list and run it with administrator privileges.