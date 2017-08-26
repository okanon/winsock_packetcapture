#include "putils.h"
#include <stdio.h>

void PrintHexDump(DWORD length, PBYTE buffer) {

	DWORD i, count, index;
	CHAR rgbDigits[] = "0123456789abcdef";
	CHAR rgbLine[100];
	char cbLine;

	for (index = 0; length; length -= count, buffer += count, index += count) {
		count = (length > 16) ? 16 : length;

		sprintf_s(rgbLine, sizeof(rgbLine), "%4.4x ", index);
		cbLine = 5;

		for (i = 0; i<count; i++) {
			rgbLine[cbLine++] = rgbDigits[buffer[i] >> 4];
			rgbLine[cbLine++] = rgbDigits[buffer[i] & 0x0f];
			if (i == 7) {
				rgbLine[cbLine++] = ':';
			}
			else {
				rgbLine[cbLine++] = ' ';
			}
		}

		for (; i < 16; i++) {
			rgbLine[cbLine++] = ' ';
			rgbLine[cbLine++] = ' ';
			rgbLine[cbLine++] = ' ';
		}

		rgbLine[cbLine++] = ' ';

		for (i = 0; i < count; i++) {
			if (buffer[i] < 32 || buffer[i] > 126) {
				rgbLine[cbLine++] = '.';
			}
			else {
				rgbLine[cbLine++] = buffer[i];
			}
		}
		rgbLine[cbLine++] = 0;
		printf("%s\n", rgbLine);
	}
} // end PrintHexDump


  //////////////////////////////////////////////////////////////////////


VOID PrintTCPRow(PMIB_TCPROW pTcpRow) {

	char* lpState = NULL;
	MY_TCPROW MyTcpRow;

	MyTcpRow.dwState = pTcpRow->dwState;
	MyTcpRow.LocalAddr.S_un.S_addr = pTcpRow->dwLocalAddr;
	MyTcpRow.sLocalPort = ntohs(pTcpRow->dwLocalPort & 0xFF00);
	MyTcpRow.RemoteAddr.S_un.S_addr =
		MIB_TCP_STATE_LISTEN == MyTcpRow.dwState ?
		0 : pTcpRow->dwRemoteAddr;
	MyTcpRow.sRemotePort =
		MIB_TCP_STATE_LISTEN == MyTcpRow.dwState ?
		0 : ntohs(pTcpRow->dwRemotePort & 0xFF00);
	printf("%s:%d\t\t%s:%d ***",
		inet_ntoa(MyTcpRow.LocalAddr), MyTcpRow.sLocalPort,
		inet_ntoa(MyTcpRow.RemoteAddr), MyTcpRow.sRemotePort);

	// TCP State
	switch (pTcpRow->dwState) {
	case MIB_TCP_STATE_CLOSED: lpState = "CLOSED"; break;
	case MIB_TCP_STATE_LISTEN: lpState = "LISTENING"; break;
	case MIB_TCP_STATE_SYN_SENT: lpState = "SIN_SENT"; break;
	case MIB_TCP_STATE_SYN_RCVD: lpState = "SYN_RCVD"; break;
	case MIB_TCP_STATE_ESTAB: lpState = "ESTABLISHED"; break;
	case MIB_TCP_STATE_FIN_WAIT1: lpState = "FIN_WAIT1"; break;
	case MIB_TCP_STATE_FIN_WAIT2: lpState = "FIN_WAIT2"; break;
	case MIB_TCP_STATE_CLOSE_WAIT: lpState = "CLOSE_WAIT"; break;
	case MIB_TCP_STATE_CLOSING: lpState = "CLOSING"; break;
	case MIB_TCP_STATE_LAST_ACK: lpState = "LAST_ACK"; break;
	case MIB_TCP_STATE_TIME_WAIT: lpState = "TIME_WAIT"; break;
	case MIB_TCP_STATE_DELETE_TCB: lpState = "DELETE_TCP"; break;
	default: lpState = "Unknown";
		break;
	}
	printf("\t%s\n", lpState);
}


//////////////////////////////////////////////////////////////////////////


VOID PrintIPHeader(IP_HEADER ip_header) {

	char *lpIP;

	printf("Version: %u\n", ip_header.ip_v); //version. This is always 4.
	printf("Header Length: %u * 4\n", ip_header.ip_hl);
	// header length is (ip_hl * 4) bytes
	printf("Type of Service: %u\n", ip_header.ip_tos); // type of service
	printf("Total Length: %u\n", ntohs(ip_header.ip_len)); // Total length
	printf("Identification: %u\n", ntohs(ip_header.ip_id)); // Identification
	printf("Flags: %u\n", ntohs(ip_header.ip_off));
	printf("Time To Live: %u\n", ip_header.ip_ttl);
	printf("Protocol: %u\n", ip_header.ip_p);
	printf("Checksum: %u\n", ntohs(ip_header.ip_sum));
	lpIP = inet_ntoa(ip_header.ip_src);
	printf("IP src: %s\n", lpIP);
	lpIP = inet_ntoa(ip_header.ip_dst);
	printf("IP dst: %s\n", lpIP);
}