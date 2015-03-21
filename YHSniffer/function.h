#ifndef FUNCTION_H
#define FUNCTION_H

#include "pcap.h"
#include "protocol.h"
#include "YHSnifferDlg.h"
#include "YHSniffer.h"
//#include "resource.h"

void YHGetNetCard(pcap_if_t **alldevs, int *num);
void YHCatchStart(void);
DWORD WINAPI YHCatchThread(LPVOID lpParameter);
void YHFilter(void);

void YHGetInfo(void);
int YHAnalyzeFrame(const u_char * pkt,struct datapkt * data,struct pktcount *npacket);
int YHAnalyzeArp(const u_char* pkt,datapkt *data,struct pktcount *npacket);
int YHAnalyzeIp(const u_char* pkt,datapkt *data,struct pktcount *npacket);
int YHAnalyzeIp6(const u_char* pkt,datapkt *data,struct pktcount *npacket);
int YHAnalyzeIcmp(const u_char* pkt,datapkt *data,struct pktcount *npacket);
int YHAnalyzeIcmp6(const u_char* pkt,datapkt *data,struct pktcount *npacket);
int YHAnalyzeTcp(const u_char* pkt,datapkt *data,struct pktcount *npacket);
int YHAnalyzeUdp(const u_char* pkt,datapkt *data,struct pktcount *npacket);
void YHPrintPacketHex(const u_char* pkt, int size_pkt, CString *buf);

#endif