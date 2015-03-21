#include "stdafx.h"
#include "function.h"



char *netcard_name;
char errbuf[PCAP_ERRBUF_SIZE];
pcap_if_t *dev;
pcap_if_t *all_devs;
pcap_t *adhandle;
pcap_dumper_t *dumpfile;  
char file_path[512];                         //  文件保存路径  
char file_name[64]; 
struct pktcount num_packet;
char *pack_filter = "tcp or udp or arp or icmp or igmp";
struct bpf_program fcode;
CPtrList local_data_list;                //保存被本地化后的数据包
CPtrList net_data_list;                    //保存从网络中直接获取的数据包
int packet_index;
void YHGetNetCard(pcap_if_t **alldevs, int *num)
{
    pcap_if_t *d;
    int i=0;
    CString error_get_netcard;
    error_get_netcard.LoadString(109);
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL /* auth is not needed */, alldevs, errbuf) == -1)
    {
        //MessageBox(error_get_netcard);
        MessageBox(NULL, error_get_netcard, error_get_netcard, MB_OK);
    } else {
        for (d = *alldevs; d != NULL; d = d->next)
        {
            *num += 1;
        }
    }
}

void YHCatchStart(void)
{
    u_int net_mask=0xffffff;
    CString temp;
    if (dev != NULL)
    {
        if ((adhandle = pcap_open_live(dev->name, 65536, 1, 1000, errbuf)) != NULL)
        {
            if (pcap_datalink(adhandle) != DLT_EN10MB)
            {
                MessageBox(NULL, CString("非以太网网络！"), 0, 0);
                exit(-1);
            } else {
                if (dev->addresses != NULL)
                {
                    net_mask = ((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
                }
                
                if (pcap_compile(adhandle, &fcode, pack_filter, 1, net_mask) < 0)
                {
                    MessageBox(NULL, CString("过滤编译错误"), 0, 0);
                    //pcap_freealldevs(all_devs);
                    //exit(-1);
                 }
                if (pcap_setfilter(adhandle, &fcode) < 0)  
                {  
                    MessageBox(NULL, CString("设置过滤器错误"), 0, 0);  
                    //pcap_freealldevs(all_devs);  
                    //exit(-1);  
                } 

                CFileFind file;
                char this_time[30];
                struct tm *ltime;
                memset(file_path,0,512);  
                memset(file_name,0,64);
                if(!file.FindFile(_T("SavedData")))  
                {  
                    CreateDirectory(_T("SavedData"), NULL);  
                }  
                time_t nowtime;  
                time(&nowtime);  
                ltime=localtime(&nowtime);  
                strftime(this_time, sizeof(this_time), "%Y%m%d %H%M%S", ltime);    
                strcpy(file_path, "SavedData\\");  
                strcat(file_name, this_time);  
                strcat(file_name, ".yhs");  
                strcat(file_path, file_name);  
                dumpfile = pcap_dump_open(adhandle, file_path);  
                if(dumpfile == NULL)  
                {  
                    MessageBox(NULL, CString("文件创建错误！"), 0, 0);  
                }  
                //MessageBox(NULL, CString("以太网网络！"), 0, 0);

            }
        } else {
    
            MessageBox(NULL, CString("捕获设置失败"), 0, 0);
        }/**/
    } else {
        MessageBox(NULL, CString("请先完成网卡设置"), 0, 0);
        //exit(0);
    }
    
}

DWORD WINAPI YHCatchThread(LPVOID lpParameter)
{
    YHCatchStart();
    int res, nItem ;
    struct tm *ltime;
    CString timestr, buf, srcMac, destMac;
    time_t local_tv_sec;
    struct pcap_pkthdr *header;                                      //数据包头
    const u_char *pkt_data = NULL, *pData=NULL;     //网络中收到的字节流数据
    u_char *ppkt_data;
    CYHSnifferDlg *pthis = (CYHSnifferDlg*) lpParameter;

    if(NULL == pthis->catch_handle)
    {
        MessageBox(NULL, _T("线程句柄错误"), _T("提示"), MB_OK);
        return -1;
    }

    while((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0)
    {
        if (res == 0)//超时
        {
            continue;
        }            
            
        struct datapkt *data = (struct datapkt*)malloc(sizeof(struct datapkt));        
        memset(data,0,sizeof(struct datapkt));

        if (NULL == data)
        {
            MessageBox(NULL, _T("空间已满，无法接收新的数据包"), _T("Error"), MB_OK);
            return -1;
        }
        
        if(YHAnalyzeFrame(pkt_data, data, &num_packet) < 0)
        {
            continue;
        }
            
        //将数据包保存到打开的文件中
        if(dumpfile != NULL)
        {
            pcap_dump((unsigned char*)dumpfile, header, pkt_data);
        }
        pthis->YHUpdatePacket();

        ppkt_data = (u_char*)malloc(header->len);
        memcpy(ppkt_data,pkt_data,header->len);

        local_data_list.AddTail(data);
        net_data_list.AddTail(ppkt_data);

        data->len = header->len;                                //链路中收到的数据长度
        local_tv_sec = header->ts.tv_sec;
        ltime = localtime(&local_tv_sec);
        data->time[0] = ltime->tm_year+1900;
        data->time[1] = ltime->tm_mon+1;
        data->time[2] = ltime->tm_mday;
        data->time[3] = ltime->tm_hour;
        data->time[4] = ltime->tm_min;
        data->time[5] = ltime->tm_sec;

        /*为新接收到的数据包在listControl中新建一个item*/
        buf.Format(_T("%d"), packet_index);
        nItem = pthis->list.InsertItem(packet_index, buf);

        /*显示时间戳*/
        timestr.Format(_T("%d/%d/%d  %d:%d:%d"),data->time[0],
            data->time[1],data->time[2],data->time[3],data->time[4],data->time[5]);
        pthis->list.SetItemText(nItem,1,timestr);

        /*获得源IP*/
        buf.Empty();
        if(0x0806== data->ethh->type)
        {
            buf.Format(_T("%d.%d.%d.%d"),data->arph->ar_srcip[0],
                data->arph->ar_srcip[1],data->arph->ar_srcip[2],data->arph->ar_srcip[3]);            
        }else if(0x0800 == data->ethh->type) {
            struct  in_addr in;
            in.S_un.S_addr = data->iph->saddr;
            buf = CString(inet_ntoa(in));
        }else if(0x86dd ==data->ethh->type ){
            int n;
            for(n=0;n<8;n++)
            {            
                if(n<=6)
                    buf.AppendFormat(_T("%02x:"),data->iph6->saddr[n]);        
                else
                    buf.AppendFormat(_T("%02x"),data->iph6->saddr[n]);        
            }
        }
        pthis->list.SetItemText(nItem,2,buf);

        /*获得目的IP*/
        buf.Empty();
        if(0x0806 == data->ethh->type)
        {
            buf.Format(_T("%d.%d.%d.%d"),data->arph->ar_destip[0],
                data->arph->ar_destip[1],data->arph->ar_destip[2],data->arph->ar_destip[3]);            
        }else if(0x0800 == data->ethh->type){
            struct  in_addr in;
            in.S_un.S_addr = data->iph->daddr;
            buf = CString(inet_ntoa(in));
        }else if(0x86dd ==data->ethh->type ){
            int n;
            for(n=0;n<8;n++)
            {            
                if(n<=6)
                    buf.AppendFormat(_T("%02x:"),data->iph6->daddr[n]);        
                else
                    buf.AppendFormat(_T("%02x"),data->iph6->daddr[n]);        
            }
        }
        pthis->list.SetItemText(nItem,3,buf);

        /*获得协议*/
        pthis->list.SetItemText(nItem,4,CString(data->pktType));

        /*显示源MAC*/
        buf.Empty();
        buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"),data->ethh->src[0],data->ethh->src[1],
                            data->ethh->src[2],data->ethh->src[3],data->ethh->src[4],data->ethh->src[5]);
        pthis->list.SetItemText(nItem,5,buf);

        /*显示目的MAC*/
        buf.Empty();
        buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"),data->ethh->dest[0],data->ethh->dest[1],
                            data->ethh->dest[2],data->ethh->dest[3],data->ethh->dest[4],data->ethh->dest[5]);
        pthis->list.SetItemText(nItem,6,buf);

        /*显示长度*/
        buf.Empty();
        buf.Format(_T("%d"),data->len);
        pthis->list.SetItemText(nItem,7,buf);

        /*对包计数*/
        packet_index ++;
    }


    return 1;

}

/*pkt为网络中捕获的包，data为要存为本机上的数据*/

/*分析链路层*/
int YHAnalyzeFrame(const u_char * pkt,struct datapkt * data,struct pktcount *npacket)
{
        int i;
        struct ethhdr *ethh = (struct ethhdr*)pkt;
        data->ethh = (struct ethhdr*)malloc(sizeof(struct ethhdr));
        if(NULL == data->ethh)
            return -1;
    
        /*目的MAC和源MAC*/
        for(i=0;i<6;i++)
        {
            data->ethh->dest[i] = ethh->dest[i];
            data->ethh->src[i] = ethh->src[i];
        }
    
        npacket->n_sum++;

        /*由于网络字节顺序原因，需要对齐*/
        data->ethh->type = ntohs(ethh->type);

        //处理ARP还是IP包？
        switch(data->ethh->type)
        {
            case 0x0806:
                return YHAnalyzeArp((u_char*)pkt+14,data,npacket);      //mac 头大小为14
                break;
            case 0x0800:                
                return YHAnalyzeIp((u_char*)pkt+14,data,npacket);
                break;
            case 0x86dd:        
                return YHAnalyzeIp6((u_char*)pkt+14,data,npacket);            
                return -1;
                break;
            default:
                npacket->n_other++;
                return -1;
                break;
        }
        return 1;
}

/*分析网络层：ARP*/
int YHAnalyzeArp(const u_char* pkt,datapkt *data,struct pktcount *npacket)
{
    int i;
    struct arphdr *arph = (struct arphdr*)pkt;
    data->arph = (struct arphdr*)malloc(sizeof(struct arphdr));
    
    if(NULL == data->arph )
        return -1;
    
    //复制IP及MAC
    for(i=0;i<6;i++)
    {
        if(i<4)
        {
            data->arph->ar_destip[i] = arph->ar_destip[i];
            data->arph->ar_srcip[i] = arph->ar_srcip[i];
        }
        data->arph->ar_destmac[i] = arph->ar_destmac[i];
        data->arph->ar_srcmac[i]= arph->ar_srcmac[i];
    }

    data->arph->ar_hln = arph->ar_hln;
    data->arph->ar_hrd = ntohs(arph->ar_hrd);
    data->arph->ar_op = ntohs(arph->ar_op);
    data->arph->ar_pln = arph->ar_pln;
    data->arph->ar_pro = ntohs(arph->ar_pro);

    strcpy(data->pktType,"ARP");
    npacket->n_arp++;
    return 1;
}

/*分析网络层：IP*/
int YHAnalyzeIp(const u_char* pkt,datapkt *data,struct pktcount *npacket)
{
    int i;
    struct iphdr *iph = (struct iphdr*)pkt;
    data->iph = (struct iphdr*)malloc(sizeof(struct iphdr));
    
    if(NULL == data->iph)
        return -1;
    data->iph->check = iph->check;
    npacket->n_ip++;
    
    data->iph->saddr = iph->saddr;
    data->iph->daddr = iph->daddr;

    data->iph->frag_off = iph->frag_off;
    data->iph->id = iph->id;
    data->iph->proto = iph->proto;
    data->iph->tlen = ntohs(iph->tlen);
    data->iph->tos = iph->tos;
    data->iph->ttl = iph->ttl;
    data->iph->ihl = iph->ihl;
    data->iph->version = iph->version;
    //data->iph->ver_ihl= iph->ver_ihl;
    data->iph->op_pad = iph->op_pad;

    int iplen = iph->ihl*4;                            //ip头长度
    switch(iph->proto)
    {
        case PROTO_ICMP:
            return YHAnalyzeIcmp((u_char*)iph+iplen,data,npacket);
            break;
        case PROTO_TCP:
            return YHAnalyzeTcp((u_char*)iph+iplen,data,npacket);
            break;
        case PROTO_UDP:
            return YHAnalyzeUdp((u_char*)iph+iplen,data,npacket);
            break;
        default :
            return-1;
            break;
    }
    return 1;
}

/*分析网络层：IPV6*/
int YHAnalyzeIp6(const u_char* pkt,datapkt *data,struct pktcount *npacket)
{
    int i;
    struct iphdr6 *iph6 = (struct iphdr6*)pkt;
    data->iph6 = (struct iphdr6*)malloc(sizeof(struct iphdr6));
    
    if(NULL == data->iph6)
        return -1;

    npacket->n_ip6++;
    
    data->iph6->version = iph6->version;
    data->iph6->flowtype = iph6->flowtype;
    data->iph6->flowid = iph6->flowid;
    data->iph6->plen = ntohs(iph6->plen);
    data->iph6->nh = iph6->nh;
    data->iph6->hlim =iph6->hlim;

    for(i=0;i<16;i++)
    {
        data->iph6->saddr[i] = iph6->saddr[i];
        data->iph6->daddr[i] = iph6->daddr[i];
    }
    
    switch(iph6->nh)
    {
        case 0x3a:                    
            return YHAnalyzeIcmp6((u_char*)iph6+40,data,npacket);
            break;
        case 0x06:
            return YHAnalyzeTcp((u_char*)iph6+40,data,npacket);
            break;
        case 0x11:
            return YHAnalyzeUdp((u_char*)iph6+40,data,npacket);
            break;
        default :
            return-1;
            break;
    }
    //npacket->n_ip6++;
    //strcpy(data->pktType,"IPV6");
    return 1;
}
    
/*分析传输层：ICMP*/
int YHAnalyzeIcmp(const u_char* pkt,datapkt *data,struct pktcount *npacket)
{
    struct icmphdr* icmph = (struct icmphdr*)pkt;
    data->icmph = (struct icmphdr*)malloc(sizeof(struct icmphdr));
    
    if(NULL == data->icmph)
        return -1;

    data->icmph->chksum = icmph->chksum;
    data->icmph->code = icmph->code;
    data->icmph->seq =icmph->seq;
    data->icmph->type = icmph->type;
    strcpy(data->pktType,"ICMP");
    npacket->n_icmp++;
    return 1;
}

/*分析传输层：ICMPv6*/
int YHAnalyzeIcmp6(const u_char* pkt,datapkt *data,struct pktcount *npacket)
{
    int i;
    struct icmphdr6* icmph6 = (struct icmphdr6*)pkt;
    data->icmph6 = (struct icmphdr6*)malloc(sizeof(struct icmphdr6));
    
    if(NULL == data->icmph6)
        return -1;

    data->icmph6->chksum = icmph6->chksum;
    data->icmph6->code = icmph6->code;
    data->icmph6->seq =icmph6->seq;
    data->icmph6->type = icmph6->type;
    data->icmph6->op_len = icmph6->op_len;
    data->icmph6->op_type = icmph6->op_type;
    for(i=0;i<6;i++)
    {
        data->icmph6->op_ethaddr[i] = icmph6->op_ethaddr[i];
    }
    strcpy(data->pktType,"ICMPv6");
    npacket->n_icmp6++;
    return 1;
}

/*分析传输层：TCP*/
int YHAnalyzeTcp(const u_char* pkt,datapkt *data,struct pktcount *npacket)
{
    struct tcphdr *tcph = (struct tcphdr*)pkt;
    data->tcph = (struct tcphdr*)malloc(sizeof(struct tcphdr));
    if(NULL == data->tcph)
        return -1;
    
    data->tcph->ack_seq = tcph->ack_seq;
    data->tcph->check = tcph->check;
    
    data->tcph->doff = tcph->doff;
    data->tcph->res1 = tcph->res1;
    data->tcph->cwr = tcph->cwr;
    data->tcph->ece = tcph->ece;
    data->tcph->urg = tcph->urg;
    data->tcph->ack = tcph->ack;
    data->tcph->psh = tcph->psh;
    data->tcph->rst = tcph->rst;
    data->tcph->syn = tcph->syn;
    data->tcph->fin = tcph->fin;
    //data->tcph->doff_flag = tcph->doff_flag;

    data->tcph->dport = ntohs(tcph->dport);
    data->tcph->seq = tcph->seq;
    data->tcph->sport = ntohs(tcph->sport);
    data->tcph->urg_ptr = tcph->urg_ptr;
    data->tcph->window= tcph->window;
    data->tcph->opt = tcph->opt;
    
    /////////////////////*不要忘记http分支*/////////////////////////
    if(ntohs(tcph->dport) == 80 || ntohs(tcph->sport)==80)
    {
        npacket->n_http++;
        strcpy(data->pktType,"HTTP");
    }
    else{
        npacket->n_tcp++;
        strcpy(data->pktType,"TCP");    
    }
    return 1;
}

/*分析传输层：UDP*/
int YHAnalyzeUdp(const u_char* pkt,datapkt *data,struct pktcount *npacket)
{
    struct udphdr* udph = (struct udphdr*)pkt;
    data->udph = (struct udphdr*)malloc(sizeof(struct udphdr));
    if(NULL == data->udph )
        return -1;

    data->udph->check = udph->check;
    data->udph->dport = ntohs(udph->dport);
    data->udph->len = ntohs(udph->len);
    data->udph->sport = ntohs(udph->sport);

    strcpy(data->pktType,"UDP");
    npacket->n_udp++;
    return 1;
}

void YHPrintPacketHex(const u_char* pkt, int size_pkt, CString *buf)
{
    int i = 0,j = 0, rowcount;
    u_char ch;
     
   
 
    for(i= 0; i < size_pkt; i += 16)
    {
        buf->AppendFormat(_T("%04x: "), (u_int)i);
        rowcount = (size_pkt - i) > 16 ? 16 : (size_pkt - i);                         
 
        for(j = 0; j < rowcount; j++)
        {
            buf->AppendFormat(_T("%02x  "), (u_int)pkt[i+j]);
        }
                   
          //不足16，用空格补足
        if(rowcount < 16)
            for(j = rowcount; j < 16; j++)
                buf->AppendFormat(_T("     "));  
 
        buf->Append(_T("\t\t"));
        for(j = 0; j < rowcount; j++)
        {
            ch = pkt[i+j];
            ch = isprint(ch) ? ch : '.';
            buf->AppendFormat(_T("%c"), ch);
        }
 
        buf->Append(_T("\r\n"));
        if(rowcount < 16)
            return;
    }
}