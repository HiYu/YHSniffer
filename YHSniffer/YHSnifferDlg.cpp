
// YHSnifferDlg.cpp : implementation file
//

#include "stdafx.h"
#include "YHSniffer.h"
#include "YHSnifferDlg.h"
#include "afxdialogex.h"
#include "SetDialog.h"
#include "FilterDialog.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

extern pcap_if_t *dev;
extern int packet_index;
// CAboutDlg dialog used for App About
extern CPtrList local_data_list;                //保存被本地化后的数据包
extern CPtrList net_data_list;                    //保存从网络中直接获取的数据包
class CAboutDlg : public CDialogEx
{
public:
    CAboutDlg();

// Dialog Data
    enum { IDD = IDD_ABOUTBOX };

    protected:
    virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV supprot

// Implementation
protected:
    DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CYHSnifferDlg dialog




CYHSnifferDlg::CYHSnifferDlg(CWnd* pParent /*=NULL*/)
    : CDialogEx(CYHSnifferDlg::IDD, pParent)
{
    m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CYHSnifferDlg::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_LIST, list);
    DDX_Control(pDX, IDC_EDIT_NET_CARD, netcard_edit);
    DDX_Control(pDX, IDC_EDIT_HEX, edit);
    DDX_Control(pDX, IDC_TREE, tree);
}

BEGIN_MESSAGE_MAP(CYHSnifferDlg, CDialogEx)
    ON_WM_SYSCOMMAND()
    ON_WM_PAINT()
    ON_WM_QUERYDRAGICON()
    ON_COMMAND(ID_NETCARD, &CYHSnifferDlg::OnNetcard)
    ON_COMMAND(ID_FLITER, &CYHSnifferDlg::OnFliter)
    ON_COMMAND(ID_BEGIN, &CYHSnifferDlg::OnBegin)
    ON_COMMAND(ID_STOP, &CYHSnifferDlg::OnStop)
    ON_NOTIFY(NM_DBLCLK, IDC_LIST, &CYHSnifferDlg::OnNMDblclkList)
    ON_COMMAND(ID_QUIT, &CYHSnifferDlg::OnQuit)
END_MESSAGE_MAP()


// CYHSnifferDlg message handlers

BOOL CYHSnifferDlg::OnInitDialog()
{
    CDialogEx::OnInitDialog();

    // Add "About..." menu item to system menu.

    // IDM_ABOUTBOX must be in the system command range.
    ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
    ASSERT(IDM_ABOUTBOX < 0xF000);

    CMenu* pSysMenu = GetSystemMenu(FALSE);
    if (pSysMenu != NULL)
    {
        BOOL bNameValid;
        CString strAboutMenu;
        CString str_num, str_time, str_sour_ip, str_dest_ip,str_prot, str_len, str_sour_mac, str_dest_mac;
        str_num.LoadString(IDS_STR_NUM);
        str_time.LoadString(IDS_STR_TIME);
        str_sour_ip.LoadString(IDS_STR_SOUR_IP);
        str_dest_ip.LoadString(IDS_STR_DEST_IP);
        str_prot.LoadString(IDS_STR_PROT);
        str_len.LoadString(IDS_STR_LEN);
        str_sour_mac.LoadString(IDS_STR_SOUR_MAC);
        str_dest_mac.LoadString(IDS_STR_DEST_MAC);
        bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
        ASSERT(bNameValid);
        if (!strAboutMenu.IsEmpty())
        {
            pSysMenu->AppendMenu(MF_SEPARATOR);
            pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
        }
        list.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);
        list.InsertColumn(0, str_num, 0, 60);
        list.InsertColumn(1, str_time, 0, 130);
        list.InsertColumn(2, str_sour_ip, 0, 100);
        list.InsertColumn(3, str_dest_ip, 0, 100);
        list.InsertColumn(4, str_prot, 0,60);
        list.InsertColumn(5, str_sour_mac, 0, 150);
        list.InsertColumn(6, str_dest_mac, 0, 150);
        list.InsertColumn(7, str_len, 0, 75);
    }

    // Set the icon for this dialog.  The framework does this automatically
    //  when the application's main window is not a dialog
    SetIcon(m_hIcon, TRUE);            // Set big icon
    SetIcon(m_hIcon, FALSE);        // Set small icon

    //ShowWindow(SW_MINIMIZE);

    // TODO: Add extra initialization here

    return TRUE;  // return TRUE  unless you set the focus to a control
}

void CYHSnifferDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
    if ((nID & 0xFFF0) == IDM_ABOUTBOX)
    {
        CAboutDlg dlgAbout;
        dlgAbout.DoModal();
    }
    else
    {
        CDialogEx::OnSysCommand(nID, lParam);
    }
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CYHSnifferDlg::OnPaint()
{
    if (IsIconic())
    {
        CPaintDC dc(this); // device context for painting

        SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

        // Center icon in client rectangle
        int cxIcon = GetSystemMetrics(SM_CXICON);
        int cyIcon = GetSystemMetrics(SM_CYICON);
        CRect rect;
        GetClientRect(&rect);
        int x = (rect.Width() - cxIcon + 1) / 2;
        int y = (rect.Height() - cyIcon + 1) / 2;

        // Draw the icon
        dc.DrawIcon(x, y, m_hIcon);
    }
    else
    {
        CDialogEx::OnPaint();
    }
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CYHSnifferDlg::OnQueryDragIcon()
{
    return static_cast<HCURSOR>(m_hIcon);
}



void CYHSnifferDlg::OnNetcard()
{
    // TODO: Add your command handler code here
    CSetDialog set_dialog;
    set_dialog.DoModal();
}


void CYHSnifferDlg::OnFliter()
{
    // TODO: Add your command handler code here
    CFilterDialog filter_dialog;
    filter_dialog.DoModal();

}


void CYHSnifferDlg::OnBegin()
{
    // TODO: Add your command handler code here
    LPDWORD threadCap = NULL;
    packet_index = 1;
    catch_handle = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)YHCatchThread, this, 0, threadCap);
    if (catch_handle != NULL)
    {
        if (dev != NULL)
        {
            GetDlgItem(IDC_EDIT_NET_CARD)->SetWindowText( CString(dev->name));
        } else {
        
        }
    } else {
        int code = GetLastError();  
        CString str;  
        str.Format(_T("创建线程错误，代码为%d."), code);  
        MessageBox(str); 
    }    
}


int CYHSnifferDlg::YHUpdateEdit(int index)
{
    POSITION localpos,netpos;
    localpos = local_data_list.FindIndex(index);
    netpos = net_data_list.FindIndex(index);

    struct datapkt* local_data = (struct datapkt*)(local_data_list.GetAt(localpos));
    u_char * net_data = (u_char*)(net_data_list.GetAt(netpos));

    CString buf;
    YHPrintPacketHex(net_data,local_data->len,&buf);
    this->edit.SetWindowText(buf);
    return 1;
}

void CYHSnifferDlg::YHUpdatePacket(void)
{
    extern struct pktcount num_packet;
    CString pack_stat;//包统计数据列表
    pack_stat.AppendFormat(_T(" IPv4:%d  "), num_packet.n_ip);
    pack_stat.AppendFormat(_T(" IPv6:%d  "), num_packet.n_ip6);
    pack_stat.AppendFormat(_T(" ARP:%d  "), num_packet.n_arp);
    pack_stat.AppendFormat(_T(" ICMP:%d  "), num_packet.n_icmp);
    pack_stat.AppendFormat(_T(" ICMPv6:%d  "), num_packet.n_icmp6);
    pack_stat.AppendFormat(_T(" TCP:%d  "), num_packet.n_tcp);
    pack_stat.AppendFormat(_T(" UDP:%d  "), num_packet.n_udp);
    pack_stat.AppendFormat(_T(" HTTP:%d  "), num_packet.n_http);
    pack_stat.AppendFormat(_T(" 其他:%d  "), num_packet.n_other);
    GetDlgItem(IDC_EDIT_PROT_STAT)->SetWindowTextW(pack_stat);
}

void CYHSnifferDlg::OnStop()
{
    // TODO: Add your command handler code here
    if(NULL == this->catch_handle)
    {
        MessageBox(_T("捕获程序已经停止"));
    }
        
    if(TerminateThread(this->catch_handle, -1) == 0)
    {
        MessageBox(_T("关闭线程错误，请稍后重试"));
        exit(-1);
    }
    this->catch_handle = NULL;
}

void CYHSnifferDlg::OnNMDblclkList(NMHDR *pNMHDR, LRESULT *pResult)
{
    LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
    // TODO: Add your control notification handler code here
    int index;
    if (catch_handle == NULL)
    {
        index = this->list.GetHotItem();
        if(index > (local_data_list.GetCount() - 1))
        {
            exit(-1);
        }
        this->YHUpdateTree(index);
        this->YHUpdateEdit(index);
    } else {
        MessageBox(CString("正在捕获数据包，请先结束捕获"), CString("提示"), 0);
    }
    *pResult = 0;
}

//更新树形控件
int CYHSnifferDlg::YHUpdateTree(int index)
{
    POSITION localpos;
    CString str;
    int i;
    
    this->tree.DeleteAllItems();

    localpos = local_data_list.FindIndex(index);
    struct datapkt* local_data = (struct datapkt*)(local_data_list.GetAt(localpos));
    
    HTREEITEM root = this->tree.GetRootItem();
    str.Format(_T("接收到的第%d个数据包"),index+1);
    HTREEITEM data = this->tree.InsertItem(str,root);

    /*处理帧数据*/
    HTREEITEM frame = this->tree.InsertItem(_T("链路层数据"),data);
    //源MAC
    str.Format(_T("源MAC："));
    for(i=0;i<6;i++)
    {
        if(i<=4)
            str.AppendFormat(_T("%02x-"),local_data->ethh->src[i]);
        else
            str.AppendFormat(_T("%02x"),local_data->ethh->src[i]);
    }
    this->tree.InsertItem(str,frame);
    //目的MAC
    str.Format(_T("目的MAC："));
    for(i=0;i<6;i++)
    {
        if(i<=4)
            str.AppendFormat(_T("%02x-"),local_data->ethh->dest[i]);
        else
            str.AppendFormat(_T("%02x"),local_data->ethh->dest[i]);
    }
    this->tree.InsertItem(str,frame);
    //类型
    str.Format(_T("类型：0x%02x"),local_data->ethh->type);
    this->tree.InsertItem(str,frame);

    /*处理IP、ARP、IPv6数据包*/
    if(0x0806 == local_data->ethh->type)                            //ARP
    {
        HTREEITEM arp = this->tree.InsertItem(_T("ARP协议头"),data);
        str.Format(_T("硬件类型：%d"),local_data->arph->ar_hrd);
        this->tree.InsertItem(str,arp);
        str.Format(_T("协议类型：0x%02x"),local_data->arph->ar_pro);
        this->tree.InsertItem(str,arp);
        str.Format(_T("硬件地址长度：%d"),local_data->arph->ar_hln);
        this->tree.InsertItem(str,arp);
        str.Format(_T("协议地址长度：%d"),local_data->arph->ar_pln);
        this->tree.InsertItem(str,arp);
        str.Format(_T("操作码：%d"),local_data->arph->ar_op);
        this->tree.InsertItem(str,arp);

        str.Format(_T("发送方MAC："));
        for(i=0;i<6;i++)
        {
            if(i<=4)
                str.AppendFormat(_T("%02x-"),local_data->arph->ar_srcmac[i]);
            else
                str.AppendFormat(_T("%02x"),local_data->arph->ar_srcmac[i]);
        }
        this->tree.InsertItem(str,arp);

        str.Format(_T("发送方IP："),local_data->arph->ar_hln);
        for(i=0;i<4;i++)
        {
            if(i<=2)
                str.AppendFormat(_T("%d."),local_data->arph->ar_srcip[i]);
            else
                str.AppendFormat(_T("%d"),local_data->arph->ar_srcip[i]);
        }
        this->tree.InsertItem(str,arp);

        str.Format(_T("接收方MAC："),local_data->arph->ar_hln);
        for(i=0;i<6;i++)
        {
            if(i<=4)
                str.AppendFormat(_T("%02x-"),local_data->arph->ar_destmac[i]);
            else
                str.AppendFormat(_T("%02x"),local_data->arph->ar_destmac[i]);
        }
        this->tree.InsertItem(str,arp);

        str.Format(_T("接收方IP："),local_data->arph->ar_hln);
        for(i=0;i<4;i++)
        {
            if(i<=2)
                str.AppendFormat(_T("%d."),local_data->arph->ar_destip[i]);
            else
                str.AppendFormat(_T("%d"),local_data->arph->ar_destip[i]);
        }
        this->tree.InsertItem(str,arp);

    }else if(0x0800 == local_data->ethh->type){                    //IP
        
        HTREEITEM ip = this->tree.InsertItem(_T("IP协议头"),data);

        str.Format(_T("版本：%d"),local_data->iph->version);
        this->tree.InsertItem(str,ip);
        str.Format(_T("IP头长：%d"),local_data->iph->ihl);
        this->tree.InsertItem(str,ip);
        str.Format(_T("服务类型：%d"),local_data->iph->tos);
        this->tree.InsertItem(str,ip);
        str.Format(_T("总长度：%d"),local_data->iph->tlen);
        this->tree.InsertItem(str,ip);
        str.Format(_T("标识：0x%02x"),local_data->iph->id);
        this->tree.InsertItem(str,ip);
        str.Format(_T("段偏移：%d"),local_data->iph->frag_off);
        this->tree.InsertItem(str,ip);
        str.Format(_T("生存期：%d"),local_data->iph->ttl);
        this->tree.InsertItem(str,ip);
        str.Format(_T("协议：%d"),local_data->iph->proto);
        this->tree.InsertItem(str,ip);        
        str.Format(_T("头部校验和：0x%02x"),local_data->iph->check);
        this->tree.InsertItem(str,ip);

        str.Format(_T("源IP："));
        struct in_addr in;
        in.S_un.S_addr = local_data->iph->saddr;        
        str.AppendFormat(CString(inet_ntoa(in)));
        this->tree.InsertItem(str,ip);

        str.Format(_T("目的IP："));
        in.S_un.S_addr = local_data->iph->daddr;        
        str.AppendFormat(CString(inet_ntoa(in)));
        this->tree.InsertItem(str,ip);

        /*处理传输层ICMP、UDP、TCP*/
        if(1 == local_data->iph->proto )                            //ICMP
        {
            HTREEITEM icmp = this->tree.InsertItem(_T("ICMP协议头"),data);
                
            str.Format(_T("类型:%d"),local_data->icmph->type);
            this->tree.InsertItem(str,icmp);
            str.Format(_T("代码:%d"),local_data->icmph->code);
            this->tree.InsertItem(str,icmp);
            str.Format(_T("序号:%d"),local_data->icmph->seq);
            this->tree.InsertItem(str,icmp);
            str.Format(_T("校验和:%d"),local_data->icmph->chksum);
            this->tree.InsertItem(str,icmp);

        }else if(6 == local_data->iph->proto){                //TCP
            
            HTREEITEM tcp = this->tree.InsertItem(_T("TCP协议头"),data);

            str.Format(_T("  源端口:%d"),local_data->tcph->sport);
            this->tree.InsertItem(str,tcp);
            str.Format(_T("  目的端口:%d"),local_data->tcph->dport);
            this->tree.InsertItem(str,tcp);
            str.Format(_T("  序列号:0x%02x"),local_data->tcph->seq);
            this->tree.InsertItem(str,tcp);
            str.Format(_T("  确认号:%d"),local_data->tcph->ack_seq);
            this->tree.InsertItem(str,tcp);
            str.Format(_T("  头部长度:%d"),local_data->tcph->doff);

            HTREEITEM flag = this->tree.InsertItem(_T(" 标志位"),tcp);
    
            str.Format(_T("cwr %d"),local_data->tcph->cwr);
            this->tree.InsertItem(str,flag);
            str.Format(_T("ece %d"),local_data->tcph->ece);
            this->tree.InsertItem(str,flag);
            str.Format(_T("urg %d"),local_data->tcph->urg);
            this->tree.InsertItem(str,flag);
            str.Format(_T("ack %d"),local_data->tcph->ack);
            this->tree.InsertItem(str,flag);
            str.Format(_T("psh %d"),local_data->tcph->psh);
            this->tree.InsertItem(str,flag);
            str.Format(_T("rst %d"),local_data->tcph->rst);
            this->tree.InsertItem(str,flag);
            str.Format(_T("syn %d"),local_data->tcph->syn);
            this->tree.InsertItem(str,flag);
            str.Format(_T("fin %d"),local_data->tcph->fin);
            this->tree.InsertItem(str,flag);

            str.Format(_T("  紧急指针:%d"),local_data->tcph->urg_ptr);
            this->tree.InsertItem(str,tcp);
            str.Format(_T("  校验和:0x%02x"),local_data->tcph->check);
            this->tree.InsertItem(str,tcp);
            str.Format(_T("  选项:%d"),local_data->tcph->opt);
            this->tree.InsertItem(str,tcp);
        }else if(17 == local_data->iph->proto){                //UDP
            HTREEITEM udp = this->tree.InsertItem(_T("UDP协议头"),data);
                
            str.Format(_T("源端口:%d"),local_data->udph->sport);
            this->tree.InsertItem(str,udp);
            str.Format(_T("目的端口:%d"),local_data->udph->dport);
            this->tree.InsertItem(str,udp);
            str.Format(_T("总长度:%d"),local_data->udph->len);
            this->tree.InsertItem(str,udp);
            str.Format(_T("校验和:0x%02x"),local_data->udph->check);
            this->tree.InsertItem(str,udp);
        }
    }else if(0x86dd == local_data->ethh->type){        //IPv6
        HTREEITEM ip6 = this->tree.InsertItem(_T("IPv6协议头"),data);
        
        //////////////////////////////////////////////////////////////////////////////////////////
        str.Format(_T("版本:%d"),local_data->iph6->flowtype);
        this->tree.InsertItem(str,ip6);
        str.Format(_T("流类型:%d"),local_data->iph6->version);
        this->tree.InsertItem(str,ip6);
        ///////////////////////////////////////////////////////////////////////////////////////////
        str.Format(_T("流标签:%d"),local_data->iph6->flowid);
        this->tree.InsertItem(str,ip6);
        str.Format(_T("有效载荷长度:%d"),local_data->iph6->plen);
        this->tree.InsertItem(str,ip6);
        str.Format(_T("下一个首部:0x%02x"),local_data->iph6->nh);
        this->tree.InsertItem(str,ip6);
        str.Format(_T("跳限制:%d"),local_data->iph6->hlim);
        this->tree.InsertItem(str,ip6);

        str.Format(_T("源地址:"));
        int n;
        for(n=0;n<8;n++)
        {            
            if(n<=6)
                str.AppendFormat(_T("%02x:"),local_data->iph6->saddr[n]);        
            else
                str.AppendFormat(_T("%02x"),local_data->iph6->saddr[n]);        
        }    
        this->tree.InsertItem(str,ip6);

        str.Format(_T("目的地址:"));
        for(n=0;n<8;n++)
        {            
            if(n<=6)
                str.AppendFormat(_T("%02x:"),local_data->iph6->saddr[n]);        
            else
                str.AppendFormat(_T("%02x"),local_data->iph6->saddr[n]);        
        }    
        this->tree.InsertItem(str,ip6);

        /*处理传输层ICMPv6、UDP、TCP*/
        if(0x3a== local_data->iph6->nh )                            //ICMPv6
        {
            HTREEITEM icmp6 = this->tree.InsertItem(_T("ICMPv6协议头"),data);
                
            str.Format(_T("类型:%d"),local_data->icmph6->type);
            this->tree.InsertItem(str,icmp6);
            str.Format(_T("代码:%d"),local_data->icmph6->code);
            this->tree.InsertItem(str,icmp6);
            str.Format(_T("序号:%d"), local_data->icmph6->seq);
            this->tree.InsertItem(str,icmp6);
            str.Format(_T("校验和:%d"), local_data->icmph6->chksum);
            this->tree.InsertItem(str, icmp6);
            str.Format(_T("选项-类型:%d"), local_data->icmph6->op_type);
            this->tree.InsertItem(str, icmp6);
            str.Format(_T("选项-长度%d"), local_data->icmph6->op_len);
            this->tree.InsertItem(str, icmp6);
            str.Format(_T("选项-链路层地址:"));
            int i;
            for(i = 0;i < 6; i++)
            {
                if(i <= 4)                
                    str.AppendFormat(_T("%02x-"), local_data->icmph6->op_ethaddr[i]);
                else
                    str.AppendFormat(_T("%02x"), local_data->icmph6->op_ethaddr[i]);
            }
            this->tree.InsertItem(str, icmp6);

        }else if(0x06 == local_data->iph6->nh){                //TCP
            
            HTREEITEM tcp = this->tree.InsertItem(_T("TCP协议头"), data);

            str.Format(_T("  源端口:%d"), local_data->tcph->sport);
            this->tree.InsertItem(str, tcp);
            str.Format(_T("  目的端口:%d"), local_data->tcph->dport);
            this->tree.InsertItem(str,tcp);
            str.Format(_T("  序列号:0x%02x"), local_data->tcph->seq);
            this->tree.InsertItem(str, tcp);
            str.Format(_T("  确认号:%d"), local_data->tcph->ack_seq);
            this->tree.InsertItem(str,tcp);
            str.Format(_T("  头部长度:%d"), local_data->tcph->doff);

            HTREEITEM flag = this->tree.InsertItem(_T("标志位"), tcp);
    
            str.Format(_T("cwr %d"), local_data->tcph->cwr);
            this->tree.InsertItem(str, flag);
            str.Format(_T("ece %d"), local_data->tcph->ece);
            this->tree.InsertItem(str, flag);
            str.Format(_T("urg %d"), local_data->tcph->urg);
            this->tree.InsertItem(str, flag);
            str.Format(_T("ack %d"), local_data->tcph->ack);
            this->tree.InsertItem(str, flag);
            str.Format(_T("psh %d"), local_data->tcph->psh);
            this->tree.InsertItem(str, flag);
            str.Format(_T("rst %d"), local_data->tcph->rst);
            this->tree.InsertItem(str, flag);
            str.Format(_T("syn %d"), local_data->tcph->syn);
            this->tree.InsertItem(str, flag);
            str.Format(_T("fin %d"), local_data->tcph->fin);
            this->tree.InsertItem(str,flag);

            str.Format(_T("  紧急指针:%d"), local_data->tcph->urg_ptr);
            this->tree.InsertItem(str,tcp);
            str.Format(_T("  校验和:0x%02x"), local_data->tcph->check);
            this->tree.InsertItem(str, tcp);
            str.Format(_T("  选项:%d"), local_data->tcph->opt);
            this->tree.InsertItem(str,tcp);
        }else if(0x11 == local_data->iph6->nh) {                //UDP
            HTREEITEM udp = this->tree.InsertItem(_T("UDP协议头"),data);
            str.Format(_T("源端口:%d"),local_data->udph->sport);
            this->tree.InsertItem(str,udp);
            str.Format(_T("目的端口:%d"),local_data->udph->dport);
            this->tree.InsertItem(str,udp);
            str.Format(_T("总长度:%d"),local_data->udph->len);
            this->tree.InsertItem(str,udp);
            str.Format(_T("校验和:0x%02x"),local_data->udph->check);
            this->tree.InsertItem(str,udp);
        }
    }
    return 1;
}

void CYHSnifferDlg::OnQuit()
{
    // TODO: Add your command handler code here
    OnCancel();
    OnDestroy();
    PostNcDestroy();
}
