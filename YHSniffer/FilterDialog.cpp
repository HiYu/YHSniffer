// FilterDialog.cpp : implementation file
//

#include "stdafx.h"
#include "YHSniffer.h"
#include "FilterDialog.h"
#include "afxdialogex.h"


// CFilterDialog dialog
char *temp_filter = NULL;
extern char *pack_filter;
int temp_len = strlen(pack_filter);

IMPLEMENT_DYNAMIC(CFilterDialog, CDialogEx)

CFilterDialog::CFilterDialog(CWnd* pParent /*=NULL*/)
    : CDialogEx(CFilterDialog::IDD, pParent)
{

}

CFilterDialog::~CFilterDialog()
{
}

void CFilterDialog::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_FILTER_TCP, filter_tcp);
    DDX_Control(pDX, IDC_FILTER_UDP, filter_udp);
    DDX_Control(pDX, IDC_FILTER_ARP, filter_arp);
    DDX_Control(pDX, IDC_FILTER_ICMP, filter_icmp);
    DDX_Control(pDX, IDC_FILTER_IGMP, filter_igmp);
    DDX_Control(pDX, IDC_CHECK1, filter_ip);
}


BEGIN_MESSAGE_MAP(CFilterDialog, CDialogEx)
    ON_BN_CLICKED(IDOK, &CFilterDialog::OnBnClickedOk)
    ON_BN_CLICKED(IDCANCEL, &CFilterDialog::OnBnClickedCancel)
END_MESSAGE_MAP()


// CFilterDialog message handlers

BOOL CFilterDialog::OnInitDialog()
{
    CDialogEx::OnInitDialog();
    filter_tcp.SetCheck(BST_CHECKED);
    filter_udp.SetCheck(BST_CHECKED);
    filter_arp.SetCheck(BST_CHECKED);
    filter_icmp.SetCheck(BST_CHECKED);
    filter_igmp.SetCheck(BST_CHECKED);
    filter_ip.SetCheck(BST_CHECKED);
    temp_filter = (char *)malloc(temp_len * sizeof(char));
    strncpy(temp_filter, pack_filter, temp_len + 1);
    return true;
}
void CFilterDialog::OnBnClickedOk()
{
    pack_filter = (char *)malloc(sizeof(char) * temp_len);
    memset(pack_filter, 0, temp_len);
    // TODO: Add your control notification handler code here
    if (IsDlgButtonChecked(IDC_FILTER_TCP) == BST_CHECKED)
    {
        if (pack_filter[0] == 0)
        {
            strncpy(pack_filter, "tcp", strlen("tcp")+1);
        } else {
            strncat(pack_filter, " or tcp", strlen(" or tcp")+1);
        }        
    }
    if (IsDlgButtonChecked(IDC_FILTER_UDP) == BST_CHECKED)
    {
        if (pack_filter[0] == 0)
        {
            strncpy(pack_filter, "udp", strlen("udp")+1);
        } else {
            strncat(pack_filter, " or udp", strlen(" or udp")+1);
        }        
    }
    if (IsDlgButtonChecked(IDC_FILTER_ARP) == BST_CHECKED)
    {
        if (pack_filter[0] == 0)
        {
            strncpy(pack_filter, "arp", strlen("arp")+1);
        } else {
            strncat(pack_filter, " or arp", strlen("or arp")+1);
        }        
    }
    if (IsDlgButtonChecked(IDC_FILTER_ICMP) == BST_CHECKED)
    {
        if (pack_filter[0] == 0)
        {
            strncpy(pack_filter, "icmp", strlen("icmp")+1);
        } else {
            strncat(pack_filter, " or icmp", strlen("or icmp")+1);
        }        
    }
    if (IsDlgButtonChecked(IDC_FILTER_IGMP) == BST_CHECKED)
    {
        if (pack_filter[0] == 0)
        {
            strncpy(pack_filter, "igmp", strlen("igmp")+1);
        } else {
            strncat(pack_filter, " or igmp", strlen("or igmp")+1);
        }        
    }
    if (IsDlgButtonChecked(IDC_FILTER_IP) == BST_CHECKED)
    {
        if (pack_filter[0] == 0)
        {
            strncpy(pack_filter, "ip", strlen("ip")+1);
        } else {
            strncat(pack_filter, " or ip", strlen("or ip") + 1);
        }        
    }
    MessageBox(CString(pack_filter));
    CDialogEx::OnOK();
}


void CFilterDialog::OnBnClickedCancel()
{
    // TODO: Add your control notification handler code here
    temp_len = strlen(temp_filter);
    if (strcmp(pack_filter, temp_filter) != 0)
    {
        strncpy(pack_filter, temp_filter, temp_len + 1);
    }
    MessageBox(CString(pack_filter));
    CDialogEx::OnCancel();
}
