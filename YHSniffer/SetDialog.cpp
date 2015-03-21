// SetDialog.cpp : implementation file
//

#include "stdafx.h"
#include "YHSniffer.h"
#include "SetDialog.h"
#include "afxdialogex.h"
#include "function.h"
#include "protocol.h"
#include <stdlib.h>

// CSetDialog dialog
extern pcap_if_t *all_devs;

IMPLEMENT_DYNAMIC(CSetDialog, CDialogEx)

CSetDialog::CSetDialog(CWnd* pParent /*=NULL*/)
    : CDialogEx(CSetDialog::IDD, pParent)
{
    
}

CSetDialog::~CSetDialog()
{
}

void CSetDialog::DoDataExchange(CDataExchange* pDX)
{
    CDialogEx::DoDataExchange(pDX);
    DDX_Control(pDX, IDC_LIST_NETCARD, netcard_list);
}
BOOL CSetDialog::OnInitDialog()
{
    CDialogEx::OnInitDialog();
    pcap_if_t *devp;
    int i;
    dev_count = 0;
    CString stemp;
    netcard_list.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT | LVS_EX_CHECKBOXES);
    netcard_list.InsertColumn(0, _T("Ñ¡Ôñ"), 0, 80);
    netcard_list.InsertColumn(1, _T("Íø¿¨±àºÅ"), 0, 80);
    netcard_list.InsertColumn(2, _T("Íø¿¨"), 0, 400);
    YHGetNetCard( &all_devs, &dev_count);
    
    if (dev_count > 0)
    {
        netcard_list.SetCheck(0, 1);
    }

    for (i = 0, devp = all_devs; i < dev_count; i++, devp = devp->next)
    {
        stemp.Format(_T("%d"), (i + 1));
        netcard_list.InsertItem(i, _T(""));
        netcard_list.SetItemText(i, 1, stemp);
        netcard_list.SetItemText(i, 2, CString(devp->name));
    }
    
    return true;

}

BEGIN_MESSAGE_MAP(CSetDialog, CDialogEx)
    ON_BN_CLICKED(ID_NETCARD_OK, &CSetDialog::OnBnClickedNetcardOk)
    ON_BN_CLICKED(ID_NETCARD_CANCEL, &CSetDialog::OnBnClickedNetcardCancel)
END_MESSAGE_MAP()


// CSetDialog message handlers


void CSetDialog::OnBnClickedNetcardOk()
{
    // TODO: Add your control notification handler code here
    int i, j;
    pcap_if_t *devp;
    extern char *netcard_name;
    extern pcap_if_t *dev;

    for (i = 0; i < dev_count && netcard_list.GetCheck(i) == false; i++){}
    if (i < dev_count)
    {
        for (j = 0, devp = all_devs; j < i && devp->next != NULL; devp = devp->next, j++){}
        dev = devp;
        OnOK();
    }
}


void CSetDialog::OnBnClickedNetcardCancel()
{
    // TODO: Add your control notification handler code here
    OnCancel();
    OnDestroy();
    PostNcDestroy();
}
