#pragma once
#include "afxwin.h"


// CFilterDialog dialog

class CFilterDialog : public CDialogEx
{
    DECLARE_DYNAMIC(CFilterDialog)

public:
    CFilterDialog(CWnd* pParent = NULL);   // standard constructor
    virtual ~CFilterDialog();

// Dialog Data
    enum { IDD = IDD_FILTER_DIALOG };

protected:
    virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
    virtual BOOL OnInitDialog();
    DECLARE_MESSAGE_MAP()
public:
    afx_msg void OnBnClickedOk();
    CButton filter_tcp;
    CButton filter_udp;
    CButton filter_arp;
    CButton filter_icmp;
    CButton filter_igmp;
    CButton filter_ip;
    afx_msg void OnBnClickedCancel();
    
};
