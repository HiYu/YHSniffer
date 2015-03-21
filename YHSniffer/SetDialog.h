#pragma once
#include "afxcmn.h"
#include "function.h"
#include "protocol.h"

// CSetDialog dialog

class CSetDialog : public CDialogEx
{
    DECLARE_DYNAMIC(CSetDialog)

public:
    CSetDialog(CWnd* pParent = NULL);   // standard constructor
    virtual ~CSetDialog();

// Dialog Data
    enum { IDD = IDD_SET_DIALOG };

protected:
    int dev_count;
    
    virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
    virtual BOOL OnInitDialog();
    DECLARE_MESSAGE_MAP()
public:
    CListCtrl netcard_list;
    afx_msg void OnBnClickedNetcardOk();
    afx_msg void OnBnClickedNetcardCancel();
};
