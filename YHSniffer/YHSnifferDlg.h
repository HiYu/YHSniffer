
// YHSnifferDlg.h : header file
//

#pragma once
#include "afxcmn.h"
#include "afxwin.h"
#include "resource.h"

// CYHSnifferDlg dialog
class CYHSnifferDlg : public CDialogEx
{
// Construction
public:
    CYHSnifferDlg(CWnd* pParent = NULL);    // standard constructor

// Dialog Data
    enum { IDD = IDD_YHSNIFFER_DIALOG };

    protected:
    virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support


// Implementation
protected:
    HICON m_hIcon;

    // Generated message map functions
    virtual BOOL OnInitDialog();
    afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
    afx_msg void OnPaint();
    afx_msg HCURSOR OnQueryDragIcon();
    DECLARE_MESSAGE_MAP()
public:
    CListCtrl list;
    afx_msg void OnNetcard();
    afx_msg void OnFliter();
    afx_msg void OnBegin();
    int YHUpdateTree(int index);
    int YHUpdateEdit(int index);
    void YHUpdatePacket(void);
    CEdit netcard_edit;
    HANDLE catch_handle;
    
    CEdit edit;
    afx_msg void OnStop();
    afx_msg void OnNMDblclkList(NMHDR *pNMHDR, LRESULT *pResult);
    CTreeCtrl tree;
    afx_msg void OnQuit();
};
