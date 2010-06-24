
/*
 * Copyright (C) Ngwsx
 */


#include <ngx_gui.h>


#define WM_NGX_TRAYICON    2008


#define NGX_APPNAME        "Nginx Service Manager"
#define NGX_SITE           "http://www.ngwsx.org/"


static INT_PTR CALLBACK ngx_dlgproc(HWND hwnd, UINT msg, WPARAM wparam,
    LPARAM lparam);
static int ngx_manage_service(HWND hwnd, int op);
static int ngx_is_autorun(void);
static int ngx_set_autorun(int set);


static HINSTANCE       instance;
static HMENU           menu;
static HICON           main_icon;
static HICON           tray_icon;
static NOTIFYICONDATA  nid;
static char            sbin_path[MAX_PATH];


int
WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmdline, int cmdshow)
{
    MSG     msg;
    HWND    hwnd;
    HANDLE  mutex;

    mutex = CreateMutex(NULL, TRUE, NGX_APPNAME);
    if (mutex == NULL) {
        return 1;
    }

    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(mutex);
        return 0;
    }

    instance = inst;

    if (GetModuleFileName(inst, sbin_path, MAX_PATH) == 0) {
        MessageBox(NULL, "GetModuleFileName() failed", NGX_APPNAME, MB_OK);
        CloseHandle(mutex);
        return 1;
    }

    hwnd = CreateDialog(inst, MAKEINTRESOURCE(IDD_NGINX), NULL, ngx_dlgproc);
    if (hwnd == NULL) {
        MessageBox(NULL, "CreateDialog() failed", NGX_APPNAME, MB_OK);
        CloseHandle(mutex);
        return 1;
    }

#if 0
    ShowWindow(hwnd, SW_NORMAL);
    UpdateWindow(hwnd);
#endif

    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    CloseHandle(mutex);

    return (int) msg.wParam;
}


static INT_PTR CALLBACK
ngx_dlgproc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    POINT  pt;

    switch (msg) {

    case WM_INITDIALOG:
        menu = LoadMenu(instance, MAKEINTRESOURCE(IDR_NGINX));
        main_icon = LoadIcon(instance, MAKEINTRESOURCE(IDI_NGINX));
        tray_icon = LoadIcon(instance, MAKEINTRESOURCE(IDI_NGINX_TRAY));

        nid.cbSize = sizeof(NOTIFYICONDATA);
        nid.hWnd = hwnd;
        nid.uID = ID_NGINX;
        nid.uFlags = NIF_ICON|NIF_MESSAGE|NIF_TIP;
        nid.uCallbackMessage = WM_NGX_TRAYICON;
        nid.hIcon = tray_icon;

        lstrcpy(nid.szTip, NGX_APPNAME);

        Shell_NotifyIcon(NIM_ADD, &nid);

        return TRUE;

    case WM_INITMENUPOPUP:
        if ((HMENU) wparam == GetSubMenu(GetSubMenu(menu, 0), 2)) {
            CheckMenuItem(menu, ID_AUTORUN,
                  MF_BYCOMMAND|(ngx_is_autorun() ? MF_CHECKED : MF_UNCHECKED));
        }

        break;

    case WM_COMMAND:
        switch (LOWORD(wparam)) {

        case ID_OPEN:
            ShellExecute(hwnd, "open", NGX_SITE, NULL, NULL, SW_SHOWNORMAL);
            break;

        case ID_AUTORUN:
            if (GetMenuState(menu, ID_AUTORUN, MF_BYCOMMAND) & MF_CHECKED) {
                ngx_set_autorun(FALSE);

            } else {
                ngx_set_autorun(TRUE);
            }

            break;

        case ID_INSTALL:
        case ID_UNINSTALL:
        case ID_START:
        case ID_STOP:
            ngx_manage_service(hwnd, LOWORD(wparam));
            break;

        case ID_HELP:
            ShellExecute(hwnd, "open", NGX_SITE, NULL, NULL, SW_SHOWNORMAL);
            break;

        case ID_ABOUT:
            ShellExecute(hwnd, "open", NGX_SITE, NULL, NULL, SW_SHOWNORMAL);
            break;

        case ID_EXIT:
            Shell_NotifyIcon(NIM_DELETE, &nid);
            DestroyMenu(menu);
            DestroyWindow(hwnd);
            break;

        default:
            break;
        }

        break;

    case WM_NGX_TRAYICON:
        if (lparam == WM_RBUTTONUP) {
            GetCursorPos(&pt);
            SetForegroundWindow(hwnd);
            TrackPopupMenu(GetSubMenu(menu, 0), TPM_LEFTALIGN, pt.x, pt.y, 0,
                           hwnd, NULL);
        }

        break;

    case WM_CLOSE:
        SendMessage(hwnd, WM_COMMAND, MAKEWPARAM(ID_EXIT, 0), 0);
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        break;
    }

    return FALSE;
}


static int
ngx_manage_service(HWND hwnd, int op)
{
    int                  rc, len;
    char                 cmdline[MAX_PATH], *op_name;
    STARTUPINFO          si;
    PROCESS_INFORMATION  pi;

    lstrcpy(cmdline, sbin_path);
    len = lstrlen(cmdline);

    /* replace "gui.exe" with "nginx.exe -*" */

    switch (op) {
    case ID_INSTALL:
        op_name = "i";
        break;
    case ID_UNINSTALL:
        op_name = "u";
        break;
    case ID_START:
        op_name = "r";
        break;
    case ID_STOP:
        op_name = "e";
        break;
    default:
        return FALSE;
    }

    wsprintf(cmdline + len - 7, "nginx.exe -%s", op_name);

#if 0
    MessageBox(hwnd, cmdline, NGX_APPNAME, MB_OK);
#endif

    ZeroMemory(&si, sizeof(STARTUPINFO));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));

    si.cb = sizeof(STARTUPINFO);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    rc = CreateProcess(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL,
                       &si, &pi);
    if (rc == 0) {
        MessageBox(hwnd, "CreateProcess() failed", NGX_APPNAME, MB_OK);
        return FALSE;
    }

    if (WaitForSingleObject(pi.hProcess, INFINITE) == WAIT_FAILED) {
        MessageBox(hwnd, "WaitForSingleObject() failed", NGX_APPNAME, MB_OK);
        rc = FALSE;
    }

    /* TODO: GetExitCodeProcess */

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return rc;
}


static int
ngx_is_autorun(void)
{
    HKEY  hkey;

    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE,
                       "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                       0, NULL, REG_OPTION_NON_VOLATILE, KEY_READ, NULL,
                       &hkey, NULL)
        != ERROR_SUCCESS) {

        return FALSE;
    }

    if (RegQueryValueEx(hkey, NGX_APPNAME, NULL, NULL, NULL, NULL)
        != ERROR_SUCCESS)
    {
        RegCloseKey(hkey);
        return FALSE;
    }

    RegCloseKey(hkey);

    return TRUE;
}


static int
ngx_set_autorun(int set)
{
    HKEY  hkey;

    if (RegCreateKeyEx(HKEY_LOCAL_MACHINE,
                       "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                       0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL,
                       &hkey, NULL)
        != ERROR_SUCCESS) {

        return FALSE;
    }

    if (set) {
        if (RegSetValueEx(hkey, NGX_APPNAME, 0, REG_SZ, sbin_path,
                          lstrlen(sbin_path) + 1)
            != ERROR_SUCCESS)
        {
            RegCloseKey(hkey);
            return FALSE;
        }

    } else {
        if (RegDeleteValue(hkey, NGX_APPNAME) != ERROR_SUCCESS) {
            RegCloseKey(hkey);
            return FALSE;
        }
    }

    RegCloseKey(hkey);

    return TRUE;
}
