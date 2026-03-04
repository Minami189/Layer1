/*
 * USB Gatekeeper DIAGNOSTIC v4 - ASCII only logging
 *
 * BUILD:
 *   g++ -std=c++17 -o usb_diag.exe usb_diag.cpp \
 *       -luser32 -lgdi32 -lhid -lsetupapi -lbcrypt -mwindows
 */

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <bcrypt.h>
#include <dbt.h>
#include <hidusage.h>
#include <stdio.h>
#include <vector>
#include <set>
#include <string>
#include <mutex>

#pragma comment(lib, "bcrypt.lib")

// ── Pure ASCII logger — no wide strings, no encoding issues ──────────────────
FILE*      g_log = NULL;
std::mutex g_logMutex;

void Log(const char* fmt, ...)
{
    std::lock_guard<std::mutex> lk(g_logMutex);
    char buf[512];
    va_list a; va_start(a, fmt); vsnprintf(buf, 512, fmt, a); va_end(a);
    printf("%s\n", buf); fflush(stdout);
    if (g_log) { fprintf(g_log, "%s\n", buf); fflush(g_log); }
}

// ── Globals ───────────────────────────────────────────────────────────────────
std::set<HANDLE>       g_trustedDevices;
std::set<std::wstring> g_trustedNames;
std::set<HANDLE>       g_blockedDevices;
std::set<HANDLE>       g_pendingDevices;
std::mutex             g_deviceMutex;
static HANDLE          g_lastRawDevice = NULL;
HHOOK                  g_kbHook        = NULL;
HWND                   g_hWnd          = NULL;
HWND                   g_hCaptcha      = NULL;
HDEVNOTIFY             g_hDevNotify    = NULL;
static HANDLE          g_captchaDevice = NULL;

// ── Device helpers ────────────────────────────────────────────────────────────
std::wstring GetDeviceName(HANDLE h)
{
    UINT sz = 0;
    GetRawInputDeviceInfoW(h, RIDI_DEVICENAME, NULL, &sz);
    if (!sz) return L"<unknown>";
    std::wstring s(sz, L'\0');
    GetRawInputDeviceInfoW(h, RIDI_DEVICENAME, s.data(), &sz);
    return s;
}

// Narrow ASCII version for logging
std::string GetDeviceNameA(HANDLE h)
{
    std::wstring w = GetDeviceName(h);
    std::string out;
    for (wchar_t c : w)
        out += (c < 128) ? (char)c : '?';
    return out;
}

std::set<HANDLE> EnumerateKeyboards()
{
    std::set<HANDLE> out;
    UINT n = 0;
    GetRawInputDeviceList(NULL, &n, sizeof(RAWINPUTDEVICELIST));
    if (!n) return out;
    std::vector<RAWINPUTDEVICELIST> list(n);
    if (GetRawInputDeviceList(list.data(), &n, sizeof(RAWINPUTDEVICELIST)) == (UINT)-1)
        return out;
    for (auto& d : list)
        if (d.dwType == RIM_TYPEKEYBOARD)
            out.insert(d.hDevice);
    return out;
}

bool IsTrusted(HANDLE h)
{
    if (g_trustedDevices.count(h)) return true;
    return g_trustedNames.count(GetDeviceName(h)) > 0;
}

// ── Simple popup window ───────────────────────────────────────────────────────
#define IDC_BTN_OK 101

LRESULT CALLBACK CaptchaProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_CREATE:
        Log("[CAPTCHA] WM_CREATE - window exists");
        CreateWindowExW(0, L"STATIC", L"NEW KEYBOARD DETECTED\nClick OK to trust it.",
            WS_CHILD|WS_VISIBLE|SS_CENTER, 10,20,360,50,
            hw,(HMENU)200,GetModuleHandleW(NULL),NULL);
        CreateWindowExW(0, L"BUTTON", L"OK - Trust Device",
            WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON, 110,90,160,34,
            hw,(HMENU)IDC_BTN_OK,GetModuleHandleW(NULL),NULL);
        return 0;
    case WM_COMMAND:
        if (LOWORD(wp) == IDC_BTN_OK) {
            Log("[CAPTCHA] OK clicked");
            if (g_captchaDevice) {
                std::lock_guard<std::mutex> lk(g_deviceMutex);
                g_blockedDevices.erase(g_captchaDevice);
                g_pendingDevices.erase(g_captchaDevice);
                g_trustedDevices.insert(g_captchaDevice);
                g_captchaDevice = NULL;
            }
            g_hCaptcha = NULL;
            DestroyWindow(hw);
            PostQuitMessage(0);
        }
        return 0;
    case WM_CLOSE:
        Log("[CAPTCHA] WM_CLOSE");
        g_hCaptcha = NULL;
        { std::lock_guard<std::mutex> lk(g_deviceMutex);
          if (g_captchaDevice) g_pendingDevices.erase(g_captchaDevice);
          g_captchaDevice = NULL; }
        DestroyWindow(hw);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hw, msg, wp, lp);
}

DWORD WINAPI CaptchaThread(LPVOID param)
{
    HANDLE hDevice = (HANDLE)param;
    Log("[THREAD] Started");

    static bool reg = false;
    if (!reg) {
        WNDCLASSW wc    = {};
        wc.lpfnWndProc  = CaptchaProc;
        wc.hInstance    = GetModuleHandleW(NULL);
        wc.hbrBackground= (HBRUSH)(COLOR_WINDOW+1);
        wc.lpszClassName= L"DiagCaptcha";
        wc.hCursor      = LoadCursorW(NULL, IDC_ARROW);
        if (!RegisterClassW(&wc)) {
            Log("[THREAD] RegisterClassW FAILED err=%lu", GetLastError());
            return 1;
        }
        Log("[THREAD] RegisterClassW OK");
        reg = true;
    }

    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    Log("[THREAD] Screen=%dx%d", sw, sh);
    Log("[THREAD] Calling CreateWindowExW...");

    g_hCaptcha = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_APPWINDOW,
        L"DiagCaptcha",
        L"USB Gatekeeper - New Device Detected",
        WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_VISIBLE,
        (sw-390)/2, (sh-160)/2, 390, 160,
        NULL, NULL, GetModuleHandleW(NULL), NULL);

    if (!g_hCaptcha) {
        Log("[THREAD] CreateWindowExW FAILED err=%lu", GetLastError());
        std::lock_guard<std::mutex> lk(g_deviceMutex);
        g_pendingDevices.erase(hDevice);
        g_captchaDevice = NULL;
        return 1;
    }

    Log("[THREAD] Window created OK hwnd=%p", (void*)g_hCaptcha);
    ShowWindow(g_hCaptcha, SW_SHOWNORMAL);
    UpdateWindow(g_hCaptcha);
    SetForegroundWindow(g_hCaptcha);
    Log("[THREAD] Entering message loop");

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (!IsDialogMessageW(g_hCaptcha, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    Log("[THREAD] Loop exited");
    return 0;
}

void ShowCaptchaForDevice(HANDLE hDevice)
{
    Log("[SHOW] ShowCaptchaForDevice called");
    if (g_hCaptcha)                      { Log("[SHOW] skipped - already showing"); return; }
    if (g_pendingDevices.count(hDevice)) { Log("[SHOW] skipped - already pending"); return; }
    g_captchaDevice = hDevice;
    g_pendingDevices.insert(hDevice);
    HANDLE ht = CreateThread(NULL, 0, CaptchaThread, hDevice, 0, NULL);
    if (ht) { Log("[SHOW] Thread spawned OK"); CloseHandle(ht); }
    else      Log("[SHOW] CreateThread FAILED err=%lu", GetLastError());
}

LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wp, LPARAM lp)
{
    if (nCode == HC_ACTION) {
        std::lock_guard<std::mutex> lk(g_deviceMutex);
        if (g_lastRawDevice && g_blockedDevices.count(g_lastRawDevice))
            return 1;
    }
    return CallNextHookEx(g_kbHook, nCode, wp, lp);
}

LRESULT CALLBACK WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_INPUT: {
        UINT sz = 0;
        GetRawInputData((HRAWINPUT)lParam,RID_INPUT,NULL,&sz,sizeof(RAWINPUTHEADER));
        std::vector<BYTE> buf(sz);
        if (GetRawInputData((HRAWINPUT)lParam,RID_INPUT,buf.data(),&sz,sizeof(RAWINPUTHEADER))==sz) {
            auto* raw = reinterpret_cast<RAWINPUT*>(buf.data());
            if (raw->header.dwType == RIM_TYPEKEYBOARD)
                g_lastRawDevice = raw->header.hDevice;
        }
        return DefWindowProcW(hWnd, uMsg, wParam, lParam);
    }
    case WM_DEVICECHANGE: {
        Log("[DC] WM_DEVICECHANGE wParam=%llu", (unsigned long long)wParam);
        if (wParam == DBT_DEVICEARRIVAL) {
            auto* hdr = reinterpret_cast<DEV_BROADCAST_HDR*>(lParam);
            Log("[DC] devicetype=%lu", hdr ? (unsigned long)hdr->dbch_devicetype : 0UL);
            if (hdr && hdr->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE) {
                Sleep(300);
                auto current = EnumerateKeyboards();
                Log("[DC] Enumerated %zu keyboard handle(s)", current.size());
                HANDLE newDev = NULL;
                {
                    std::lock_guard<std::mutex> lk(g_deviceMutex);
                    int idx = 0;
                    for (HANDLE h : current) {
                        bool tr = IsTrusted(h);
                        bool bl = g_blockedDevices.count(h) > 0;
                        bool pe = g_pendingDevices.count(h) > 0;
                        Log("[DC]   [%d] handle=%p trusted=%d blocked=%d pending=%d",
                            idx++, (void*)h, tr, bl, pe);
                        Log("[DC]       name=%s", GetDeviceNameA(h).c_str());
                        if (!tr && !bl && !pe) {
                            g_blockedDevices.insert(h);
                            newDev = h;
                            Log("[DC]   -> BLOCKED, will show CAPTCHA");
                        }
                    }
                }
                if (newDev) ShowCaptchaForDevice(newDev);
                else Log("[DC] No new device found");
            }
        }
        return TRUE;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, uMsg, wParam, lParam);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int)
{
    AllocConsole();
    FILE* dummy;
    freopen_s(&dummy, "CONOUT$", "w", stdout);
    SetConsoleTitleW(L"USB Gatekeeper Diagnostic");

    // Log file next to exe
    wchar_t exePathW[MAX_PATH];
    GetModuleFileNameW(NULL, exePathW, MAX_PATH);
    wchar_t* slash = wcsrchr(exePathW, L'\\');
    if (slash) wcscpy_s(slash+1, MAX_PATH-(slash-exePathW)-1, L"diag.txt");
    char logPathA[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, exePathW, -1, logPathA, MAX_PATH, NULL, NULL);
    fopen_s(&g_log, logPathA, "w");
    Log("Log path: %s", logPathA);

    Log("=== USB Gatekeeper Diagnostic v4 ===");
    Log("Console and diag.txt both active");

    BYTE test[4] = {};
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL,test,4,BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
    { Log("FATAL: BCryptGenRandom failed"); Sleep(5000); return 1; }
    Log("BCryptGenRandom OK");

    {
        std::lock_guard<std::mutex> lk(g_deviceMutex);
        g_trustedDevices = EnumerateKeyboards();
        Log("Trusted keyboards at startup: %zu", g_trustedDevices.size());
        int i = 0;
        for (HANDLE h : g_trustedDevices) {
            std::wstring n = GetDeviceName(h);
            g_trustedNames.insert(n);
            Log("  [%d] handle=%p name=%s", i++, (void*)h, GetDeviceNameA(h).c_str());
        }
    }

    WNDCLASSW wc = {};
    wc.lpfnWndProc   = WindowProc;
    wc.hInstance     = hInst;
    wc.lpszClassName = L"USBGatekeeperBg";
    RegisterClassW(&wc);

    g_hWnd = CreateWindowExW(0,L"USBGatekeeperBg",L"",
        0,0,0,0,0,HWND_MESSAGE,NULL,hInst,NULL);
    if (!g_hWnd) { Log("FATAL: CreateWindowEx %lu",GetLastError()); Sleep(5000); return 1; }
    Log("Background window OK");

    RAWINPUTDEVICE rid = {};
    rid.usUsagePage = HID_USAGE_PAGE_GENERIC;
    rid.usUsage     = HID_USAGE_GENERIC_KEYBOARD;
    rid.dwFlags     = RIDEV_INPUTSINK;
    rid.hwndTarget  = g_hWnd;
    if (!RegisterRawInputDevices(&rid,1,sizeof(rid)))
    { Log("FATAL: RegisterRawInputDevices %lu",GetLastError()); Sleep(5000); return 1; }
    Log("Raw Input OK");

    DEV_BROADCAST_DEVICEINTERFACE nf = {};
    nf.dbcc_size       = sizeof(nf);
    nf.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    nf.dbcc_classguid  = {0x4D1E55B2,0xF16F,0x11CF,
                          {0x88,0xCB,0x00,0x11,0x11,0x00,0x00,0x30}};
    g_hDevNotify = RegisterDeviceNotificationW(g_hWnd,&nf,DEVICE_NOTIFY_WINDOW_HANDLE);
    if (!g_hDevNotify)
    { Log("FATAL: RegisterDeviceNotification %lu",GetLastError()); Sleep(5000); return 1; }
    Log("Device notifications OK");

    g_kbHook = SetWindowsHookExW(WH_KEYBOARD_LL,LowLevelKeyboardProc,
                                  GetModuleHandleW(NULL),0);
    if (!g_kbHook)
    { Log("FATAL: SetWindowsHookEx %lu",GetLastError()); Sleep(5000); return 1; }
    Log("Keyboard hook OK");

    Log("");
    Log(">>> Ready - plug in a USB keyboard now <<<");
    Log("");

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    UnhookWindowsHookEx(g_kbHook);
    UnregisterDeviceNotification(g_hDevNotify);
    if (g_hCaptcha) DestroyWindow(g_hCaptcha);
    DestroyWindow(g_hWnd);
    Log("=== Done ===");
    if (g_log) fclose(g_log);
    return 0;
}