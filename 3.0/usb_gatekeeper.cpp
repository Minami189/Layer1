/*
 * USB Gatekeeper — BadUSB Interceptor with Cryptographic CAPTCHA
 *
 * CAPTCHA SECURITY MODEL:
 *   - All randomness comes from BCryptGenRandom (Windows CSPRNG)
 *   - Three challenge types: Word Scramble, Hex Decode, Token Echo
 *   - 3 wrong answers = permanent block for the session
 *
 * BUILD (MSYS2 UCRT64 terminal — run as Admin):
 *   g++ -std=c++17 -o usb_gatekeeper.exe usb_gatekeeper.cpp \
 *       -luser32 -lgdi32 -lhid -lsetupapi -lcomctl32 -lbcrypt -mwindows
 */

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <bcrypt.h>
#include <commctrl.h>
#include <dbt.h>
#include <hidusage.h>
#include <iostream>
#include <vector>
#include <set>
#include <string>
#include <mutex>
#include <algorithm>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "bcrypt.lib")

#define IDC_CAPTCHA_LABEL    101
#define IDC_CAPTCHA_SUBLABEL 102
#define IDC_CAPTCHA_INPUT    103
#define IDC_CAPTCHA_SUBMIT   104
#define IDC_CAPTCHA_DENY     105

// ─────────────────────────────────────────────────────────────────────────────
// BCrypt helpers
// ─────────────────────────────────────────────────────────────────────────────
bool CryptoRandomBytes(void* buf, size_t len)
{
    return BCRYPT_SUCCESS(
        BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len,
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}

DWORD CryptoRandRange(DWORD upperBound)
{
    if (upperBound <= 1) return 0;
    DWORD result = 0;
    DWORD threshold = (0xFFFFFFFFu % upperBound);
    do { CryptoRandomBytes(&result, sizeof(result)); } while (result < threshold);
    return result % upperBound;
}

// ─────────────────────────────────────────────────────────────────────────────
// CAPTCHA generation
// ─────────────────────────────────────────────────────────────────────────────
enum class CaptchaType { WordScramble, HexDecode, TokenEcho };
struct Captcha { CaptchaType type; std::wstring prompt; std::wstring answer; };

static const wchar_t* WORD_POOL[] = {
    L"PLANET", L"BRIDGE", L"FALCON", L"SPIDER", L"WINTER",
    L"GARDEN", L"MIRROR", L"CASTLE", L"DRAGON", L"SILVER",
    L"FOREST", L"ROCKET", L"MARBLE", L"HUNTER", L"COBALT",
    L"STRIKE", L"VECTOR", L"TURRET", L"CANYON", L"PRISM"
};
static const int WORD_POOL_SIZE = 20;

std::wstring ScrambleWord(const std::wstring& word)
{
    std::wstring s = word;
    int attempts = 0;
    do {
        for (int i = (int)s.size() - 1; i > 0; --i)
            std::swap(s[i], s[CryptoRandRange((DWORD)(i + 1))]);
        attempts++;
    } while (s == word && attempts < 20);
    return s;
}

std::wstring SpaceLetters(const std::wstring& w)
{
    std::wstring out;
    for (size_t i = 0; i < w.size(); ++i) { if (i) out += L' '; out += w[i]; }
    return out;
}

std::wstring GenerateToken()
{
    const wchar_t LETTERS[] = L"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const wchar_t DIGITS[]  = L"23456789";
    std::wstring token;
    for (int group = 0; group < 3; ++group) {
        if (group) token += L'-';
        token += LETTERS[CryptoRandRange((DWORD)(wcslen(LETTERS)))];
        token += DIGITS[CryptoRandRange((DWORD)(wcslen(DIGITS)))];
    }
    return token;
}

Captcha GenerateCaptcha()
{
    Captcha c;
    c.type = static_cast<CaptchaType>(CryptoRandRange(3));
    switch (c.type)
    {
    case CaptchaType::WordScramble: {
        std::wstring word = WORD_POOL[CryptoRandRange(WORD_POOL_SIZE)];
        c.prompt = L"Unscramble these letters into a word:\n\n" + SpaceLetters(ScrambleWord(word));
        c.answer = word;
        break;
    }
    case CaptchaType::HexDecode: {
        BYTE code = (BYTE)(0x41 + CryptoRandRange(26));
        std::wostringstream oss;
        oss << L"What letter does hex value  0x"
            << std::uppercase << std::hex << std::setw(2) << std::setfill(L'0')
            << (int)code << L"  represent?\n(Type the single letter)";
        c.prompt = oss.str();
        c.answer = std::wstring(1, (wchar_t)code);
        break;
    }
    case CaptchaType::TokenEcho: {
        std::wstring token = GenerateToken();
        c.prompt = L"Type this security code exactly as shown:\n\n" + token;
        c.answer = token;
        break;
    }
    }
    return c;
}

bool WStrEqualCI(const std::wstring& a, const std::wstring& b)
{
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (towupper(a[i]) != towupper(b[i])) return false;
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Globals
// ─────────────────────────────────────────────────────────────────────────────
std::set<HANDLE>       g_trustedDevices;
std::set<std::wstring> g_trustedNames;
std::set<HANDLE>       g_blockedDevices;
std::set<HANDLE>       g_pendingDevices;
std::mutex             g_deviceMutex;

static HANDLE          g_lastRawDevice = NULL;

HHOOK                  g_kbHook     = NULL;
HWND                   g_hWnd       = NULL;
HWND                   g_hCaptcha   = NULL;
HDEVNOTIFY             g_hDevNotify = NULL;

static Captcha         g_currentCaptcha;
static HANDLE          g_captchaDevice = NULL;
static int             g_wrongAttempts = 0;
static const int       MAX_WRONG       = 3;

// ─────────────────────────────────────────────────────────────────────────────
// Device helpers
// ─────────────────────────────────────────────────────────────────────────────
std::set<HANDLE> EnumerateKeyboardDevices()
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

std::wstring GetDeviceName(HANDLE h)
{
    UINT sz = 0;
    GetRawInputDeviceInfoW(h, RIDI_DEVICENAME, NULL, &sz);
    if (!sz) return L"<unknown>";
    std::wstring s(sz, L'\0');
    GetRawInputDeviceInfoW(h, RIDI_DEVICENAME, s.data(), &sz);
    return s;
}

std::wstring ShortName(HANDLE h)
{
    std::wstring full = GetDeviceName(h);
    auto p = full.find(L"VID_");
    if (p != std::wstring::npos && full.size() > p + 16)
        return full.substr(p, 16);
    return full.size() > 40 ? full.substr(0, 40) + L"..." : full;
}

bool IsTrustedDevice(HANDLE h)
{
    if (g_trustedDevices.count(h)) return true;
    return g_trustedNames.count(GetDeviceName(h)) > 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// CAPTCHA Window Procedure  (unchanged from working version)
// ─────────────────────────────────────────────────────────────────────────────
LRESULT CALLBACK CaptchaProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp)
{
    static HBRUSH hBgBrush  = NULL;
    static HFONT  hFontBig  = NULL;
    static HFONT  hFontMono = NULL;

    auto Cleanup = [&]() {
        if (hBgBrush)  { DeleteObject(hBgBrush);  hBgBrush  = NULL; }
        if (hFontBig)  { DeleteObject(hFontBig);  hFontBig  = NULL; }
        if (hFontMono) { DeleteObject(hFontMono); hFontMono = NULL; }
    };

    switch (msg)
    {
    case WM_CREATE:
    {
        hBgBrush  = CreateSolidBrush(RGB(22, 27, 48));
        hFontBig  = CreateFontW(18, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        hFontMono = CreateFontW(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                                DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                                CLEARTYPE_QUALITY, FIXED_PITCH, L"Consolas");

        HWND hI = CreateWindowExW(0, L"STATIC", NULL, WS_CHILD|WS_VISIBLE|SS_ICON,
            16, 14, 36, 36, hw, (HMENU)200, GetModuleHandleW(NULL), NULL);
        SendMessageW(hI, STM_SETICON, (WPARAM)LoadIconW(NULL, IDI_WARNING), 0);

        HWND hHdr = CreateWindowExW(0, L"STATIC", L"New USB Keyboard — Access Blocked",
            WS_CHILD|WS_VISIBLE|SS_LEFT, 60, 14, 420, 24,
            hw, (HMENU)201, GetModuleHandleW(NULL), NULL);
        SendMessageW(hHdr, WM_SETFONT, (WPARAM)hFontBig, TRUE);

        CreateWindowExW(0, L"STATIC",
            L"Solve the challenge on your TRUSTED keyboard to approve this device.",
            WS_CHILD|WS_VISIBLE|SS_LEFT, 60, 40, 420, 18,
            hw, (HMENU)202, GetModuleHandleW(NULL), NULL);

        CreateWindowExW(0, L"STATIC", NULL, WS_CHILD|WS_VISIBLE|SS_ETCHEDHORZ,
            12, 66, 468, 2, hw, (HMENU)203, GetModuleHandleW(NULL), NULL);

        HWND hLbl = CreateWindowExW(0, L"STATIC", L"",
            WS_CHILD|WS_VISIBLE|SS_CENTER, 12, 76, 468, 64,
            hw, (HMENU)IDC_CAPTCHA_LABEL, GetModuleHandleW(NULL), NULL);
        SendMessageW(hLbl, WM_SETFONT, (WPARAM)hFontBig, TRUE);

        CreateWindowExW(0, L"STATIC", L"", WS_CHILD|WS_VISIBLE|SS_CENTER,
            12, 146, 468, 18, hw,
            (HMENU)IDC_CAPTCHA_SUBLABEL, GetModuleHandleW(NULL), NULL);

        HWND hEdit = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD|WS_VISIBLE|ES_CENTER|ES_AUTOHSCROLL,
            150, 172, 192, 28, hw,
            (HMENU)IDC_CAPTCHA_INPUT, GetModuleHandleW(NULL), NULL);
        SendMessageW(hEdit, WM_SETFONT, (WPARAM)hFontMono, TRUE);

        HWND hApp = CreateWindowExW(0, L"BUTTON", L"Approve",
            WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON, 110, 214, 110, 32,
            hw, (HMENU)IDC_CAPTCHA_SUBMIT, GetModuleHandleW(NULL), NULL);
        SendMessageW(hApp, WM_SETFONT, (WPARAM)hFontBig, TRUE);

        HWND hDny = CreateWindowExW(0, L"BUTTON", L"Deny",
            WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON, 272, 214, 110, 32,
            hw, (HMENU)IDC_CAPTCHA_DENY, GetModuleHandleW(NULL), NULL);
        SendMessageW(hDny, WM_SETFONT, (WPARAM)hFontBig, TRUE);

        g_currentCaptcha = GenerateCaptcha();
        g_wrongAttempts  = 0;
        SetDlgItemTextW(hw, IDC_CAPTCHA_LABEL,    g_currentCaptcha.prompt.c_str());
        SetDlgItemTextW(hw, IDC_CAPTCHA_SUBLABEL, L"Attempts remaining: 3");
        SetFocus(GetDlgItem(hw, IDC_CAPTCHA_INPUT));
        return 0;
    }

    case WM_ERASEBKGND: {
        RECT rc; GetClientRect(hw, &rc);
        FillRect((HDC)wp, &rc, hBgBrush);
        return 1;
    }

    case WM_CTLCOLORSTATIC: {
        SetBkMode((HDC)wp, TRANSPARENT);
        SetTextColor((HDC)wp, RGB(210, 220, 255));
        return (LRESULT)hBgBrush;
    }

    case WM_CTLCOLOREDIT: {
        SetBkColor((HDC)wp, RGB(36, 41, 66));
        SetTextColor((HDC)wp, RGB(230, 240, 255));
        static HBRUSH hEditBrush = CreateSolidBrush(RGB(36, 41, 66));
        return (LRESULT)hEditBrush;
    }

    case WM_COMMAND:
    {
        int id = LOWORD(wp);

        if (id == IDC_CAPTCHA_SUBMIT || id == IDOK)
        {
            wchar_t buf[64] = {};
            GetDlgItemTextW(hw, IDC_CAPTCHA_INPUT, buf, 63);
            std::wstring userInput(buf);
            // trim
            auto b = userInput.find_first_not_of(L" \t\r\n");
            auto e = userInput.find_last_not_of(L" \t\r\n");
            userInput = (b == std::wstring::npos) ? L"" : userInput.substr(b, e - b + 1);

            if (WStrEqualCI(userInput, g_currentCaptcha.answer))
            {
                HANDLE approvedDevice = g_captchaDevice;
                {
                    std::lock_guard<std::mutex> lk(g_deviceMutex);
                    g_blockedDevices.erase(approvedDevice);
                    g_pendingDevices.erase(approvedDevice);
                    g_trustedDevices.insert(approvedDevice);
                    g_trustedNames.insert(GetDeviceName(approvedDevice));
                }
                std::wcout << L"[CAPTCHA PASSED] Device trusted: "
                           << ShortName(approvedDevice) << L"\n";
                g_captchaDevice = NULL;
                g_hCaptcha      = NULL;
                Cleanup();
                DestroyWindow(hw);
                // Signal the captcha thread's message loop to exit
                PostQuitMessage(0);
            }
            else
            {
                g_wrongAttempts++;
                MessageBeep(MB_ICONEXCLAMATION);
                if (g_wrongAttempts >= MAX_WRONG)
                {
                    std::wcout << L"[CAPTCHA LOCKOUT] Permanently blocked: "
                               << ShortName(g_captchaDevice) << L"\n";
                    {
                        std::lock_guard<std::mutex> lk(g_deviceMutex);
                        g_pendingDevices.erase(g_captchaDevice);
                    }
                    MessageBoxW(hw,
                        L"Maximum attempts exceeded.\nDevice permanently blocked.",
                        L"USB Gatekeeper — Locked",
                        MB_OK|MB_ICONERROR|MB_TOPMOST);
                    g_captchaDevice = NULL;
                    g_hCaptcha      = NULL;
                    Cleanup();
                    DestroyWindow(hw);
                    PostQuitMessage(0);
                }
                else
                {
                    int rem = MAX_WRONG - g_wrongAttempts;
                    SetDlgItemTextW(hw, IDC_CAPTCHA_SUBLABEL,
                        (L"Wrong!  Attempts remaining: " + std::to_wstring(rem)).c_str());
                    g_currentCaptcha = GenerateCaptcha();
                    SetDlgItemTextW(hw, IDC_CAPTCHA_LABEL, g_currentCaptcha.prompt.c_str());
                    SetDlgItemTextW(hw, IDC_CAPTCHA_INPUT, L"");
                    SetFocus(GetDlgItem(hw, IDC_CAPTCHA_INPUT));
                    std::wcout << L"[CAPTCHA FAILED] Wrong answer ("
                               << g_wrongAttempts << L"/" << MAX_WRONG << L")\n";
                }
            }
            return 0;
        }

        if (id == IDC_CAPTCHA_DENY || id == IDCANCEL)
        {
            std::wcout << L"[CAPTCHA DENIED] Stays blocked: "
                       << ShortName(g_captchaDevice) << L"\n";
            {
                std::lock_guard<std::mutex> lk(g_deviceMutex);
                g_pendingDevices.erase(g_captchaDevice);
            }
            g_captchaDevice = NULL;
            g_hCaptcha      = NULL;
            Cleanup();
            DestroyWindow(hw);
            PostQuitMessage(0);
            return 0;
        }
        return 0;
    }

    case WM_CLOSE:
        SendMessageW(hw, WM_COMMAND, IDC_CAPTCHA_DENY, 0);
        return 0;

    case WM_DESTROY:
        Cleanup();
        return 0;
    }
    return DefWindowProcW(hw, msg, wp, lp);
}

// ─────────────────────────────────────────────────────────────────────────────
// CAPTCHA thread — own thread + own message loop so it never blocks the main
// pump and its messages are always dispatched immediately.
// ─────────────────────────────────────────────────────────────────────────────
DWORD WINAPI CaptchaThread(LPVOID param)
{
    HANDLE hDevice = (HANDLE)param;

    // Register window class once per process
    static bool reg = false;
    if (!reg) {
        WNDCLASSW wc     = {};
        wc.lpfnWndProc   = CaptchaProc;
        wc.hInstance     = GetModuleHandleW(NULL);
        wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
        wc.lpszClassName = L"CaptchaClass";
        wc.hCursor       = LoadCursorW(NULL, IDC_ARROW);
        RegisterClassW(&wc);
        reg = true;
    }

    int sw = GetSystemMetrics(SM_CXSCREEN);
    int sh = GetSystemMetrics(SM_CYSCREEN);
    int w = 510, h = 276;

    g_hCaptcha = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_DLGMODALFRAME,
        L"CaptchaClass",
        L"USB Gatekeeper  —  Security Challenge",
        WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
        (sw - w) / 2, (sh - h) / 2, w, h,
        NULL, NULL, GetModuleHandleW(NULL), NULL);

    if (!g_hCaptcha) {
        std::wcout << L"[ERROR] CAPTCHA window creation failed: "
                   << GetLastError() << L"\n";
        std::lock_guard<std::mutex> lk(g_deviceMutex);
        g_pendingDevices.erase(hDevice);
        g_captchaDevice = NULL;
        return 1;
    }

    ShowWindow(g_hCaptcha, SW_SHOWNORMAL);
    UpdateWindow(g_hCaptcha);
    SetForegroundWindow(g_hCaptcha);

    std::wcout << L"[CAPTCHA] Window shown for: " << ShortName(hDevice) << L"\n";

    // Private message loop for this window only
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        if (!IsDialogMessageW(g_hCaptcha, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Spawn CAPTCHA thread for a newly-blocked device
// ─────────────────────────────────────────────────────────────────────────────
void ShowCaptchaForDevice(HANDLE hDevice)
{
    if (g_hCaptcha)                      return;
    if (g_pendingDevices.count(hDevice)) return;

    g_captchaDevice = hDevice;
    g_pendingDevices.insert(hDevice);

    HANDLE hThread = CreateThread(NULL, 0, CaptchaThread, hDevice, 0, NULL);
    if (hThread)
        CloseHandle(hThread);
    else
        std::wcout << L"[ERROR] CreateThread failed: " << GetLastError() << L"\n";
}

// ─────────────────────────────────────────────────────────────────────────────
// Low-Level Keyboard Hook
// ─────────────────────────────────────────────────────────────────────────────
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam)
{
    if (nCode == HC_ACTION)
    {
        std::lock_guard<std::mutex> lk(g_deviceMutex);
        bool isInjected = (g_lastRawDevice == NULL);
        bool isBlocked  = (!isInjected && g_blockedDevices.count(g_lastRawDevice));

        if (isInjected || isBlocked)
        {
            auto* kb = reinterpret_cast<KBDLLHOOKSTRUCT*>(lParam);
            std::wcout << (isInjected ? L"[BLOCKED-INJECT] " : L"[BLOCKED] ")
                       << L"VK=0x" << std::hex << kb->vkCode;
            if (!isInjected) std::wcout << L" from " << ShortName(g_lastRawDevice);
            std::wcout << L"\n";
            return 1;
        }
    }
    return CallNextHookEx(g_kbHook, nCode, wParam, lParam);
}

// ─────────────────────────────────────────────────────────────────────────────
// Background message-only window
// ─────────────────────────────────────────────────────────────────────────────
LRESULT CALLBACK WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    case WM_INPUT:
    {
        UINT sz = 0;
        GetRawInputData((HRAWINPUT)lParam, RID_INPUT, NULL, &sz, sizeof(RAWINPUTHEADER));
        std::vector<BYTE> buf(sz);
        if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT,
                            buf.data(), &sz, sizeof(RAWINPUTHEADER)) == sz)
        {
            auto* raw = reinterpret_cast<RAWINPUT*>(buf.data());
            if (raw->header.dwType == RIM_TYPEKEYBOARD)
                g_lastRawDevice = raw->header.hDevice;
        }
        return DefWindowProcW(hWnd, uMsg, wParam, lParam);
    }

    case WM_DEVICECHANGE:
    {
        if (wParam == DBT_DEVICEARRIVAL)
        {
            auto* hdr = reinterpret_cast<DEV_BROADCAST_HDR*>(lParam);
            if (hdr && hdr->dbch_devicetype == DBT_DEVTYP_DEVICEINTERFACE)
            {
                // Brief delay so Windows finishes enumerating the new device
                Sleep(300);

                auto current = EnumerateKeyboardDevices();
                HANDLE newDev = NULL;
                {
                    std::lock_guard<std::mutex> lk(g_deviceMutex);
                    for (HANDLE h : current)
                    {
                        if (!IsTrustedDevice(h) &&
                            !g_blockedDevices.count(h) &&
                            !g_pendingDevices.count(h))
                        {
                            g_blockedDevices.insert(h);
                            newDev = h;
                            std::wcout << L"[ALERT] New keyboard blocked (CAPTCHA pending): "
                                       << ShortName(h) << L"\n";
                        }
                    }
                }
                // ShowCaptchaForDevice spawns its own thread so this returns immediately
                if (newDev) ShowCaptchaForDevice(newDev);
            }
        }
        else if (wParam == DBT_DEVICEREMOVECOMPLETE)
        {
            auto current = EnumerateKeyboardDevices();
            std::lock_guard<std::mutex> lk(g_deviceMutex);

            for (auto it = g_blockedDevices.begin(); it != g_blockedDevices.end(); )
                it = current.count(*it) ? ++it : g_blockedDevices.erase(it);
            for (auto it = g_pendingDevices.begin(); it != g_pendingDevices.end(); )
                it = current.count(*it) ? ++it : g_pendingDevices.erase(it);

            if (g_captchaDevice && !current.count(g_captchaDevice))
            {
                if (g_hCaptcha) { DestroyWindow(g_hCaptcha); g_hCaptcha = NULL; }
                g_captchaDevice = NULL;
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

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────
int main()
{
    BYTE test[4] = {};
    if (!CryptoRandomBytes(test, 4)) {
        std::wcerr << L"[FATAL] BCryptGenRandom unavailable.\n";
        return 1;
    }
    std::wcout << L"[INFO] BCryptGenRandom: OK\n";

    // 1. Snapshot trusted keyboards by handle AND name
    {
        std::lock_guard<std::mutex> lk(g_deviceMutex);
        g_trustedDevices = EnumerateKeyboardDevices();
        for (HANDLE h : g_trustedDevices) {
            std::wstring n = GetDeviceName(h);
            g_trustedNames.insert(n);
            std::wcout << L"[TRUSTED] " << n << L"\n";
        }
        std::wcout << L"[INFO] " << g_trustedDevices.size()
                   << L" trusted keyboard(s) at startup.\n\n";
    }

    // 2. Invisible message-only window
    WNDCLASSW wc     = {};
    wc.lpfnWndProc   = WindowProc;
    wc.hInstance     = GetModuleHandleW(NULL);
    wc.lpszClassName = L"USBGatekeeperBg";
    RegisterClassW(&wc);

    g_hWnd = CreateWindowExW(0, L"USBGatekeeperBg", L"",
        0, 0, 0, 0, 0, HWND_MESSAGE, NULL, wc.hInstance, NULL);
    if (!g_hWnd) {
        std::wcerr << L"[ERROR] CreateWindowEx: " << GetLastError() << L"\n";
        return 1;
    }

    // 3. Raw Input — all keyboards, even when unfocused
    RAWINPUTDEVICE rid = {};
    rid.usUsagePage = HID_USAGE_PAGE_GENERIC;
    rid.usUsage     = HID_USAGE_GENERIC_KEYBOARD;
    rid.dwFlags     = RIDEV_INPUTSINK;
    rid.hwndTarget  = g_hWnd;
    if (!RegisterRawInputDevices(&rid, 1, sizeof(rid))) {
        std::wcerr << L"[ERROR] RegisterRawInputDevices: " << GetLastError() << L"\n";
        return 1;
    }

    // 4. Device-arrival notifications
    DEV_BROADCAST_DEVICEINTERFACE nf = {};
    nf.dbcc_size       = sizeof(nf);
    nf.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    nf.dbcc_classguid  = { 0x4D1E55B2, 0xF16F, 0x11CF,
                           {0x88,0xCB,0x00,0x11,0x11,0x00,0x00,0x30} };
    g_hDevNotify = RegisterDeviceNotificationW(
        g_hWnd, &nf, DEVICE_NOTIFY_WINDOW_HANDLE);
    if (!g_hDevNotify) {
        std::wcerr << L"[ERROR] RegisterDeviceNotification: " << GetLastError() << L"\n";
        return 1;
    }

    // 5. System-wide low-level keyboard hook
    g_kbHook = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKeyboardProc,
                                  GetModuleHandleW(NULL), 0);
    if (!g_kbHook) {
        std::wcerr << L"[ERROR] SetWindowsHookEx: " << GetLastError() << L"\n";
        return 1;
    }

    std::wcout << L"[INFO] USB Gatekeeper active.\n"
               << L"       Plug in USB keyboard  ->  CAPTCHA popup appears.\n"
               << L"       Run .ahk script        ->  keystrokes blocked.\n"
               << L"       3 wrong answers         ->  permanent block.\n"
               << L"       Ctrl+C to exit.\n\n";

    // 6. Main message pump — no IsDialogMessage needed, CAPTCHA is on its own thread
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    // 7. Cleanup
    UnhookWindowsHookEx(g_kbHook);
    UnregisterDeviceNotification(g_hDevNotify);
    if (g_hCaptcha) DestroyWindow(g_hCaptcha);
    DestroyWindow(g_hWnd);

    std::wcout << L"[INFO] Gatekeeper stopped.\n";
    return 0;
}