#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define UNICODE
#define _UNICODE
#define _WIN32_IE 0x0600
#define WINVER 0x0600
#define _WIN32_WINNT 0x0600

#include <windows.h>
#include <commctrl.h>
#include <bcrypt.h>
#include <dbt.h>
#include <hidusage.h>
#include <setupapi.h>
#include <shellapi.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <deque> // [FIX 2]
#include <set>
#include <map>
#include <string>
#include <mutex>
#include <atomic>
#include <cmath>
#include <algorithm>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "setupapi.lib")
// Auto-deny timeout for the CAPTCHA window.  Set to 0 to disable.
// ─────────────────────────────────────────────────────────────────────────────
static constexpr UINT CAPTCHA_TIMEOUT_MS = 60000;
#define CAPTCHA_TIMER_ID 42

// ─────────────────────────────────────────────────────────────────────────────
// Control IDs
// ─────────────────────────────────────────────────────────────────────────────
#define IDC_LABEL 101
#define IDC_SUBLABEL 102
#define IDC_INPUT 103
#define IDC_SUBMIT 104
#define IDC_DENY 105
#define IDC_T1 201
#define IDC_T2 202
#define IDC_T3 203
#define IDC_T4 204
#define IDC_T5 205

#define IDC_LOG 1001
#define IDC_DEVLIST 1002
#define IDC_BTN_ALLOW 1003
#define IDC_BTN_BLOCK 1004
#define IDC_BTN_CLEAR 1005
#define IDC_BTN_FORGET 1006
#define IDC_CHK_ALLOWLIST 1007
#define IDC_CHK_REMBLOCKED 1008
#define IDC_STATIC_LOG 1009
#define IDC_STATIC_DEV 1010
#define IDC_STATIC_SETTINGS 1011
#define IDC_BTN_REFRESH 1012

// Custom window messages
#define WM_TRAYICON (WM_USER + 1)
#define WM_NEXT_CAPTCHA (WM_USER + 2)    // [FIX 2] posted by captcha thread on exit
#define WM_DISMISS_CAPTCHA (WM_USER + 3) // [FIX 2] clean shutdown without DenyDevice

// ─────────────────────────────────────────────────────────────────────────────
// Device record
// ─────────────────────────────────────────────────────────────────────────────
struct DevRecord
{
    std::wstring vid, pid;
    std::wstring instanceId;
    std::wstring manufacturer;
    std::wstring product;
    std::wstring usbSerial;
    std::wstring fullName;
    std::wstring friendly;
    USHORT version = 0;
    enum class Status
    {
        Unknown,
        Allowed,
        Blocked
    } status = Status::Unknown;
};

// ─────────────────────────────────────────────────────────────────────────────
// BCrypt helpers
// ─────────────────────────────────────────────────────────────────────────────
bool CryptoRandomBytes(void *buf, size_t len)
{
    return BCRYPT_SUCCESS(BCryptGenRandom(NULL, (PUCHAR)buf, (ULONG)len,
                                          BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}
DWORD CryptoRandRange(DWORD upper)
{
    if (upper <= 1)
        return 0;
    DWORD r = 0, t = 0xFFFFFFFFu % upper;
    do
    {
        CryptoRandomBytes(&r, sizeof(r));
    } while (r < t);
    return r % upper;
}

// ─────────────────────────────────────────────────────────────────────────────
// Challenge types
// ─────────────────────────────────────────────────────────────────────────────
enum class ChalType
{
    Scramble,
    Hex,Token,
    MouseColor
};
enum class DevClass
{
    Keyboard,
    Mouse,
    Unknown
};
struct Challenge
{
    ChalType type;
    std::wstring display, hint, answer;
    int colorIdx = 0, targetBox = 0, boxColors[5] = {};
};

static const wchar_t *WORDS[] = {
    L"PLANET", L"BRIDGE", L"FALCON", L"SPIDER", L"WINTER",
    L"GARDEN", L"MIRROR", L"CASTLE", L"DRAGON", L"SILVER",
    L"FOREST", L"ROCKET", L"MARBLE", L"HUNTER", L"COBALT",
    L"STRIKE", L"VECTOR", L"TURRET", L"CANYON", L"PRISM"};
static const wchar_t *CNAMES[] = {L"RED", L"GREEN", L"BLUE", L"YELLOW", L"ORANGE"};
static const COLORREF CVALS[] = {
    RGB(210, 45, 45), RGB(45, 170, 45), RGB(45, 90, 210),
    RGB(210, 190, 0), RGB(210, 110, 0)};

std::wstring ScrambleWord(const std::wstring &w)
{
    std::wstring s = w;
    int t = 0;
    do
    {
        for (int i = (int)s.size() - 1; i > 0; --i)
            std::swap(s[i], s[CryptoRandRange(i + 1)]);
    } while (s == w && ++t < 20);
    return s;
}
std::wstring SpaceLetters(const std::wstring &w)
{
    std::wstring o;
    for (size_t i = 0; i < w.size(); ++i)
    {
        if (i)
            o += L' ';
        o += w[i];
    }
    return o;
}
std::wstring MakeToken()
{
    const wchar_t L2[] = L"ABCDEFGHJKLMNPQRSTUVWXYZ", D2[] = L"23456789";
    std::wstring t;
    for (int g = 0; g < 3; ++g)
    {
        if (g)
            t += L'-';
        t += L2[CryptoRandRange((DWORD)wcslen(L2))];
        t += D2[CryptoRandRange((DWORD)wcslen(D2))];
    }
    return t;
}
Challenge GenKBChallenge()
{
    Challenge c;
    c.type = (ChalType)CryptoRandRange(3);
    switch (c.type)
    {
    case ChalType::Scramble:
    {
        std::wstring w = WORDS[CryptoRandRange(20)];
        c.display = SpaceLetters(ScrambleWord(w));
        c.hint = L"Unscramble into a word";
        c.answer = w;
        break;
    }
    case ChalType::Hex:
    {
        BYTE code = (BYTE)(0x41 + CryptoRandRange(26));
        std::wostringstream ss;
        ss << L"0x" << std::uppercase << std::hex << std::setw(2) << std::setfill(L'0') << (int)code;
        c.display = ss.str();
        c.hint = L"Type the letter this hex value represents";
        c.answer = std::wstring(1, (wchar_t)code);
        break;
    }
    case ChalType::Token:
    {
        std::wstring tok = MakeToken();
        c.display = tok;
        c.hint = L"Type this code exactly";
        c.answer = tok;
        break;
    }
    default:
        break;
    }
    return c;
}
Challenge GenMouseChallenge()
{
    Challenge c;
    c.type = ChalType::MouseColor;
    c.colorIdx = (int)CryptoRandRange(5);
    int perm[5] = {0, 1, 2, 3, 4};
    for (int i = 4; i > 0; --i)
        std::swap(perm[i], perm[CryptoRandRange(i + 1)]);
    for (int i = 0; i < 5; i++)
        c.boxColors[i] = perm[i];
    for (int i = 0; i < 5; i++)
        if (c.boxColors[i] == c.colorIdx)
        {
            c.targetBox = i;
            break;
        }
    c.display = std::wstring(L"Click the ") + CNAMES[c.colorIdx] + L" box";
    return c;
}
bool WEqCI(const std::wstring &a, const std::wstring &b)
{
    if (a.size() != b.size())
        return false;
    for (size_t i = 0; i < a.size(); ++i)
        if (towupper(a[i]) != towupper(b[i]))
            return false;
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Timing analysis
// ─────────────────────────────────────────────────────────────────────────────
struct Timing
{
    std::vector<double> ts;
    void Add(double t) { ts.push_back(t); }
    void Reset() { ts.clear(); }
    bool IsHuman() const
    {
        if (ts.size() < 4)
            return true;
        std::vector<double> gaps;
        for (size_t i = 1; i < ts.size(); ++i)
            gaps.push_back(ts[i] - ts[i - 1]);
        double mean = 0;
        for (double g : gaps)
            mean += g;
        mean /= gaps.size();
        double var = 0;
        for (double g : gaps)
            var += (g - mean) * (g - mean);
        var /= gaps.size();
        return !(mean < 50.0 && std::sqrt(var) < 20.0);
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Feature toggles
// ─────────────────────────────────────────────────────────────────────────────
static bool g_allowListingEnabled = true;
static bool g_rememberBlockedEnabled = true;

// ─────────────────────────────────────────────────────────────────────────────
// Globals
// ─────────────────────────────────────────────────────────────────────────────
std::map<std::wstring, DevRecord> g_db;
std::set<HANDLE> g_trusted;
std::set<std::wstring> g_trustedNames;
// Removed g_trustedVIDPIDs - using instance-specific trust only
std::set<HANDLE> g_blocked;
std::set<HANDLE> g_pending;
std::mutex g_devMutex;

static HANDLE g_rawRing[4] = {};
static int g_rawRingIdx = 0;
static std::atomic<bool> g_captchaActive{false};

// [FIX 2] CAPTCHA queue ───────────────────────────────────────────────────────
struct CaptchaQueueItem
{
    HANDLE dev;
    DevClass dc;
};
static std::deque<CaptchaQueueItem> g_captchaQueue;
static std::mutex g_captchaQueueMtx;

HHOOK g_kbHook = NULL;
HWND g_hWnd = NULL;
HWND g_hMsgWnd = NULL;
HWND g_hCaptcha = NULL;
HWND g_hLog = NULL;
HWND g_hDevList = NULL;
HDEVNOTIFY g_hDevNotify = NULL;
HWND g_hTrayWnd = NULL;

static HWND g_hStaticLog = NULL;
static HWND g_hStaticDev = NULL;
static HWND g_hStaticSettings = NULL;
static HWND g_hBtnAllow = NULL;
static HWND g_hBtnBlock = NULL;
static HWND g_hBtnClear = NULL;
static HWND g_hBtnForget = NULL;
static HWND g_hBtnRefresh = NULL;
static HWND g_hChkAllowList = NULL;
static HWND g_hChkRemBlocked = NULL;

// Drag-splitter
static int g_logHeight = 160;
static bool g_splitterDrag = false;
static int g_dragBaseY = 0;
static int g_dragBaseLogH = 0;
static int g_splitterTopY = 0;
#define SPLITTER_H 6

static Challenge g_chal;
static HANDLE g_chalDev = NULL;
static DevClass g_chalDC = DevClass::Unknown;
static int g_wrong = 0;
static const int MAX_WRONG = 3;
static Timing g_timing;
static HWND g_mouseBoxHwnd[5] = {};
static std::wstring g_dbPath;

NOTIFYICONDATAW g_nid = {};
#define IDI_TRAY 1

// Forward declarations
void AppLog(const std::wstring &msg);
void RefreshDevList();
void ProcessCaptchaQueue();
void UpdateTrayTooltip();

// ─────────────────────────────────────────────────────────────────────────────
// Device path helpers
// ─────────────────────────────────────────────────────────────────────────────
std::wstring GetDevName(HANDLE h)
{
    UINT sz = 0;
    GetRawInputDeviceInfoW(h, RIDI_DEVICENAME, NULL, &sz);
    if (!sz)
        return L"<unknown>";
    std::vector<wchar_t> buf(sz);
    GetRawInputDeviceInfoW(h, RIDI_DEVICENAME, buf.data(), &sz);
    return std::wstring(buf.data());
}

std::wstring ExtractToken(const std::wstring &name, const std::wstring &prefix)
{
    auto p = name.find(prefix);
    if (p == std::wstring::npos)
        return L"";
    p += prefix.size();
    auto e = name.find_first_of(L"&#\\/", p);
    size_t len = (e == std::wstring::npos) ? 8 : e - p;
    if (len > 8)
        len = 8;
    return name.substr(p, len);
}
std::wstring GetVID(const std::wstring &n) { return ExtractToken(n, L"VID_"); }
std::wstring GetPID(const std::wstring &n) { return ExtractToken(n, L"PID_"); }

std::wstring GetInstanceId(const std::wstring &n)
{
    auto p1 = n.find(L'#');
    if (p1 == std::wstring::npos)
        return L"<none>";
    auto p2 = n.find(L'#', p1 + 1);
    if (p2 == std::wstring::npos)
        return L"<none>";
    auto p3 = n.find(L'#', p2 + 1);
    std::wstring inst = n.substr(p2 + 1, p3 == std::wstring::npos ? std::wstring::npos : p3 - p2 - 1);
    return inst.empty() ? L"<none>" : inst;
}
inline std::wstring GetSerial(const std::wstring &n) { return GetInstanceId(n); }

std::wstring ShortName(HANDLE h)
{
    std::wstring f = GetDevName(h);
    std::wstring vid = GetVID(f), pid = GetPID(f);
    if (!vid.empty() && !pid.empty())
        return L"VID_" + vid + L"&PID_" + pid;
    auto p = f.find(L"VID_");
    if (p != std::wstring::npos && f.size() > p + 16)
        return f.substr(p, 16);
    return f.size() > 40 ? f.substr(0, 40) + L"..." : f;
}

std::set<HANDLE> EnumByType(DWORD type)
{
    std::set<HANDLE> out;
    UINT n = 0;
    GetRawInputDeviceList(NULL, &n, sizeof(RAWINPUTDEVICELIST));
    if (!n)
        return out;
    std::vector<RAWINPUTDEVICELIST> list(n);
    if (GetRawInputDeviceList(list.data(), &n, sizeof(RAWINPUTDEVICELIST)) == (UINT)-1)
        return out;
    for (auto &d : list)
        if (d.dwType == type)
            out.insert(d.hDevice);
    return out;
}

std::wstring MakeDBKey(const std::wstring &fullName)
{
    return L"VID_" + GetVID(fullName) + L"&PID_" + GetPID(fullName) + L"&INST_" + GetInstanceId(fullName);
}

// ─────────────────────────────────────────────────────────────────────────────
// [FIX 1] Device key — VID + PID + Instance for arrival matching.
//
// Both dbcc_name (from WM_DEVICECHANGE) and RIDI_DEVICENAME embed all three
// tokens in the same '#'-separated path format, so we can match them directly.
// We normalise to uppercase for case-insensitive comparison.
// If instance extraction fails ("<none>") we fall back to VID+PID-only matching;
// this degrades gracefully to the pre-v4.2 behaviour for pathological paths.
// ─────────────────────────────────────────────────────────────────────────────
struct DevKey
{
    std::wstring vid, pid, inst;
};

static std::wstring ToUpper(std::wstring s)
{
    std::transform(s.begin(), s.end(), s.begin(), towupper);
    return s;
}
DevKey ExtractDevKey(const std::wstring &path)
{
    return {ToUpper(GetVID(path)), ToUpper(GetPID(path)), ToUpper(GetInstanceId(path))};
}
bool DevKeyMatch(const DevKey &a, const DevKey &b)
{
    if (a.vid.empty() || b.vid.empty())
        return false;
    if (a.vid != b.vid || a.pid != b.pid)
        return false;
    // If either instance is "<NONE>" (extraction failed) accept on VID+PID alone
    if (a.inst == L"<NONE>" || b.inst == L"<NONE>")
        return true;
    return a.inst == b.inst;
}

// ─────────────────────────────────────────────────────────────────────────────
// HID descriptor
// ─────────────────────────────────────────────────────────────────────────────
struct HIDDescriptor
{
    std::wstring manufacturer = L"<unknown>";
    std::wstring product = L"<unknown>";
    std::wstring usbSerial = L"<none>";
    USHORT version = 0;
};
HIDDescriptor GetHIDDescriptor(const std::wstring &devPath)
{
    // HidD_* functions unavailable on this toolchain — return defaults
    (void)devPath;
    return HIDDescriptor{};
}
DevRecord BuildRecord(HANDLE h)
{
    DevRecord r;
    r.fullName = GetDevName(h);
    r.vid = GetVID(r.fullName);
    r.pid = GetPID(r.fullName);
    r.instanceId = GetInstanceId(r.fullName);
    HIDDescriptor desc = GetHIDDescriptor(r.fullName);
    r.manufacturer = desc.manufacturer;
    r.product = desc.product;
    r.usbSerial = desc.usbSerial;
    r.version = desc.version;
    if (r.manufacturer != L"<unknown>" && r.product != L"<unknown>")
        r.friendly = r.manufacturer + L" " + r.product;
    else if (r.product != L"<unknown>")
        r.friendly = r.product;
    else
        r.friendly = L"VID_" + r.vid + L"&PID_" + r.pid;
    return r;
}

// ─────────────────────────────────────────────────────────────────────────────
// Persistent DB
// ─────────────────────────────────────────────────────────────────────────────
static std::string WtoA(const std::wstring &w)
{
    std::string s;
    for (wchar_t c : w)
        s += (c < 128 ? (char)c : '?');
    return s;
}
void SaveDB()
{
    if (g_dbPath.empty())
        return;
    std::ofstream f(WtoA(g_dbPath).c_str());
    if (!f)
        return;
    for (auto &kv : g_db)
    {
        auto &r = kv.second;
        char st = (r.status == DevRecord::Status::Allowed) ? 'A' : (r.status == DevRecord::Status::Blocked) ? 'B'
                                                                                                            : 'U';
        f << st << '|' << WtoA(r.vid) << '|' << WtoA(r.pid) << '|' << WtoA(r.instanceId)
          << '|' << WtoA(r.manufacturer) << '|' << WtoA(r.product) << '|' << WtoA(r.usbSerial)
          << '|' << r.version << '|' << WtoA(r.fullName) << '\n';
    }
}
static std::wstring SplitAt(const std::wstring &line, size_t &pos)
{
    auto e = line.find(L'|', pos);
    std::wstring tok = line.substr(pos, e == std::wstring::npos ? std::wstring::npos : e - pos);
    pos = (e == std::wstring::npos) ? line.size() : e + 1;
    return tok;
}
void LoadDB()
{
    if (g_dbPath.empty())
        return;
    std::ifstream f(WtoA(g_dbPath).c_str());
    if (!f)
        return;
    std::string lineA;
    while (std::getline(f, lineA))
    {
        if (lineA.size() < 3)
            continue;
        std::wstring line(lineA.begin(), lineA.end());
        wchar_t st = line[0];
        size_t pos = 2;
        DevRecord r;
        r.vid = SplitAt(line, pos);
        r.pid = SplitAt(line, pos);
        r.instanceId = SplitAt(line, pos);
        r.manufacturer = (pos < line.size()) ? SplitAt(line, pos) : L"<unknown>";
        r.product = (pos < line.size()) ? SplitAt(line, pos) : L"<unknown>";
        r.usbSerial = (pos < line.size()) ? SplitAt(line, pos) : L"<none>";
        if (pos < line.size())
        {
            std::wstring v = SplitAt(line, pos);
            r.version = (USHORT)_wtoi(v.c_str());
        }
        if (pos < line.size())
            r.fullName = SplitAt(line, pos);
        r.friendly = (r.manufacturer != L"<unknown>" && r.product != L"<unknown>")
                         ? r.manufacturer + L" " + r.product
                     : (r.product != L"<unknown>") ? r.product
                                                   : L"VID_" + r.vid + L"&PID_" + r.pid;
        if (st == L'A')
            r.status = DevRecord::Status::Allowed;
        else if (st == L'B')
            r.status = DevRecord::Status::Blocked;
        g_db[L"VID_" + r.vid + L"&PID_" + r.pid + L"&INST_" + r.instanceId] = r;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Log
// ─────────────────────────────────────────────────────────────────────────────
void AppLog(const std::wstring &msg)
{
    if (!g_hLog)
        return;
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t ts[32];
    swprintf_s(ts, L"[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    std::wstring line = std::wstring(ts) + msg;
    SendMessageW(g_hLog, LB_INSERTSTRING, 0, (LPARAM)line.c_str());
    int cnt = (int)SendMessageW(g_hLog, LB_GETCOUNT, 0, 0);
    if (cnt > 500)
        SendMessageW(g_hLog, LB_DELETESTRING, cnt - 1, 0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Device list - shows real-time connection status
// ─────────────────────────────────────────────────────────────────────────────
void RefreshDevList()
{
    if (!g_hDevList)
        return;
    SendMessageW(g_hDevList, LVM_DELETEALLITEMS, 0, 0);

    // Get all currently connected devices
    std::set<std::wstring> connectedNames;
    for (HANDLE h : EnumByType(RIM_TYPEKEYBOARD))
        connectedNames.insert(GetDevName(h));
    for (HANDLE h : EnumByType(RIM_TYPEMOUSE))
        connectedNames.insert(GetDevName(h));

    int row = 0;
    std::lock_guard<std::mutex> lk(g_devMutex);
    for (auto &kv : g_db)
    {
        auto &r = kv.second;
        const wchar_t *stStr = (r.status == DevRecord::Status::Allowed) ? L"ALLOWED" : (r.status == DevRecord::Status::Blocked) ? L"BLOCKED"
                                                                                                                                : L"unknown";
        // Check if device is currently connected
        bool connected = connectedNames.count(r.fullName) > 0;
        const wchar_t *connStr = connected ? L"YES" : L"NO";

        LVITEMW lvi = {};
        lvi.mask = LVIF_TEXT;
        lvi.iItem = row;
        lvi.iSubItem = 0;
        lvi.pszText = (LPWSTR)connStr; // First column: Connected status
        SendMessageW(g_hDevList, LVM_INSERTITEMW, 0, (LPARAM)&lvi);
        auto setCol = [&](int col, const std::wstring &text)
        {
            lvi.iSubItem = col;
            lvi.pszText = (LPWSTR)text.c_str();
            SendMessageW(g_hDevList, LVM_SETITEMW, 0, (LPARAM)&lvi);
        };
        setCol(1, stStr);
        setCol(2, r.manufacturer);
        setCol(3, r.product);
        setCol(4, r.usbSerial);
        setCol(5, r.vid);
        setCol(6, r.pid);
        setCol(7, r.instanceId);
        row++;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Trust helpers - INSTANCE-SPECIFIC trust only
// ─────────────────────────────────────────────────────────────────────────────
void RebuildTrustFromDB()
{
    g_trustedNames.clear();
    // Removed g_trustedVIDPIDs - we only trust specific instances, not all devices with same VID+PID
    for (auto &kv : g_db)
    {
        if (kv.second.status == DevRecord::Status::Allowed)
        {
            g_trustedNames.insert(kv.second.fullName);
        }
    }
}
DevRecord::Status DBStatus(HANDLE h)
{
    std::wstring n = GetDevName(h);
    auto it = g_db.find(MakeDBKey(n));
    if (it != g_db.end())
        return it->second.status;
    // Removed VID+PID fallback - instance-specific only
    return DevRecord::Status::Unknown;
}
bool IsTrusted(HANDLE h)
{
    if (g_trusted.count(h))
        return true;
    std::wstring n = GetDevName(h);
    if (g_trustedNames.count(n))
        return true;
    // Removed VID+PID check - instance-specific trust only
    return false;
}
void TrustDev(HANDLE h)
{
    std::wstring n = GetDevName(h);
    g_trusted.insert(h);
    g_trustedNames.insert(n);
    // Removed VID+PID insertion - instance-specific trust only
}

// Trust only THIS SPECIFIC INSTANCE (for CAPTCHA pass - session-only trust)
void TrustDevInstanceOnly(HANDLE h)
{
    std::wstring n = GetDevName(h);
    g_trusted.insert(h);      // Trust this handle only
    g_trustedNames.insert(n); // Trust this specific instance path only
    // Do NOT add to g_trustedVIDPIDs - other instances still need CAPTCHA
}

// ─────────────────────────────────────────────────────────────────────────────
// Tray tooltip — shows queue depth when non-empty
// ─────────────────────────────────────────────────────────────────────────────
void UpdateTrayTooltip()
{
    if (!g_hTrayWnd)
        return;
    size_t queued;
    {
        std::lock_guard<std::mutex> lk(g_captchaQueueMtx);
        queued = g_captchaQueue.size();
    }
    // +1 if a CAPTCHA is actively being shown
    size_t total = queued + (g_captchaActive.load() ? 1 : 0);
    if (total > 0)
        swprintf_s(g_nid.szTip, L"USB Gatekeeper — %zu device(s) pending CAPTCHA", (size_t)total);
    else
        wcscpy_s(g_nid.szTip, L"USB Gatekeeper — Active");
    Shell_NotifyIconW(NIM_MODIFY, &g_nid);
}

// ─────────────────────────────────────────────────────────────────────────────
// [FIX 2] CAPTCHA queue driver
//
// Called from:
//   • ShowCaptcha()         — a new device needs a CAPTCHA
//   • WM_NEXT_CAPTCHA       — a captcha thread just finished (any outcome)
//
// Invariant: g_captchaActive is only true while a CaptchaThread is running.
// The thread always sets g_captchaActive=false then posts WM_NEXT_CAPTCHA before
// it returns, so no device is ever left stuck in the queue.
// ─────────────────────────────────────────────────────────────────────────────
void ProcessCaptchaQueue()
{
    // Loop so we can skip queue entries whose device is no longer blocked
    // (e.g. manually allowed or disconnected while waiting in queue).
    while (true)
    {
        bool expected = false;
        if (!g_captchaActive.compare_exchange_strong(expected, true))
            return; // Another captcha is already showing; come back on WM_NEXT_CAPTCHA

        CaptchaQueueItem next{};
        bool found = false;

        while (true)
        {
            {
                std::lock_guard<std::mutex> lk(g_captchaQueueMtx);
                if (g_captchaQueue.empty())
                    break;
                next = g_captchaQueue.front();
                g_captchaQueue.pop_front();
            }
            {
                std::lock_guard<std::mutex> lk(g_devMutex);
                if (g_blocked.count(next.dev))
                {
                    found = true;
                    break;
                }
                // Device was allowed/disconnected while waiting — clean up pending
                g_pending.erase(next.dev);
            }
        }

        if (!found)
        {
            g_captchaActive = false;
            UpdateTrayTooltip();
            return;
        }

        g_chalDev = next.dev;
        g_chalDC = next.dc;

        HANDLE ht = CreateThread(NULL, 0, [](LPVOID) -> DWORD
                                 {
                // Defined below; forward-declared via function pointer trick.
                // Actual body is CaptchaThread — redeclared at definition site.
                extern DWORD WINAPI CaptchaThread(LPVOID);
                return CaptchaThread(NULL); }, NULL, 0, NULL);

        if (ht)
        {
            CloseHandle(ht);
            UpdateTrayTooltip();
            return;
        }

        // Thread creation failed — release the lock and try the next item
        g_captchaActive = false;
        AppLog(L"[ERROR] CaptchaThread creation failed");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Approve / Deny
// NOTE: g_captchaActive is intentionally NOT cleared here.
//       The captcha thread sets it to false and posts WM_NEXT_CAPTCHA just
//       before it exits, so the queue always advances correctly.
// ─────────────────────────────────────────────────────────────────────────────
// ─────────────────────────────────────────────────────────────────────────────
// [SESSION-ONLY TRUST] ApproveDevice — CAPTCHA pass grants session-only trust
//
// Passing the CAPTCHA only trusts the device for THIS SESSION. The device
// remains Status::Unknown in the database and will require CAPTCHA on next replug.
// Use the "Allow Selected" button in the GUI for permanent allow-listing.
// ─────────────────────────────────────────────────────────────────────────────
void ApproveDevice(HANDLE dev)
{
    {
        std::lock_guard<std::mutex> lk(g_devMutex);
        TrustDev(dev); // Add to session trust (g_trusted, g_trustedNames, g_trustedVIDPIDs)

        // Ensure device record exists in DB, but keep status as Unknown
        DevRecord r = BuildRecord(dev);
        std::wstring dbk = MakeDBKey(r.fullName);
        if (!g_db.count(dbk))
        {
            r.status = DevRecord::Status::Unknown; // NOT Allowed!
            g_db[dbk] = r;
        }
        // If it already exists, don't change its status

        g_trusted.insert(dev);
        for (auto it = g_blocked.begin(); it != g_blocked.end();)
            it = IsTrusted(*it) ? g_blocked.erase(it) : ++it;
        for (auto it = g_pending.begin(); it != g_pending.end();)
            it = IsTrusted(*it) ? g_pending.erase(it) : ++it;
        for (int i = 0; i < 4; i++)
            g_rawRing[i] = NULL;
    }
    // Don't call SaveDB() - we're not changing persistent state
    AppLog(L"[APPROVED] " + ShortName(dev) + L" (session only — use 'Allow Selected' for permanent)");
    g_chalDev = NULL;
    g_hCaptcha = NULL;
    RefreshDevList();
}

// ─────────────────────────────────────────────────────────────────────────────
// [SECURITY FIX 2] DenyDevice — session-only block, does NOT save to DB
//
// When a CAPTCHA is denied/timed out, the device is blocked for this session
// but remains Status::Unknown in the database. On replug, the CAPTCHA will run
// again. Only manual "Allow" via the GUI saves it as Status::Allowed.
//
// The "Remember-Blocked" setting now only applies to manual blocking via the GUI
// button, not to CAPTCHA denial.
// ─────────────────────────────────────────────────────────────────────────────
void DenyDevice(HANDLE dev)
{
    if (!dev)
        return; // [FIX 2] guard: device handle cleared externally (disconnect)
    {
        std::lock_guard<std::mutex> lk(g_devMutex);
        g_pending.erase(dev);
        g_blocked.insert(dev);
        // [SECURITY FIX 2] Do NOT save to DB when denying CAPTCHA
        // Device stays as Status::Unknown and will require CAPTCHA on replug
    }
    AppLog(L"[BLOCKED] " + ShortName(dev) + L" (session only — CAPTCHA required on replug)");
    g_chalDev = NULL;
    g_hCaptcha = NULL;
    RefreshDevList();
}

// ─────────────────────────────────────────────────────────────────────────────
// Manual allow / block / forget
// Uses WM_DISMISS_CAPTCHA for cross-thread-safe captcha closure.
// ─────────────────────────────────────────────────────────────────────────────
void ManualAllow(const std::wstring &dbKey)
{
    std::wstring friendly, fullName;
    {
        std::lock_guard<std::mutex> lk(g_devMutex);
        auto it = g_db.find(dbKey);
        if (it == g_db.end())
            return;
        it->second.status = DevRecord::Status::Allowed;
        friendly = it->second.friendly;
        fullName = it->second.fullName;
        RebuildTrustFromDB();

        // Clear from blocked/pending if currently connected
        auto clearSets = [&](std::set<HANDLE> &s)
        {
            for (auto it2 = s.begin(); it2 != s.end();)
            {
                if (GetDevName(*it2) == fullName)
                    it2 = s.erase(it2);
                else
                    ++it2;
            }
        };
        clearSets(g_blocked);
        clearSets(g_pending);
        for (int i = 0; i < 4; i++)
            g_rawRing[i] = NULL;

        // Close captcha if it's showing for this exact device
        if (g_chalDev && GetDevName(g_chalDev) == fullName)
        {
            g_chalDev = NULL;
            if (g_hCaptcha)
            {
                PostMessageW(g_hCaptcha, WM_DISMISS_CAPTCHA, 0, 0);
                g_hCaptcha = NULL;
            }
        }
    }
    SaveDB();
    AppLog(L"[MANUAL ALLOW] " + friendly);
    RefreshDevList();
}

void ManualBlock(const std::wstring &dbKey)
{
    std::wstring friendly, fullName;
    {
        std::lock_guard<std::mutex> lk(g_devMutex);
        auto it = g_db.find(dbKey);
        if (it == g_db.end())
            return;
        it->second.status = DevRecord::Status::Blocked;
        friendly = it->second.friendly;
        fullName = it->second.fullName;
        RebuildTrustFromDB();

        // Process currently connected devices with this exact instance
        auto processHandles = [&](const std::set<HANDLE> &handles)
        {
            for (HANDLE h : handles)
            {
                std::wstring dn = GetDevName(h);
                if (dn == fullName)
                {
                    g_trusted.erase(h);
                    g_trustedNames.erase(dn);
                    g_blocked.insert(h);
                }
            }
        };
        processHandles(EnumByType(RIM_TYPEKEYBOARD));
        processHandles(EnumByType(RIM_TYPEMOUSE));
    }
    SaveDB();
    AppLog(L"[MANUAL BLOCK] " + friendly);
    RefreshDevList();
}

void ManualForget(const std::wstring &dbKey)
{
    std::wstring friendly, fullName;
    {
        std::lock_guard<std::mutex> lk(g_devMutex);
        auto it = g_db.find(dbKey);
        if (it == g_db.end())
            return;
        friendly = it->second.friendly;
        fullName = it->second.fullName;
        it->second.status = DevRecord::Status::Unknown;
        RebuildTrustFromDB();

        auto removeHandles = [&](std::set<HANDLE> &s)
        {
            for (auto hit = s.begin(); hit != s.end();)
            {
                if (GetDevName(*hit) == fullName)
                    hit = s.erase(hit);
                else
                    ++hit;
            }
        };
        removeHandles(g_trusted);
        removeHandles(g_pending);

        // Block the device if currently connected
        for (HANDLE h : EnumByType(RIM_TYPEKEYBOARD))
        {
            if (GetDevName(h) == fullName)
                g_blocked.insert(h);
        }
        for (HANDLE h : EnumByType(RIM_TYPEMOUSE))
        {
            if (GetDevName(h) == fullName)
                g_blocked.insert(h);
        }
        for (int i = 0; i < 4; i++)
            g_rawRing[i] = NULL;

        if (g_chalDev && GetDevName(g_chalDev) == fullName)
        {
            g_chalDev = NULL;
            if (g_hCaptcha)
            {
                PostMessageW(g_hCaptcha, WM_DISMISS_CAPTCHA, 0, 0);
                g_hCaptcha = NULL;
            }
        }
    }
    SaveDB();
    AppLog(L"[FORGOTTEN] " + friendly + L" — CAPTCHA required on next plug-in");
    RefreshDevList();
}

// ─────────────────────────────────────────────────────────────────────────────
// CAPTCHA window proc
// ─────────────────────────────────────────────────────────────────────────────
LRESULT CALLBACK CaptchaProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp)
{
    static HBRUSH hBg = NULL, hEdit = NULL;
    static HFONT hFontB = NULL, hFontM = NULL;
    static HBRUSH hBox[5] = {};

    auto Cleanup = [&]()
    {
        if (hBg)
        {
            DeleteObject(hBg);
            hBg = NULL;
        }
        if (hEdit)
        {
            DeleteObject(hEdit);
            hEdit = NULL;
        }
        if (hFontB)
        {
            DeleteObject(hFontB);
            hFontB = NULL;
        }
        if (hFontM)
        {
            DeleteObject(hFontM);
            hFontM = NULL;
        }
        for (auto &b : hBox)
            if (b)
            {
                DeleteObject(b);
                b = NULL;
            }
    };

    // helper to (re)start the inactivity timer
    auto ResetTimer = [&]()
    {
        if (CAPTCHA_TIMEOUT_MS > 0)
        {
            KillTimer(hw, CAPTCHA_TIMER_ID);
            SetTimer(hw, CAPTCHA_TIMER_ID, CAPTCHA_TIMEOUT_MS, NULL);
        }
    };

    switch (msg)
    {
    case WM_CREATE:
    {
        hBg = CreateSolidBrush(RGB(18, 22, 40));
        hEdit = CreateSolidBrush(RGB(30, 35, 60));
        hFontB = CreateFontW(18, 0, 0, 0, FW_SEMIBOLD, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                             CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        hFontM = CreateFontW(17, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                             CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, FIXED_PITCH, L"Consolas");
        HWND hIco = CreateWindowExW(0, L"STATIC", NULL, WS_CHILD | WS_VISIBLE | SS_ICON,
                                    16, 14, 32, 32, hw, (HMENU)200, GetModuleHandleW(NULL), NULL);
        SendMessageW(hIco, STM_SETICON, (WPARAM)LoadIconW(NULL, IDI_WARNING), 0);
        std::wstring title = (g_chalDC == DevClass::Mouse) ? L"New USB Mouse — Security Challenge" : L"New USB Keyboard — Security Challenge";
        HWND hTitle = CreateWindowExW(0, L"STATIC", title.c_str(), WS_CHILD | WS_VISIBLE | SS_LEFT,
                                      56, 16, 440, 22, hw, (HMENU)201, GetModuleHandleW(NULL), NULL);
        SendMessageW(hTitle, WM_SETFONT, (WPARAM)hFontB, TRUE);
        CreateWindowExW(0, L"STATIC", NULL, WS_CHILD | WS_VISIBLE | SS_ETCHEDHORZ,
                        12, 50, 480, 2, hw, (HMENU)202, GetModuleHandleW(NULL), NULL);
        if (g_chalDC == DevClass::Mouse)
        {
            HWND hP = CreateWindowExW(0, L"STATIC", g_chal.display.c_str(),
                                      WS_CHILD | WS_VISIBLE | SS_CENTER, 12, 60, 480, 28, hw,
                                      (HMENU)IDC_LABEL, GetModuleHandleW(NULL), NULL);
            SendMessageW(hP, WM_SETFONT, (WPARAM)hFontB, TRUE);
            CreateWindowExW(0, L"STATIC", L"3 attempts remaining", WS_CHILD | WS_VISIBLE | SS_CENTER,
                            12, 90, 480, 18, hw, (HMENU)IDC_SUBLABEL, GetModuleHandleW(NULL), NULL);
            for (int i = 0; i < 5; i++)
            {
                int ci = g_chal.boxColors[i];
                hBox[i] = CreateSolidBrush(CVALS[ci]);
                g_mouseBoxHwnd[i] = CreateWindowExW(WS_EX_CLIENTEDGE, L"BUTTON", CNAMES[ci],
                                                    WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                                                    12 + i * 92, 116, 86, 62, hw,
                                                    (HMENU)(UINT_PTR)(IDC_T1 + i),
                                                    GetModuleHandleW(NULL), NULL);
            }
            CreateWindowExW(0, L"BUTTON", L"Deny Access", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                            185, 194, 120, 30, hw, (HMENU)IDC_DENY, GetModuleHandleW(NULL), NULL);
        }
        else
        {
            HWND hDisp = CreateWindowExW(0, L"STATIC", g_chal.display.c_str(),
                                         WS_CHILD | WS_VISIBLE | SS_CENTER, 12, 60, 480, 52, hw,
                                         (HMENU)IDC_LABEL, GetModuleHandleW(NULL), NULL);
            SendMessageW(hDisp, WM_SETFONT, (WPARAM)hFontB, TRUE);
            CreateWindowExW(0, L"STATIC", g_chal.hint.c_str(), WS_CHILD | WS_VISIBLE | SS_CENTER,
                            12, 116, 480, 18, hw, (HMENU)IDC_SUBLABEL, GetModuleHandleW(NULL), NULL);
            HWND hE = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
                                      WS_CHILD | WS_VISIBLE | ES_CENTER | ES_AUTOHSCROLL,
                                      148, 142, 196, 28, hw, (HMENU)IDC_INPUT,
                                      GetModuleHandleW(NULL), NULL);
            SendMessageW(hE, WM_SETFONT, (WPARAM)hFontM, TRUE);
            HWND hSub = CreateWindowExW(0, L"BUTTON", L"Submit",
                                        WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                                        108, 182, 114, 32, hw, (HMENU)IDC_SUBMIT,
                                        GetModuleHandleW(NULL), NULL);
            SendMessageW(hSub, WM_SETFONT, (WPARAM)hFontB, TRUE);
            CreateWindowExW(0, L"BUTTON", L"Deny Access", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                            270, 182, 114, 32, hw, (HMENU)IDC_DENY,
                            GetModuleHandleW(NULL), NULL);
            SetFocus(GetDlgItem(hw, IDC_INPUT));
        }
        g_wrong = 0;
        g_timing.Reset();
        ResetTimer(); // start inactivity timer
        return 0;
    }

    // Inactivity timeout → auto-deny
    case WM_TIMER:
        if (wp == CAPTCHA_TIMER_ID)
        {
            KillTimer(hw, CAPTCHA_TIMER_ID);
            AppLog(L"[AUTO-DENY] CAPTCHA timed out — device blocked");
            SendMessageW(hw, WM_COMMAND, IDC_DENY, 0);
        }
        return 0;

    // [FIX 2] Clean dismissal: device manually allowed/forgotten, or disconnected.
    // Does NOT call DenyDevice; the captcha thread will handle g_captchaActive.
    case WM_DISMISS_CAPTCHA:
        KillTimer(hw, CAPTCHA_TIMER_ID);
        Cleanup();
        DestroyWindow(hw);
        PostQuitMessage(0);
        return 0;

    case WM_COMMAND:
    {
        // [FIX 2] Capture g_chalDev immediately; it may be NULL'd from another thread.
        HANDLE dev = g_chalDev;
        int id = LOWORD(wp);

        if (id == IDC_SUBMIT || id == IDOK)
        {
            wchar_t buf[128] = {};
            GetDlgItemTextW(hw, IDC_INPUT, buf, 127);
            std::wstring input(buf);
            auto b = input.find_first_not_of(L" \t"), e = input.find_last_not_of(L" \t");
            input = (b == std::wstring::npos) ? L"" : input.substr(b, e - b + 1);

            if (!g_timing.IsHuman())
            {
                g_wrong++;
                g_timing.Reset();
                MessageBeep(MB_ICONEXCLAMATION);
                if (g_wrong >= MAX_WRONG)
                    goto deny;
                SetDlgItemTextW(hw, IDC_SUBLABEL,
                                (L"Robotic input! " + std::to_wstring(MAX_WRONG - g_wrong) + L" left").c_str());
                g_chal = GenKBChallenge();
                SetDlgItemTextW(hw, IDC_LABEL, g_chal.display.c_str());
                SetDlgItemTextW(hw, IDC_INPUT, L"");
                SetFocus(GetDlgItem(hw, IDC_INPUT));
                ResetTimer();
                return 0;
            }
            if (WEqCI(input, g_chal.answer))
            {
                KillTimer(hw, CAPTCHA_TIMER_ID);
                ApproveDevice(dev);
                Cleanup();
                DestroyWindow(hw);
                PostQuitMessage(0);
            }
            else
            {
                g_wrong++;
                g_timing.Reset();
                MessageBeep(MB_ICONEXCLAMATION);
                if (g_wrong >= MAX_WRONG)
                {
                    MessageBoxW(hw, L"Max attempts. Device blocked.", L"Blocked",
                                MB_OK | MB_ICONERROR | MB_TOPMOST);
                    goto deny;
                }
                SetDlgItemTextW(hw, IDC_SUBLABEL,
                                (L"Wrong. " + std::to_wstring(MAX_WRONG - g_wrong) + L" left").c_str());
                g_chal = GenKBChallenge();
                SetDlgItemTextW(hw, IDC_LABEL, g_chal.display.c_str());
                SetDlgItemTextW(hw, IDC_INPUT, L"");
                SetFocus(GetDlgItem(hw, IDC_INPUT));
                ResetTimer();
            }
            return 0;
        }
        if (id >= IDC_T1 && id <= IDC_T5)
        {
            int clicked = id - IDC_T1;
            if (clicked == g_chal.targetBox)
            {
                KillTimer(hw, CAPTCHA_TIMER_ID);
                ApproveDevice(dev);
                Cleanup();
                DestroyWindow(hw);
                PostQuitMessage(0);
            }
            else
            {
                g_wrong++;
                MessageBeep(MB_ICONEXCLAMATION);
                if (g_wrong >= MAX_WRONG)
                    goto deny;
                SetDlgItemTextW(hw, IDC_SUBLABEL,
                                (L"Wrong box. " + std::to_wstring(MAX_WRONG - g_wrong) + L" left").c_str());
                g_chal = GenMouseChallenge();
                SetDlgItemTextW(hw, IDC_LABEL, g_chal.display.c_str());
                for (int i = 0; i < 5; i++)
                {
                    int ci = g_chal.boxColors[i];
                    SetWindowTextW(g_mouseBoxHwnd[i], CNAMES[ci]);
                    if (hBox[i])
                        DeleteObject(hBox[i]);
                    hBox[i] = CreateSolidBrush(CVALS[ci]);
                    InvalidateRect(g_mouseBoxHwnd[i], NULL, TRUE);
                }
                ResetTimer();
            }
            return 0;
        }
        if (id == IDC_DENY || id == IDCANCEL)
        {
        deny:
            KillTimer(hw, CAPTCHA_TIMER_ID);
            DenyDevice(dev); // dev may be NULL → DenyDevice guards for that
            Cleanup();
            DestroyWindow(hw);
            PostQuitMessage(0);
            return 0;
        }
        return 0;
    }

    case WM_KEYDOWN:
        if ((HWND)GetFocus() == GetDlgItem(hw, IDC_INPUT))
            g_timing.Add((double)GetTickCount64());
        ResetTimer(); // any keystroke resets the timeout
        return DefWindowProcW(hw, msg, wp, lp);

    case WM_CTLCOLORBTN:
    {
        HWND hC = (HWND)lp;
        for (int i = 0; i < 5; i++)
            if (hC == g_mouseBoxHwnd[i] && hBox[i])
            {
                SetTextColor((HDC)wp, RGB(255, 255, 255));
                SetBkMode((HDC)wp, TRANSPARENT);
                return (LRESULT)hBox[i];
            }
        return DefWindowProcW(hw, msg, wp, lp);
    }
    case WM_ERASEBKGND:
    {
        RECT rc;
        GetClientRect(hw, &rc);
        FillRect((HDC)wp, &rc, hBg);
        return 1;
    }
    case WM_CTLCOLORSTATIC:
        SetBkMode((HDC)wp, TRANSPARENT);
        SetTextColor((HDC)wp, RGB(200, 215, 255));
        return (LRESULT)hBg;
    case WM_CTLCOLOREDIT:
        SetBkColor((HDC)wp, RGB(30, 35, 60));
        SetTextColor((HDC)wp, RGB(220, 235, 255));
        return (LRESULT)hEdit;
    case WM_CLOSE:
        SendMessageW(hw, WM_COMMAND, IDC_DENY, 0);
        return 0;
    case WM_DESTROY:
        Cleanup();
        return 0;
    }
    return DefWindowProcW(hw, msg, wp, lp);
}

// ─────────────────────────────────────────────────────────────────────────────
// CAPTCHA thread
// [FIX 2] On exit: always clears g_captchaActive and posts WM_NEXT_CAPTCHA so
//         ProcessCaptchaQueue() advances to the next queued device.
// ─────────────────────────────────────────────────────────────────────────────
DWORD WINAPI CaptchaThread(LPVOID)
{
    g_wrong = 0;
    g_timing.Reset();
    g_chal = (g_chalDC == DevClass::Mouse) ? GenMouseChallenge() : GenKBChallenge();

    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    static bool regKB = false, regM = false;
    if (g_chalDC == DevClass::Mouse && !regM)
    {
        WNDCLASSW wc = {};
        wc.lpfnWndProc = CaptchaProc;
        wc.hInstance = GetModuleHandleW(NULL);
        wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
        wc.lpszClassName = L"CaptchaMouse";
        wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
        RegisterClassW(&wc);
        regM = true;
    }
    if (g_chalDC != DevClass::Mouse && !regKB)
    {
        WNDCLASSW wc = {};
        wc.lpfnWndProc = CaptchaProc;
        wc.hInstance = GetModuleHandleW(NULL);
        wc.hbrBackground = (HBRUSH)GetStockObject(BLACK_BRUSH);
        wc.lpszClassName = L"CaptchaKeyboard";
        wc.hCursor = LoadCursorW(NULL, IDC_ARROW);
        RegisterClassW(&wc);
        regKB = true;
    }
    const wchar_t *cls = (g_chalDC == DevClass::Mouse) ? L"CaptchaMouse" : L"CaptchaKeyboard";
    int w = 510, h = (g_chalDC == DevClass::Mouse ? 244 : 270);
    g_hCaptcha = CreateWindowExW(WS_EX_TOPMOST | WS_EX_DLGMODALFRAME, cls, L"USB Gatekeeper",
                                 WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_VISIBLE,
                                 (sw - w) / 2, (sh - h) / 2, w, h, NULL, NULL, GetModuleHandleW(NULL), NULL);
    ShowWindow(g_hCaptcha, SW_SHOWNORMAL);
    UpdateWindow(g_hCaptcha);
    SetForegroundWindow(g_hCaptcha);

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        if (!IsDialogMessageW(g_hCaptcha, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    // [FIX 2] Always release the active flag and drive the queue forward.
    g_captchaActive = false;
    PostMessageW(g_hMsgWnd, WM_NEXT_CAPTCHA, 0, 0);
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// [FIX 2] ShowCaptcha — enqueues the device; ProcessCaptchaQueue shows it when
//         the current CAPTCHA (if any) is resolved.
// ─────────────────────────────────────────────────────────────────────────────
void ShowCaptcha(HANDLE hDev, DevClass dc)
{
    {
        std::lock_guard<std::mutex> lk(g_devMutex);
        if (g_pending.count(hDev))
            return; // already queued or active
        g_pending.insert(hDev);
    }
    {
        std::lock_guard<std::mutex> lk(g_captchaQueueMtx);
        g_captchaQueue.push_back({hDev, dc});
    }
    UpdateTrayTooltip();
    ProcessCaptchaQueue();
}

// ─────────────────────────────────────────────────────────────────────────────
// Low-level keyboard hook (unchanged)
// ─────────────────────────────────────────────────────────────────────────────
LRESULT CALLBACK LowLevelKBProc(int nCode, WPARAM wp, LPARAM lp)
{
    if (nCode == HC_ACTION)
    {
        auto *kb = reinterpret_cast<KBDLLHOOKSTRUCT *>(lp);
        // Layer 1: block software injection
        if (kb->flags & LLKHF_INJECTED)
        {
            wchar_t kn[32] = L"?";
            UINT sc = MapVirtualKeyW(kb->vkCode, MAPVK_VK_TO_VSC);
            GetKeyNameTextW((LONG)(sc << 16), kn, 32);
            std::wostringstream _s;
            _s << std::hex << std::uppercase << kb->vkCode;
            AppLog(L"[BLOCKED] Injection: VK=0x" + _s.str() + L" (" + kn + L")");
            return 1;
        }
        // Layer 2: block keys outside captcha during active challenge
        if (g_captchaActive && g_chalDC == DevClass::Keyboard && g_hCaptcha)
        {
            if (GetForegroundWindow() != g_hCaptcha)
            {
                wchar_t kn[32] = L"?";
                UINT sc = MapVirtualKeyW(kb->vkCode, MAPVK_VK_TO_VSC);
                GetKeyNameTextW((LONG)(sc << 16), kn, 32);
                AppLog(L"[BLOCKED] Key outside captcha: (" + std::wstring(kn) + L")");
                return 1;
            }
        }
        // Layer 3: ring buffer — block keys from blocked device
        {
            std::lock_guard<std::mutex> lk(g_devMutex);
            if (!g_blocked.empty())
            {
                for (int i = 0; i < 4; i++)
                {
                    if (g_rawRing[i] && g_blocked.count(g_rawRing[i]))
                    {
                        wchar_t kn[32] = L"?";
                        UINT sc = MapVirtualKeyW(kb->vkCode, MAPVK_VK_TO_VSC);
                        GetKeyNameTextW((LONG)(sc << 16), kn, 32);
                        AppLog(L"[BLOCKED] Device key: (" + std::wstring(kn) + L")");
                        return 1;
                    }
                }
            }
        }
    }
    return CallNextHookEx(g_kbHook, nCode, wp, lp);
}

// ─────────────────────────────────────────────────────────────────────────────
// Layout (unchanged)
// ─────────────────────────────────────────────────────────────────────────────
static void LayoutMainWindow(int W, int H)
{
    const int PAD = 8, LABEL_H = 16, BTN_H = 28, BTN_W = 130, CHK_H = 20, CHK_W = 280;
    int y = PAD;
    if (g_hStaticLog)
        SetWindowPos(g_hStaticLog, NULL, PAD, y, W - PAD * 2, LABEL_H, SWP_NOZORDER);
    y += LABEL_H + 2;
    int logH = g_logHeight;
    if (logH < 40)
        logH = 40;
    if (logH > H - 280)
        logH = H - 280;
    if (g_hLog)
        SetWindowPos(g_hLog, NULL, PAD, y, W - PAD * 2, logH, SWP_NOZORDER);
    y += logH;
    g_splitterTopY = y;
    y += SPLITTER_H + 4;
    if (g_hStaticSettings)
        SetWindowPos(g_hStaticSettings, NULL, PAD, y, W - PAD * 2, LABEL_H, SWP_NOZORDER);
    y += LABEL_H + 2;
    if (g_hChkAllowList)
        SetWindowPos(g_hChkAllowList, NULL, PAD, y, CHK_W, CHK_H, SWP_NOZORDER);
    if (g_hChkRemBlocked)
        SetWindowPos(g_hChkRemBlocked, NULL, PAD + CHK_W + 8, y, CHK_W, CHK_H, SWP_NOZORDER);
    y += CHK_H + PAD;
    if (g_hStaticDev)
        SetWindowPos(g_hStaticDev, NULL, PAD, y, W - PAD * 2, LABEL_H, SWP_NOZORDER);
    y += LABEL_H + 2;
    int listBottom = H - PAD - BTN_H - PAD;
    int listH = listBottom - y;
    if (listH < 60)
        listH = 60;
    if (g_hDevList)
        SetWindowPos(g_hDevList, NULL, PAD, y, W - PAD * 2, listH, SWP_NOZORDER);
    y = listBottom + PAD;
    if (g_hBtnAllow)
        SetWindowPos(g_hBtnAllow, NULL, PAD + (BTN_W + PAD) * 0, y, BTN_W, BTN_H, SWP_NOZORDER);
    if (g_hBtnBlock)
        SetWindowPos(g_hBtnBlock, NULL, PAD + (BTN_W + PAD) * 1, y, BTN_W, BTN_H, SWP_NOZORDER);
    if (g_hBtnClear)
        SetWindowPos(g_hBtnClear, NULL, PAD + (BTN_W + PAD) * 2, y, BTN_W, BTN_H, SWP_NOZORDER);
    if (g_hBtnForget)
        SetWindowPos(g_hBtnForget, NULL, PAD + (BTN_W + PAD) * 3, y, BTN_W, BTN_H, SWP_NOZORDER);
    if (g_hBtnRefresh)
        SetWindowPos(g_hBtnRefresh, NULL, PAD + (BTN_W + PAD) * 4, y, BTN_W, BTN_H, SWP_NOZORDER);
}

// ─────────────────────────────────────────────────────────────────────────────
// Main GUI window proc (unchanged except WM_SIZE repaints the splitter)
// ─────────────────────────────────────────────────────────────────────────────
LRESULT CALLBACK MainWndProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg)
    {
    case WM_CREATE:
    {
        HFONT hF = CreateFontW(14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                               CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        auto mkStatic = [&](const wchar_t *txt, HMENU id) -> HWND
        {
            HWND h=CreateWindowExW(0,L"STATIC",txt,WS_CHILD|WS_VISIBLE,0,0,0,0,hw,id,GetModuleHandleW(NULL),NULL);
            SendMessageW(h,WM_SETFONT,(WPARAM)hF,TRUE); return h; };
        auto mkChk = [&](const wchar_t *txt, HMENU id) -> HWND
        {
            HWND h=CreateWindowExW(0,L"BUTTON",txt,WS_CHILD|WS_VISIBLE|BS_AUTOCHECKBOX,0,0,0,0,hw,id,GetModuleHandleW(NULL),NULL);
            SendMessageW(h,WM_SETFONT,(WPARAM)hF,TRUE); return h; };
        auto mkBtn = [&](const wchar_t *txt, HMENU id) -> HWND
        {
            HWND h=CreateWindowExW(0,L"BUTTON",txt,WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,0,0,0,0,hw,id,GetModuleHandleW(NULL),NULL);
            SendMessageW(h,WM_SETFONT,(WPARAM)hF,TRUE); return h; };

        g_hStaticLog = mkStatic(L"Event Log", (HMENU)IDC_STATIC_LOG);
        g_hLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"LISTBOX", NULL,
                                 WS_CHILD | WS_VISIBLE | WS_VSCROLL | LBS_NOSEL | LBS_NOINTEGRALHEIGHT,
                                 0, 0, 0, 0, hw, (HMENU)IDC_LOG, GetModuleHandleW(NULL), NULL);
        SendMessageW(g_hLog, WM_SETFONT, (WPARAM)hF, TRUE);

        g_hStaticSettings = mkStatic(L"Settings", (HMENU)IDC_STATIC_SETTINGS);
        g_hChkAllowList = mkChk(L"Allow-list trusted devices (skip CAPTCHA)", (HMENU)IDC_CHK_ALLOWLIST);
        g_hChkRemBlocked = mkChk(L"Remember blocked devices", (HMENU)IDC_CHK_REMBLOCKED);
        SendMessageW(g_hChkAllowList, BM_SETCHECK, g_allowListingEnabled ? BST_CHECKED : BST_UNCHECKED, 0);
        SendMessageW(g_hChkRemBlocked, BM_SETCHECK, g_rememberBlockedEnabled ? BST_CHECKED : BST_UNCHECKED, 0);

        g_hStaticDev = mkStatic(
            L"Known Devices  (Connected / Status / Manufacturer / Product / USB Serial / VID / PID / Instance)",
            (HMENU)IDC_STATIC_DEV);
        g_hDevList = CreateWindowExW(WS_EX_CLIENTEDGE, WC_LISTVIEWW, NULL,
                                     WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                                     0, 0, 0, 0, hw, (HMENU)IDC_DEVLIST, GetModuleHandleW(NULL), NULL);
        SendMessageW(g_hDevList, LVM_SETEXTENDEDLISTVIEWSTYLE, 0, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES);
        SendMessageW(g_hDevList, WM_SETFONT, (WPARAM)hF, TRUE);
        struct
        {
            const wchar_t *name;
            int cx;
        } cols[] = {
            {L"Connected", 80}, {L"Status", 80}, {L"Manufacturer", 130}, {L"Product", 160}, {L"USB Serial", 110}, {L"VID", 60}, {L"PID", 60}, {L"Instance", 140}};
        for (int i = 0; i < 8; i++)
        {
            LVCOLUMNW col = {};
            col.mask = LVCF_TEXT | LVCF_WIDTH;
            col.cx = cols[i].cx;
            col.pszText = (LPWSTR)cols[i].name;
            SendMessageW(g_hDevList, LVM_INSERTCOLUMNW, i, (LPARAM)&col);
        }
        g_hBtnAllow = mkBtn(L"Allow Selected", (HMENU)IDC_BTN_ALLOW);
        g_hBtnBlock = mkBtn(L"Block Selected", (HMENU)IDC_BTN_BLOCK);
        g_hBtnClear = mkBtn(L"Clear Log", (HMENU)IDC_BTN_CLEAR);
        g_hBtnForget = mkBtn(L"Forget Device", (HMENU)IDC_BTN_FORGET);
        g_hBtnRefresh = mkBtn(L"Refresh Devices", (HMENU)IDC_BTN_REFRESH);
        RECT rc;
        GetClientRect(hw, &rc);
        LayoutMainWindow(rc.right, rc.bottom);
        return 0;
    }
    case WM_SIZE:
        LayoutMainWindow(LOWORD(lp), HIWORD(lp));
        InvalidateRect(hw, NULL, FALSE);
        return 0;
    case WM_PAINT:
    {
        PAINTSTRUCT ps;
        BeginPaint(hw, &ps);
        RECT sr = {0, g_splitterTopY, ps.rcPaint.right, g_splitterTopY + SPLITTER_H};
        FillRect(ps.hdc, &sr, (HBRUSH)(COLOR_BTNFACE + 1));
        HPEN hpD = CreatePen(PS_SOLID, 1, GetSysColor(COLOR_BTNSHADOW));
        HPEN hpL = CreatePen(PS_SOLID, 1, GetSysColor(COLOR_BTNHIGHLIGHT));
        HPEN old = (HPEN)SelectObject(ps.hdc, hpD);
        MoveToEx(ps.hdc, 0, g_splitterTopY + 1, NULL);
        LineTo(ps.hdc, ps.rcPaint.right, g_splitterTopY + 1);
        SelectObject(ps.hdc, hpL);
        MoveToEx(ps.hdc, 0, g_splitterTopY + 3, NULL);
        LineTo(ps.hdc, ps.rcPaint.right, g_splitterTopY + 3);
        SelectObject(ps.hdc, old);
        DeleteObject(hpD);
        DeleteObject(hpL);
        EndPaint(hw, &ps);
        return 0;
    }
    case WM_SETCURSOR:
    {
        POINT pt;
        GetCursorPos(&pt);
        ScreenToClient(hw, &pt);
        if (pt.y >= g_splitterTopY && pt.y < g_splitterTopY + SPLITTER_H)
        {
            SetCursor(LoadCursorW(NULL, IDC_SIZENS));
            return TRUE;
        }
        return DefWindowProcW(hw, msg, wp, lp);
    }
    case WM_LBUTTONDOWN:
    {
        int y = (short)HIWORD(lp);
        if (y >= g_splitterTopY && y < g_splitterTopY + SPLITTER_H)
        {
            g_splitterDrag = true;
            g_dragBaseY = y;
            g_dragBaseLogH = g_logHeight;
            SetCapture(hw);
        }
        return 0;
    }
    case WM_MOUSEMOVE:
        if (g_splitterDrag)
        {
            int y = (short)HIWORD(lp);
            int nh = g_dragBaseLogH + (y - g_dragBaseY);
            if (nh < 40)
                nh = 40;
            if (nh > 600)
                nh = 600;
            g_logHeight = nh;
            RECT rc;
            GetClientRect(hw, &rc);
            LayoutMainWindow(rc.right, rc.bottom);
            InvalidateRect(hw, NULL, FALSE);
        }
        return 0;
    case WM_LBUTTONUP:
        if (g_splitterDrag)
        {
            g_splitterDrag = false;
            ReleaseCapture();
        }
        return 0;
    case WM_GETMINMAXINFO:
    {
        auto *mmi = reinterpret_cast<MINMAXINFO *>(lp);
        mmi->ptMinTrackSize.x = 740;
        mmi->ptMinTrackSize.y = 500;
        return 0;
    }
    case WM_COMMAND:
    {
        int id = LOWORD(wp);
        if (id == IDC_CHK_ALLOWLIST)
        {
            g_allowListingEnabled = (SendMessageW(g_hChkAllowList, BM_GETCHECK, 0, 0) == BST_CHECKED);
            AppLog(g_allowListingEnabled ? L"[SETTING] Allow-Listing ENABLED" : L"[SETTING] Allow-Listing DISABLED");
            return 0;
        }
        if (id == IDC_CHK_REMBLOCKED)
        {
            g_rememberBlockedEnabled = (SendMessageW(g_hChkRemBlocked, BM_GETCHECK, 0, 0) == BST_CHECKED);
            AppLog(g_rememberBlockedEnabled ? L"[SETTING] Remember-Blocked ENABLED" : L"[SETTING] Remember-Blocked DISABLED");
            return 0;
        }
        if (id == IDC_BTN_ALLOW || id == IDC_BTN_BLOCK)
        {
            int sel = (int)SendMessageW(g_hDevList, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
            if (sel < 0)
            {
                MessageBoxW(hw, L"Select a device first.", L"No Selection", MB_OK | MB_ICONINFORMATION);
                return 0;
            }
            std::wstring key;
            {
                std::lock_guard<std::mutex> lk(g_devMutex);
                int row = 0;
                for (auto &kv : g_db)
                {
                    if (row == sel)
                    {
                        key = kv.first;
                        break;
                    }
                    row++;
                }
            }
            if (key.empty())
                return 0;
            (id == IDC_BTN_ALLOW) ? ManualAllow(key) : ManualBlock(key);
            return 0;
        }
        if (id == IDC_BTN_CLEAR)
        {
            SendMessageW(g_hLog, LB_RESETCONTENT, 0, 0);
            return 0;
        }
        if (id == IDC_BTN_FORGET)
        {
            int sel = (int)SendMessageW(g_hDevList, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
            if (sel < 0)
            {
                MessageBoxW(hw, L"Select a device first.", L"No Selection", MB_OK | MB_ICONINFORMATION);
                return 0;
            }
            std::wstring key;
            {
                std::lock_guard<std::mutex> lk(g_devMutex);
                int row = 0;
                for (auto &kv : g_db)
                {
                    if (row == sel)
                    {
                        key = kv.first;
                        break;
                    }
                    row++;
                }
            }
            if (key.empty())
                return 0;
            if (MessageBoxW(hw, L"Forget this device? A fresh CAPTCHA will be required on next plug-in.",
                            L"Confirm Forget", MB_YESNO | MB_ICONQUESTION) != IDYES)
                return 0;
            ManualForget(key);
            return 0;
        }
        if (id == IDC_BTN_REFRESH)
        {
            {
                std::lock_guard<std::mutex> lk(g_devMutex);
                auto rescan = [&](HANDLE h)
                {
                    DevRecord fresh = BuildRecord(h);
                    auto it = g_db.find(MakeDBKey(fresh.fullName));
                    if (it != g_db.end())
                    {
                        it->second.manufacturer = fresh.manufacturer;
                        it->second.product = fresh.product;
                        it->second.usbSerial = fresh.usbSerial;
                        it->second.version = fresh.version;
                        it->second.friendly = fresh.friendly;
                    }
                };
                for (HANDLE h : EnumByType(RIM_TYPEKEYBOARD))
                    rescan(h);
                for (HANDLE h : EnumByType(RIM_TYPEMOUSE))
                    rescan(h);
            }
            SaveDB();
            RefreshDevList();
            AppLog(L"[INFO] Device list refreshed");
            return 0;
        }
        return 0;
    }
    case WM_DEVICECHANGE:
    {
        if (wp == DBT_DEVICEARRIVAL)
        {
            auto *hdr = reinterpret_cast<DEV_BROADCAST_HDR *>(lp);
            if (!hdr || hdr->dbch_devicetype != DBT_DEVTYP_DEVICEINTERFACE)
                break;

            // [FIX 1] Extract the identity of the device that just arrived.
            auto *devIface = reinterpret_cast<DEV_BROADCAST_DEVICEINTERFACE *>(lp);
            DevKey arrivedKey = ExtractDevKey(devIface->dbcc_name);

            Sleep(400); // let Windows finish registering the device

            HANDLE newDev = NULL;
            DevClass dc = DevClass::Unknown;

            // tryDevice: match by DevKey first (FIX 1), then apply flowchart logic
            auto tryDevice = [&](HANDLE h, DevClass devCls) -> bool
            {
                // [FIX 1] Only consider handles that match the arrived device.
                // Falls back to VID+PID if instance extraction failed.
                std::wstring hn = GetDevName(h);
                if (!DevKeyMatch(arrivedKey, ExtractDevKey(hn)))
                    return false;

                std::lock_guard<std::mutex> lk(g_devMutex);
                if (IsTrusted(h) || g_blocked.count(h) || g_pending.count(h))
                    return false;

                DevRecord r = BuildRecord(h);
                std::wstring dbk = MakeDBKey(r.fullName);
                auto dbSt = DBStatus(h);

                // Step 1 — Allow-Listing
                if (g_allowListingEnabled && dbSt == DevRecord::Status::Allowed)
                {
                    TrustDev(h);
                    r.status = DevRecord::Status::Allowed;
                    g_db[dbk] = r;
                    AppLog(L"[ALLOW-LIST] Auto-trusted: " + r.friendly +
                           L"  (use 'Forget' to require CAPTCHA on replug)");
                    return false;
                }
                // Step 2 — Remember-Blocked
                if (g_rememberBlockedEnabled && dbSt == DevRecord::Status::Blocked)
                {
                    g_blocked.insert(h);
                    AppLog(L"[SILENTLY BLOCKED] Previously blocked: " + r.friendly);
                    return false;
                }
                // Step 3 — CAPTCHA required
                g_blocked.insert(h);
                if (!g_db.count(dbk))
                    g_db[dbk] = r;
                newDev = h;
                dc = devCls;
                AppLog(L"[ALERT] New " + std::wstring(devCls == DevClass::Keyboard ? L"keyboard" : L"mouse") +
                       L" — CAPTCHA required: " + r.friendly);
                return true;
            };

            bool needCaptcha = false;
            for (HANDLE h : EnumByType(RIM_TYPEKEYBOARD))
                if (tryDevice(h, DevClass::Keyboard))
                {
                    needCaptcha = true;
                    break;
                }
            if (!needCaptcha)
                for (HANDLE h : EnumByType(RIM_TYPEMOUSE))
                    if (tryDevice(h, DevClass::Mouse))
                    {
                        needCaptcha = true;
                        break;
                    }

            SaveDB();
            RefreshDevList();
            if (needCaptcha)
                ShowCaptcha(newDev, dc);
        }
        else if (wp == DBT_DEVICEREMOVECOMPLETE)
        {
            auto kbs = EnumByType(RIM_TYPEKEYBOARD);
            auto mice = EnumByType(RIM_TYPEMOUSE);
            std::set<HANDLE> all;
            all.insert(kbs.begin(), kbs.end());
            all.insert(mice.begin(), mice.end());
            {
                std::lock_guard<std::mutex> lk(g_devMutex);
                for (auto it = g_blocked.begin(); it != g_blocked.end();)
                    it = all.count(*it) ? ++it : g_blocked.erase(it);
                for (auto it = g_pending.begin(); it != g_pending.end();)
                    it = all.count(*it) ? ++it : g_pending.erase(it);

                // [FIX 2] If the device being challenged was removed, dismiss cleanly.
                // WM_DISMISS_CAPTCHA → captcha thread exits → sets g_captchaActive=false
                // → posts WM_NEXT_CAPTCHA → queue advances normally.
                if (g_chalDev && !all.count(g_chalDev))
                {
                    g_chalDev = NULL; // NULL before posting so DenyDevice sees NULL → no-op
                    if (g_hCaptcha)
                    {
                        PostMessageW(g_hCaptcha, WM_DISMISS_CAPTCHA, 0, 0);
                        g_hCaptcha = NULL;
                    }
                }
            }

            // Also remove any queued items for disconnected devices
            {
                std::lock_guard<std::mutex> lk(g_captchaQueueMtx);
                g_captchaQueue.erase(
                    std::remove_if(g_captchaQueue.begin(), g_captchaQueue.end(),
                                   [&](const CaptchaQueueItem &item)
                                   { return !all.count(item.dev); }),
                    g_captchaQueue.end());
            }

            RefreshDevList(); // Update device list to show disconnected status
        }
        return TRUE;
    }
    case WM_CLOSE:
        ShowWindow(hw, SW_HIDE);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hw, msg, wp, lp);
}

// ─────────────────────────────────────────────────────────────────────────────
// Background message window — WM_INPUT + WM_DEVICECHANGE
// ─────────────────────────────────────────────────────────────────────────────
LRESULT CALLBACK MsgWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
    // [FIX 2] Drive the CAPTCHA queue after each captcha thread exits.
    case WM_NEXT_CAPTCHA:
        ProcessCaptchaQueue();
        return 0;

    case WM_INPUT:
    {
        UINT sz = 0;
        GetRawInputData((HRAWINPUT)lParam, RID_INPUT, NULL, &sz, sizeof(RAWINPUTHEADER));
        std::vector<BYTE> buf(sz);
        if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT, buf.data(), &sz, sizeof(RAWINPUTHEADER)) == sz)
        {
            auto *raw = reinterpret_cast<RAWINPUT *>(buf.data());
            if (raw->header.dwType == RIM_TYPEKEYBOARD)
            {
                g_rawRing[g_rawRingIdx & 3] = raw->header.hDevice;
                g_rawRingIdx++;
            }
        }
        return DefWindowProcW(hWnd, uMsg, wParam, lParam);
    }

    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hWnd, uMsg, wParam, lParam);
}

// ─────────────────────────────────────────────────────────────────────────────
// System tray
// ─────────────────────────────────────────────────────────────────────────────
void AddTrayIcon(HWND hw)
{
    g_nid.cbSize = sizeof(g_nid);
    g_nid.hWnd = hw;
    g_nid.uID = IDI_TRAY;
    g_nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g_nid.uCallbackMessage = WM_TRAYICON;
    g_nid.hIcon = LoadIconW(NULL, IDI_SHIELD);
    wcscpy_s(g_nid.szTip, L"USB Gatekeeper — Active");
    Shell_NotifyIconW(NIM_ADD, &g_nid);
}
void RemoveTrayIcon() { Shell_NotifyIconW(NIM_DELETE, &g_nid); }

LRESULT CALLBACK TrayWndProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp)
{
    if (msg == WM_TRAYICON && (lp == WM_LBUTTONDBLCLK || lp == WM_RBUTTONUP))
    {
        ShowWindow(g_hWnd, IsWindowVisible(g_hWnd) ? SW_HIDE : SW_SHOW);
        if (IsWindowVisible(g_hWnd))
            SetForegroundWindow(g_hWnd);
        return 0;
    }
    return DefWindowProcW(hw, msg, wp, lp);
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int)
{
    INITCOMMONCONTROLSEX icc = {sizeof(icc), ICC_LISTVIEW_CLASSES};
    InitCommonControlsEx(&icc);

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    wchar_t *sl = wcsrchr(exePath, L'\\');
    if (sl)
    {
        wcscpy_s(sl + 1, MAX_PATH - (sl - exePath) - 1, L"usb_gatekeeper_db.txt");
        g_dbPath = exePath;
    }

    LoadDB();
    BYTE test[4] = {};
    if (!CryptoRandomBytes(test, 4))
    {
        MessageBoxW(NULL, L"BCrypt failed.", L"Fatal", MB_OK | MB_ICONERROR);
        return 1;
    }

    {
        std::lock_guard<std::mutex> lk(g_devMutex);
        RebuildTrustFromDB();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // [SECURITY FIX 1] Startup: classify all currently connected HID devices
    // Unknown devices are now BLOCKED and require CAPTCHA, not auto-trusted
    // ─────────────────────────────────────────────────────────────────────────
    {
        std::lock_guard<std::mutex> lk(g_devMutex);
        auto processStartup = [&](HANDLE h)
        {
            DevRecord r = BuildRecord(h);
            std::wstring dbk = MakeDBKey(r.fullName);
            auto it = g_db.find(dbk);
            if (it != g_db.end())
            {
                if (it->second.status == DevRecord::Status::Blocked)
                {
                    if (g_rememberBlockedEnabled)
                    {
                        g_blocked.insert(h);
                        AppLog(L"[STARTUP] Blocked (DB): " + r.friendly);
                    }
                    else
                    {
                        TrustDev(h);
                        AppLog(L"[STARTUP] Remember-Blocked OFF — trusted: " + r.friendly);
                    }
                }
                else if (it->second.status == DevRecord::Status::Allowed)
                {
                    if (g_allowListingEnabled)
                    {
                        TrustDev(h);
                        it->second.fullName = r.fullName;
                        AppLog(L"[STARTUP] Trusted (DB): " + r.friendly);
                    }
                    else
                    {
                        g_blocked.insert(h);
                        AppLog(L"[STARTUP] Allow-Listing OFF — pending CAPTCHA: " + r.friendly);
                    }
                }
                else
                {
                    // Status::Unknown — block it
                    g_blocked.insert(h);
                    AppLog(L"[STARTUP] Unknown — pending CAPTCHA: " + r.friendly);
                }
            }
            else
            {
                // [SECURITY FIX 1] NEW DEVICE NOT IN DB — require CAPTCHA
                g_blocked.insert(h);
                r.status = DevRecord::Status::Unknown;
                g_db[dbk] = r;
                AppLog(L"[STARTUP] Unknown device — pending CAPTCHA: " + r.friendly);
            }
        };
        for (HANDLE h : EnumByType(RIM_TYPEKEYBOARD))
            processStartup(h);
        for (HANDLE h : EnumByType(RIM_TYPEMOUSE))
            processStartup(h);
        AppLog(L"[INFO] " + std::to_wstring(g_trusted.size()) + L" trusted, " +
               std::to_wstring(g_blocked.size()) + L" blocked at startup");
    }
    SaveDB();

    // Main window
    WNDCLASSW wcMain = {};
    wcMain.lpfnWndProc = MainWndProc;
    wcMain.hInstance = hInst;
    wcMain.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wcMain.lpszClassName = L"USBGatekeeperMain";
    wcMain.hCursor = LoadCursorW(NULL, IDC_ARROW);
    wcMain.hIcon = LoadIconW(NULL, IDI_SHIELD);
    RegisterClassW(&wcMain);
    g_hWnd = CreateWindowExW(0, L"USBGatekeeperMain", L"USB Gatekeeper v4.3",
                             WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 960, 680,
                             NULL, NULL, hInst, NULL);
    ShowWindow(g_hWnd, SW_SHOW);
    UpdateWindow(g_hWnd);
    RefreshDevList();

    // Tray icon window
    WNDCLASSW wcTray = {};
    wcTray.lpfnWndProc = TrayWndProc;
    wcTray.hInstance = hInst;
    wcTray.lpszClassName = L"USBTray";
    RegisterClassW(&wcTray);
    g_hTrayWnd = CreateWindowExW(0, L"USBTray", L"", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, hInst, NULL);
    AddTrayIcon(g_hTrayWnd);

    // Background message window (raw input + device change)
    WNDCLASSW wcMsg = {};
    wcMsg.lpfnWndProc = MsgWndProc;
    wcMsg.hInstance = hInst;
    wcMsg.lpszClassName = L"USBGatekeeperMsg";
    RegisterClassW(&wcMsg);
    g_hMsgWnd = CreateWindowExW(0, L"USBGatekeeperMsg", L"", 0, 0, 0, 0, 0, HWND_MESSAGE, NULL, hInst, NULL);

    // Register for raw input (keyboard + mouse, background)
    RAWINPUTDEVICE rids[2] = {};
    rids[0].usUsagePage = HID_USAGE_PAGE_GENERIC;
    rids[0].usUsage = HID_USAGE_GENERIC_KEYBOARD;
    rids[0].dwFlags = RIDEV_INPUTSINK;
    rids[0].hwndTarget = g_hMsgWnd;
    rids[1].usUsagePage = HID_USAGE_PAGE_GENERIC;
    rids[1].usUsage = HID_USAGE_GENERIC_MOUSE;
    rids[1].dwFlags = RIDEV_INPUTSINK;
    rids[1].hwndTarget = g_hMsgWnd;
    RegisterRawInputDevices(rids, 2, sizeof(RAWINPUTDEVICE));

    // Device arrival/removal notifications - register on MAIN WINDOW for reliable detection
    // (message-only windows don't always receive device notifications reliably)
    DEV_BROADCAST_DEVICEINTERFACE nf = {};
    nf.dbcc_size = sizeof(nf);
    nf.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    nf.dbcc_classguid = {0x4D1E55B2, 0xF16F, 0x11CF, {0x88, 0xCB, 0x00, 0x11, 0x11, 0x00, 0x00, 0x30}};
    g_hDevNotify = RegisterDeviceNotificationW(g_hWnd, &nf, DEVICE_NOTIFY_WINDOW_HANDLE);

    g_kbHook = SetWindowsHookExW(WH_KEYBOARD_LL, LowLevelKBProc, hInst, 0);

    AppLog(L"[INFO] USB Gatekeeper v4.3 active");
    AppLog(L"[INFO] Allow-Listing: " + std::wstring(g_allowListingEnabled ? L"ON" : L"OFF"));
    AppLog(L"[INFO] Remember-Blocked: " + std::wstring(g_rememberBlockedEnabled ? L"ON" : L"OFF"));
    if (CAPTCHA_TIMEOUT_MS > 0)
        AppLog(L"[INFO] CAPTCHA auto-deny timeout: " + std::to_wstring(CAPTCHA_TIMEOUT_MS / 1000) + L"s");
    AppLog(L"[INFO] TIP: 'Forget Device' before replug to trigger a fresh CAPTCHA");
    AppLog(L"[SECURITY] Unknown devices at startup require CAPTCHA");
    AppLog(L"[SECURITY] Denied CAPTCHAs require CAPTCHA on replug (not saved as blocked)");
    AppLog(L"[TWO-TIER TRUST] Pass CAPTCHA = session-only | 'Allow Selected' = permanent");
    AppLog(L"[INSTANCE-SPECIFIC] Each USB port tracked separately - one allow ≠ all ports");

    // Show CAPTCHA for any devices that were unknown at startup
    {
        std::vector<std::pair<HANDLE, DevClass>> toChallenge;
        {
            std::lock_guard<std::mutex> lk(g_devMutex);
            for (HANDLE h : EnumByType(RIM_TYPEKEYBOARD))
                if (g_blocked.count(h) && !g_pending.count(h) && DBStatus(h) == DevRecord::Status::Unknown)
                    toChallenge.push_back({h, DevClass::Keyboard});
            for (HANDLE h : EnumByType(RIM_TYPEMOUSE))
                if (g_blocked.count(h) && !g_pending.count(h) && DBStatus(h) == DevRecord::Status::Unknown)
                    toChallenge.push_back({h, DevClass::Mouse});
        }
        for (auto &p : toChallenge)
            ShowCaptcha(p.first, p.second);
    }

    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0)
    {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    UnhookWindowsHookEx(g_kbHook);
    UnregisterDeviceNotification(g_hDevNotify);
    RemoveTrayIcon();
    SaveDB();
    return 0;
}