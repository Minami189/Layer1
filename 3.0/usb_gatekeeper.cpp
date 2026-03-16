/*
 * USB Gatekeeper v4.0 — BadUSB Interceptor with Persistent Storage + Management GUI
 *
 * BUILD (MSYS2 UCRT64, run as Admin):
 *   g++ -std=c++17 -o usb_gatekeeper.exe usb_gatekeeper.cpp \
 *       -luser32 -lgdi32 -lhid -lsetupapi -lbcrypt -lcomctl32 -mwindows
 *
 * FEATURES:
 *   - Blocks new USB keyboards/mice until CAPTCHA solved
 *   - Persistent allow/block list saved to usb_gatekeeper_db.txt (same folder as exe)
 *   - Main GUI window: live log, connected devices list, allow/block buttons
 *   - Stores VID, PID, serial, full device name per entry
 *   - CAPTCHA: scramble/hex/token for keyboards, color-click for mice
 *   - Timing analysis detects robotic input
 *   - LLKHF_INJECTED blocks AutoHotkey/SendInput
 */

#define WIN32_LEAN_AND_MEAN
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
#include <hidsdi.h>
#include <shellapi.h>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <set>
#include <map>
#include <string>
#include <mutex>
#include <atomic>
#include <cmath>
#include <algorithm>

#pragma comment(lib,"comctl32.lib")

// ─────────────────────────────────────────────────────────────────────────────
// IDs
// ─────────────────────────────────────────────────────────────────────────────
#define IDC_LABEL       101
#define IDC_SUBLABEL    102
#define IDC_INPUT       103
#define IDC_SUBMIT      104
#define IDC_DENY        105
#define IDC_T1 201
#define IDC_T2 202
#define IDC_T3 203
#define IDC_T4 204
#define IDC_T5 205

// Main window controls
#define IDC_LOG         1001
#define IDC_DEVLIST     1002
#define IDC_BTN_ALLOW   1003
#define IDC_BTN_BLOCK   1004
#define IDC_BTN_CLEAR   1005
#define IDC_BTN_FORGET  1006
#define IDC_STATIC_LOG  1006
#define IDC_STATIC_DEV  1007

// ─────────────────────────────────────────────────────────────────────────────
// Device record — stored in DB file and memory
// ─────────────────────────────────────────────────────────────────────────────
struct DevRecord {
    std::wstring vid;       // VID_XXXX
    std::wstring pid;       // PID_XXXX
    std::wstring serial;    // serial number or "<none>"
    std::wstring fullName;  // full raw input device name string
    std::wstring friendly;  // VID_XXXX&PID_XXXX display
    enum class Status { Unknown, Allowed, Blocked } status = Status::Unknown;
};

// ─────────────────────────────────────────────────────────────────────────────
// BCrypt
// ─────────────────────────────────────────────────────────────────────────────
bool CryptoRandomBytes(void* buf, size_t len)
{
    return BCRYPT_SUCCESS(BCryptGenRandom(NULL,(PUCHAR)buf,(ULONG)len,
                          BCRYPT_USE_SYSTEM_PREFERRED_RNG));
}
DWORD CryptoRandRange(DWORD upper)
{
    if(upper<=1) return 0;
    DWORD r=0, t=0xFFFFFFFFu%upper;
    do{ CryptoRandomBytes(&r,sizeof(r)); } while(r<t);
    return r%upper;
}

// ─────────────────────────────────────────────────────────────────────────────
// Challenge
// ─────────────────────────────────────────────────────────────────────────────
enum class ChalType { Scramble, Hex, Token, MouseColor };
enum class DevClass  { Keyboard, Mouse, Unknown };

struct Challenge {
    ChalType     type;
    std::wstring display, hint, answer;
    int          colorIdx=0, targetBox=0, boxColors[5]={};
};

static const wchar_t* WORDS[]=
{L"PLANET",L"BRIDGE",L"FALCON",L"SPIDER",L"WINTER",L"GARDEN",L"MIRROR",
 L"CASTLE",L"DRAGON",L"SILVER",L"FOREST",L"ROCKET",L"MARBLE",L"HUNTER",
 L"COBALT",L"STRIKE",L"VECTOR",L"TURRET",L"CANYON",L"PRISM"};
static const wchar_t* CNAMES[]={L"RED",L"GREEN",L"BLUE",L"YELLOW",L"ORANGE"};
static const COLORREF CVALS[]={RGB(210,45,45),RGB(45,170,45),RGB(45,90,210),RGB(210,190,0),RGB(210,110,0)};

std::wstring ScrambleWord(const std::wstring& w)
{
    std::wstring s=w; int t=0;
    do{ for(int i=(int)s.size()-1;i>0;--i) std::swap(s[i],s[CryptoRandRange(i+1)]); }
    while(s==w && ++t<20); return s;
}
std::wstring SpaceLetters(const std::wstring& w)
{ std::wstring o; for(size_t i=0;i<w.size();++i){if(i)o+=L' ';o+=w[i];} return o; }
std::wstring MakeToken()
{
    const wchar_t L2[]=L"ABCDEFGHJKLMNPQRSTUVWXYZ", D2[]=L"23456789";
    std::wstring t;
    for(int g=0;g<3;++g){ if(g)t+=L'-'; t+=L2[CryptoRandRange((DWORD)wcslen(L2))]; t+=D2[CryptoRandRange((DWORD)wcslen(D2))]; }
    return t;
}
Challenge GenKBChallenge()
{
    Challenge c; c.type=(ChalType)CryptoRandRange(3);
    switch(c.type){
    case ChalType::Scramble:{ std::wstring w=WORDS[CryptoRandRange(20)]; c.display=SpaceLetters(ScrambleWord(w)); c.hint=L"Unscramble into a word"; c.answer=w; break; }
    case ChalType::Hex:{ BYTE code=(BYTE)(0x41+CryptoRandRange(26)); std::wostringstream ss; ss<<L"0x"<<std::uppercase<<std::hex<<std::setw(2)<<std::setfill(L'0')<<(int)code; c.display=ss.str(); c.hint=L"Type the letter this hex value represents"; c.answer=std::wstring(1,(wchar_t)code); break; }
    case ChalType::Token:{ std::wstring tok=MakeToken(); c.display=tok; c.hint=L"Type this code exactly"; c.answer=tok; break; }
    default: break;
    }
    return c;
}
Challenge GenMouseChallenge()
{
    Challenge c; c.type=ChalType::MouseColor; c.colorIdx=(int)CryptoRandRange(5);
    int perm[5]={0,1,2,3,4}; for(int i=4;i>0;--i) std::swap(perm[i],perm[CryptoRandRange(i+1)]);
    for(int i=0;i<5;i++) c.boxColors[i]=perm[i];
    for(int i=0;i<5;i++) if(c.boxColors[i]==c.colorIdx){c.targetBox=i;break;}
    c.display=std::wstring(L"Click the ")+CNAMES[c.colorIdx]+L" box"; return c;
}
bool WEqCI(const std::wstring& a, const std::wstring& b)
{ if(a.size()!=b.size()) return false; for(size_t i=0;i<a.size();++i) if(towupper(a[i])!=towupper(b[i])) return false; return true; }

// ─────────────────────────────────────────────────────────────────────────────
// Timing
// ─────────────────────────────────────────────────────────────────────────────
struct Timing {
    std::vector<double> ts;
    void Add(double t){ ts.push_back(t); }
    void Reset(){ ts.clear(); }
    bool IsHuman() const {
        if(ts.size()<4) return true;
        std::vector<double> gaps; for(size_t i=1;i<ts.size();++i) gaps.push_back(ts[i]-ts[i-1]);
        double mean=0; for(double g:gaps) mean+=g; mean/=gaps.size();
        double var=0; for(double g:gaps) var+=(g-mean)*(g-mean); var/=gaps.size();
        return !(mean<50.0 && std::sqrt(var)<20.0);
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Globals
// ─────────────────────────────────────────────────────────────────────────────
std::map<std::wstring,DevRecord> g_db;          // key = fullName, persistent
std::set<HANDLE>        g_trusted;
std::set<std::wstring>  g_trustedNames;
std::set<std::wstring>  g_trustedVIDs;
std::set<HANDLE>        g_blocked;
std::set<HANDLE>        g_pending;
std::mutex              g_devMutex;

static HANDLE            g_lastRawDevice = NULL;
static bool              g_rawReady      = false;
static std::atomic<bool> g_captchaActive{false};

HHOOK      g_kbHook     = NULL;
HWND       g_hWnd       = NULL;         // main GUI window
HWND       g_hMsgWnd    = NULL;         // invisible message-only window
HWND       g_hCaptcha   = NULL;
HWND       g_hLog       = NULL;         // log listbox
HWND       g_hDevList   = NULL;         // device listview
HDEVNOTIFY g_hDevNotify = NULL;

static Challenge  g_chal;
static HANDLE     g_chalDev = NULL;
static DevClass   g_chalDC  = DevClass::Unknown;
static int        g_wrong   = 0;
static const int  MAX_WRONG = 3;
static Timing     g_timing;
static HWND       g_mouseBoxHwnd[5]={};

static std::wstring g_dbPath; // path to persistent DB file

// ─────────────────────────────────────────────────────────────────────────────
// Device identity helpers
// ─────────────────────────────────────────────────────────────────────────────
std::wstring GetDevName(HANDLE h)
{
    UINT sz=0; GetRawInputDeviceInfoW(h,RIDI_DEVICENAME,NULL,&sz);
    if(!sz) return L"<unknown>";
    std::wstring s(sz,L'\0'); GetRawInputDeviceInfoW(h,RIDI_DEVICENAME,s.data(),&sz);
    return s;
}
std::wstring ExtractToken(const std::wstring& name, const std::wstring& prefix)
{
    auto p=name.find(prefix); if(p==std::wstring::npos) return L"";
    p+=prefix.size(); auto e=name.find_first_of(L"&#\\/",p);
    return name.substr(p, e==std::wstring::npos?8:std::min((size_t)8,e-p));
}
std::wstring GetVID(const std::wstring& name){ return ExtractToken(name,L"VID_"); }
std::wstring GetPID(const std::wstring& name){ return ExtractToken(name,L"PID_"); }
std::wstring GetSerial(const std::wstring& name)
{
    // Serial is the segment after the PID in the device path
    // Format: ...VID_XXXX&PID_XXXX\SERIALNUMBER#...
    auto p=name.find(L"PID_"); if(p==std::wstring::npos) return L"<none>";
    p=name.find(L'\\',p); if(p==std::wstring::npos) return L"<none>";
    ++p; auto e=name.find(L'#',p);
    std::wstring s=name.substr(p, e==std::wstring::npos?std::wstring::npos:e-p);
    if(s.empty()||s==L"&") return L"<none>";
    return s;
}
std::wstring ShortName(HANDLE h)
{
    std::wstring f=GetDevName(h);
    std::wstring vid=GetVID(f), pid=GetPID(f);
    if(!vid.empty()&&!pid.empty()) return L"VID_"+vid+L"&PID_"+pid;
    auto p=f.find(L"VID_"); if(p!=std::wstring::npos&&f.size()>p+16) return f.substr(p,16);
    return f.size()>40?f.substr(0,40)+L"...":f;
}
std::set<HANDLE> EnumByType(DWORD type)
{
    std::set<HANDLE> out; UINT n=0;
    GetRawInputDeviceList(NULL,&n,sizeof(RAWINPUTDEVICELIST)); if(!n) return out;
    std::vector<RAWINPUTDEVICELIST> list(n);
    if(GetRawInputDeviceList(list.data(),&n,sizeof(RAWINPUTDEVICELIST))==(UINT)-1) return out;
    for(auto& d:list) if(d.dwType==type) out.insert(d.hDevice); return out;
}

// Canonical DB key: VID+PID+serial — deduplicates MI_00/MI_03 siblings
std::wstring MakeDBKey(const std::wstring& fullName)
{
    std::wstring vid=GetVID(fullName), pid=GetPID(fullName), ser=GetSerial(fullName);
    return L"VID_"+vid+L"&PID_"+pid+L"&SER_"+ser;
}

DevRecord BuildRecord(HANDLE h)
{
    DevRecord r;
    r.fullName = GetDevName(h);
    r.vid      = GetVID(r.fullName);
    r.pid      = GetPID(r.fullName);
    r.serial   = GetSerial(r.fullName);
    r.friendly = L"VID_"+r.vid+L"&PID_"+r.pid;
    return r;
}

// ─────────────────────────────────────────────────────────────────────────────
// Persistent DB  (simple text file: STATUS|VID|PID|SERIAL|FULLNAME)
// ─────────────────────────────────────────────────────────────────────────────
void SaveDB()
{
    if(g_dbPath.empty()) return;
    // Use narrow fstream - MinGW wofstream doesn't accept wstring path
    std::ofstream f(g_dbPath.c_str());
    if(!f) return;
    for(auto& kv:g_db){
        auto& r=kv.second;
        char st='U';
        if(r.status==DevRecord::Status::Allowed) st='A';
        if(r.status==DevRecord::Status::Blocked) st='B';
        // Convert wstring fields to narrow for storage
        auto W=[](const std::wstring& w){ std::string s; for(wchar_t c:w) s+=(c<128?(char)c:'?'); return s; };
        f<<st<<'|'<<W(r.vid)<<'|'<<W(r.pid)<<'|'<<W(r.serial)<<'|'<<W(r.fullName)<<'\n';
    }
}
void LoadDB()
{
    if(g_dbPath.empty()) return;
    std::ifstream f(g_dbPath.c_str());
    if(!f) return;
    std::string lineA;
    while(std::getline(f,lineA)){
        std::wstring line(lineA.begin(),lineA.end());
        if(line.size()<5) continue;
        wchar_t st=line[0];
        // parse |
        auto p1=line.find(L'|',1); if(p1==std::wstring::npos) continue;
        auto p2=line.find(L'|',p1+1); if(p2==std::wstring::npos) continue;
        auto p3=line.find(L'|',p2+1); if(p3==std::wstring::npos) continue;
        auto p4=line.find(L'|',p3+1); if(p4==std::wstring::npos) continue;
        DevRecord r;
        r.vid      = line.substr(p1+1,p2-p1-1);
        r.pid      = line.substr(p2+1,p3-p2-1);
        r.serial   = line.substr(p3+1,p4-p3-1);
        r.fullName = line.substr(p4+1);
        r.friendly = L"VID_"+r.vid+L"&PID_"+r.pid;
        if(st==L'A') r.status=DevRecord::Status::Allowed;
        else if(st==L'B') r.status=DevRecord::Status::Blocked;
        g_db[L"VID_"+r.vid+L"&PID_"+r.pid+L"&SER_"+r.serial]=r;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Log to GUI
// ─────────────────────────────────────────────────────────────────────────────
void AppLog(const std::wstring& msg)
{
    if(!g_hLog) return;
    // prepend timestamp
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t ts[32]; swprintf_s(ts,L"[%02d:%02d:%02d] ",st.wHour,st.wMinute,st.wSecond);
    std::wstring line=std::wstring(ts)+msg;
    // Add to top of listbox
    SendMessageW(g_hLog,LB_INSERTSTRING,0,(LPARAM)line.c_str());
    // Trim to 500 lines
    int cnt=(int)SendMessageW(g_hLog,LB_GETCOUNT,0,0);
    if(cnt>500) SendMessageW(g_hLog,LB_DELETESTRING,cnt-1,0);
}

// ─────────────────────────────────────────────────────────────────────────────
// Refresh device list in GUI
// ─────────────────────────────────────────────────────────────────────────────
void RefreshDevList()
{
    if(!g_hDevList) return;
    SendMessageW(g_hDevList,LVM_DELETEALLITEMS,0,0);
    int row=0;
    std::lock_guard<std::mutex> lk(g_devMutex);
    for(auto& kv:g_db){
        auto& r=kv.second;
        LVITEMW lvi={};
        lvi.mask=LVIF_TEXT; lvi.iItem=row;

        // Col 0: Status
        const wchar_t* stStr=L"Unknown";
        if(r.status==DevRecord::Status::Allowed) stStr=L"ALLOWED";
        if(r.status==DevRecord::Status::Blocked) stStr=L"BLOCKED";
        lvi.iSubItem=0; lvi.pszText=(LPWSTR)stStr;
        SendMessageW(g_hDevList,LVM_INSERTITEMW,0,(LPARAM)&lvi);

        // Col 1: VID
        lvi.mask=LVIF_TEXT; lvi.iSubItem=1; lvi.pszText=(LPWSTR)r.vid.c_str();
        SendMessageW(g_hDevList,LVM_SETITEMW,0,(LPARAM)&lvi);
        // Col 2: PID
        lvi.iSubItem=2; lvi.pszText=(LPWSTR)r.pid.c_str();
        SendMessageW(g_hDevList,LVM_SETITEMW,0,(LPARAM)&lvi);
        // Col 3: Serial
        lvi.iSubItem=3; lvi.pszText=(LPWSTR)r.serial.c_str();
        SendMessageW(g_hDevList,LVM_SETITEMW,0,(LPARAM)&lvi);
        // Col 4: Friendly
        lvi.iSubItem=4; lvi.pszText=(LPWSTR)r.friendly.c_str();
        SendMessageW(g_hDevList,LVM_SETITEMW,0,(LPARAM)&lvi);

        row++;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Trust helpers
// ─────────────────────────────────────────────────────────────────────────────

// Rebuild runtime trust sets from DB — called after LoadDB and after any status change.
// Allowed entries populate g_trustedNames/VIDs so IsTrusted works across restarts.
// Blocked entries are explicitly removed from trust sets.
// Must be called with g_devMutex held.
void RebuildTrustFromDB()
{
    g_trustedNames.clear();
    g_trustedVIDs.clear();
    // Note: g_trusted (handles) is NOT cleared here — handles are session-specific.
    // Name and VID sets are what survive restarts.
    for(auto& kv:g_db){
        auto& r=kv.second;
        if(r.status==DevRecord::Status::Allowed){
            g_trustedNames.insert(r.fullName);
            if(!r.vid.empty()) g_trustedVIDs.insert(r.vid);
        }
    }
}

// Check DB by canonical key first, then VID+PID fallback
DevRecord::Status DBStatus(HANDLE h)
{
    std::wstring n=GetDevName(h);
    auto it=g_db.find(MakeDBKey(n));
    if(it!=g_db.end()) return it->second.status;
    // Fallback: match by VID+PID (handles devices with no/changing serial)
    std::wstring vid=GetVID(n), pid=GetPID(n);
    for(auto& kv:g_db)
        if(kv.second.vid==vid && kv.second.pid==pid)
            return kv.second.status;
    return DevRecord::Status::Unknown;
}

bool IsTrusted(HANDLE h)
{
    // 1. Session handle (fastest)
    if(g_trusted.count(h)) return true;
    // 2. Persistent name match
    std::wstring n=GetDevName(h);
    if(g_trustedNames.count(n)) return true;
    // 3. Persistent VID match
    std::wstring vid=GetVID(n);
    return !vid.empty() && g_trustedVIDs.count(vid);
}

bool IsDBBlocked(HANDLE h)
{
    return DBStatus(h)==DevRecord::Status::Blocked;
}

void TrustDev(HANDLE h)
{
    std::wstring n=GetDevName(h), vid=GetVID(n);
    g_trusted.insert(h);
    g_trustedNames.insert(n);
    if(!vid.empty()) g_trustedVIDs.insert(vid);
}

// ─────────────────────────────────────────────────────────────────────────────
// Approve / Deny
// ─────────────────────────────────────────────────────────────────────────────
void ApproveDevice(HANDLE dev)
{
    {
        std::lock_guard<std::mutex> lk(g_devMutex);
        TrustDev(dev);
        DevRecord r=BuildRecord(dev); r.status=DevRecord::Status::Allowed;
        g_db[MakeDBKey(r.fullName)]=r;
        RebuildTrustFromDB(); // sync name/VID sets with DB
        g_trusted.insert(dev); // re-add handle (RebuildTrustFromDB clears name/VID only)
        for(auto it=g_blocked.begin();it!=g_blocked.end();) it=IsTrusted(*it)?g_blocked.erase(it):++it;
        for(auto it=g_pending.begin();it!=g_pending.end();) it=IsTrusted(*it)?g_pending.erase(it):++it;
        g_lastRawDevice=NULL;
    }
    SaveDB();
    AppLog(L"[APPROVED] "+ShortName(dev));
    g_chalDev=NULL; g_hCaptcha=NULL; g_captchaActive=false;
    RefreshDevList();
}
void DenyDevice(HANDLE dev)
{
    {
        std::lock_guard<std::mutex> lk(g_devMutex);
        g_pending.erase(dev);
        DevRecord r=BuildRecord(dev); r.status=DevRecord::Status::Blocked;
        g_db[MakeDBKey(r.fullName)]=r;
    }
    SaveDB();
    AppLog(L"[BLOCKED] "+ShortName(dev));
    g_chalDev=NULL; g_hCaptcha=NULL; g_captchaActive=false;
    RefreshDevList();
}

// ─────────────────────────────────────────────────────────────────────────────
// Manual allow/block from GUI button
// ─────────────────────────────────────────────────────────────────────────────
void ManualAllow(const std::wstring& dbKey)
{
    std::wstring friendly, vid, pid;
    {
        std::lock_guard<std::mutex> lk(g_devMutex);
        auto it=g_db.find(dbKey);
        if(it==g_db.end()) return;
        it->second.status=DevRecord::Status::Allowed;
        friendly=it->second.friendly;
        vid=it->second.vid;   // from the DB record — reliable
        pid=it->second.pid;

        // Rebuild trust sets so this device's VID is now in g_trustedVIDs
        RebuildTrustFromDB();

        // Clear ALL handles from g_blocked/g_pending whose VID+PID matches.
        // Match by VID+PID against the raw device path from GetDevName() —
        // NOT against the DB key string which has a different format.
        auto clearSets=[&](std::set<HANDLE>& s){
            for(auto it2=s.begin();it2!=s.end();){
                std::wstring dn=GetDevName(*it2);
                bool match=(!vid.empty()&&GetVID(dn)==vid&&GetPID(dn)==pid);
                it2=match?s.erase(it2):++it2;
            }
        };
        clearSets(g_blocked);
        clearSets(g_pending);
        g_lastRawDevice=NULL;

        // Close any open captcha for this device
        if(g_chalDev){
            std::wstring cn=GetDevName(g_chalDev);
            if(!vid.empty()&&GetVID(cn)==vid&&GetPID(cn)==pid){
                g_chalDev=NULL; g_captchaActive=false;
                if(g_hCaptcha){ DestroyWindow(g_hCaptcha); g_hCaptcha=NULL; }
            }
        }
    }
    SaveDB();
    AppLog(L"[MANUAL ALLOW] "+friendly+L" — device unblocked");
    RefreshDevList();
}
void ManualBlock(const std::wstring& dbKey)
{
    std::wstring friendly, vid, pid;
    {
        std::lock_guard<std::mutex> lk(g_devMutex);
        auto it=g_db.find(dbKey);
        if(it==g_db.end()) return;
        it->second.status=DevRecord::Status::Blocked;
        friendly=it->second.friendly;
        vid=it->second.vid;   // from DB record — reliable
        pid=it->second.pid;

        // Rebuild trust sets — this device's VID is removed from g_trustedVIDs
        RebuildTrustFromDB();

        // Find all currently connected handles matching VID+PID.
        // Remove from g_trusted/g_trustedNames and add to g_blocked.
        auto processHandles=[&](std::set<HANDLE>& handles){
            for(HANDLE h:handles){
                std::wstring dn=GetDevName(h);
                if(!vid.empty()&&GetVID(dn)==vid&&GetPID(dn)==pid){
                    g_trusted.erase(h);
                    g_trustedNames.erase(dn);
                    g_blocked.insert(h);
                }
            }
        };
        auto kbs=EnumByType(RIM_TYPEKEYBOARD);
        auto mice=EnumByType(RIM_TYPEMOUSE);
        processHandles(kbs);
        processHandles(mice);
    }
    SaveDB();
    AppLog(L"[MANUAL BLOCK] "+friendly+L" — device blocked");
    RefreshDevList();
}

// ─────────────────────────────────────────────────────────────────────────────
// Forget device — removes from DB and all runtime sets so next plug triggers
// a fresh CAPTCHA as if the device has never been seen before
// ─────────────────────────────────────────────────────────────────────────────
void ManualForget(const std::wstring& dbKey)
{
    std::wstring friendly, vid, pid;
    {
        std::lock_guard<std::mutex> lk(g_devMutex);
        auto it=g_db.find(dbKey);
        if(it==g_db.end()) return;
        friendly=it->second.friendly;
        vid=it->second.vid;
        pid=it->second.pid;

        // Mark as Unknown — NOT erased. On restart the startup code sees Unknown
        // and skips auto-trusting it. WM_DEVICECHANGE will treat it as a new
        // device and show the CAPTCHA. Blocked immediately in this session too.
        it->second.status=DevRecord::Status::Unknown;

        // Rebuild trust sets — Unknown entries are not added to trustedNames/VIDs
        RebuildTrustFromDB();

        // Remove matching handles from ALL runtime sets by VID+PID
        auto removeHandles=[&](std::set<HANDLE>& s){
            for(auto hit=s.begin();hit!=s.end();){
                std::wstring dn=GetDevName(*hit);
                bool match=(!vid.empty()&&GetVID(dn)==vid&&GetPID(dn)==pid);
                hit=match?s.erase(hit):++hit;
            }
        };
        removeHandles(g_trusted);
        removeHandles(g_pending);

        // Add to g_blocked so keystrokes are swallowed until CAPTCHA is solved
        auto kbs=EnumByType(RIM_TYPEKEYBOARD);
        auto mice=EnumByType(RIM_TYPEMOUSE);
        for(HANDLE h:kbs){
            std::wstring dn=GetDevName(h);
            if(!vid.empty()&&GetVID(dn)==vid&&GetPID(dn)==pid) g_blocked.insert(h);
        }
        for(HANDLE h:mice){
            std::wstring dn=GetDevName(h);
            if(!vid.empty()&&GetVID(dn)==vid&&GetPID(dn)==pid) g_blocked.insert(h);
        }
        g_lastRawDevice=NULL;
    }
    SaveDB();
    AppLog(L"[FORGOTTEN] "+friendly+L" — blocked now, CAPTCHA required on next plug-in");
    RefreshDevList();
}

// ─────────────────────────────────────────────────────────────────────────────
// CAPTCHA window proc
// ─────────────────────────────────────────────────────────────────────────────
LRESULT CALLBACK CaptchaProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp)
{
    static HBRUSH hBg=NULL,hEdit=NULL; static HFONT hFB=NULL,hFM=NULL; static HBRUSH hBox[5]={};
    auto Cleanup=[&](){ if(hBg){DeleteObject(hBg);hBg=NULL;} if(hEdit){DeleteObject(hEdit);hEdit=NULL;} if(hFB){DeleteObject(hFB);hFB=NULL;} if(hFM){DeleteObject(hFM);hFM=NULL;} for(auto& b:hBox)if(b){DeleteObject(b);b=NULL;} };
    switch(msg){
    case WM_CREATE:{
        hBg=CreateSolidBrush(RGB(18,22,40)); hEdit=CreateSolidBrush(RGB(30,35,60));
        hFB=CreateFontW(18,0,0,0,FW_SEMIBOLD,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        hFM=CreateFontW(17,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,FIXED_PITCH,L"Consolas");
        HWND hIcon=CreateWindowExW(0,L"STATIC",NULL,WS_CHILD|WS_VISIBLE|SS_ICON,16,14,32,32,hw,(HMENU)200,GetModuleHandleW(NULL),NULL);
        SendMessageW(hIcon,STM_SETICON,(WPARAM)LoadIconW(NULL,IDI_WARNING),0);
        std::wstring title=(g_chalDC==DevClass::Mouse)?L"New USB Mouse — Security Challenge":L"New USB Keyboard — Security Challenge";
        HWND hTitle=CreateWindowExW(0,L"STATIC",title.c_str(),WS_CHILD|WS_VISIBLE|SS_LEFT,56,16,440,22,hw,(HMENU)201,GetModuleHandleW(NULL),NULL);
        SendMessageW(hTitle,WM_SETFONT,(WPARAM)hFB,TRUE);
        CreateWindowExW(0,L"STATIC",NULL,WS_CHILD|WS_VISIBLE|SS_ETCHEDHORZ,12,50,480,2,hw,(HMENU)202,GetModuleHandleW(NULL),NULL);
        if(g_chalDC==DevClass::Mouse){
            HWND hP=CreateWindowExW(0,L"STATIC",g_chal.display.c_str(),WS_CHILD|WS_VISIBLE|SS_CENTER,12,60,480,28,hw,(HMENU)IDC_LABEL,GetModuleHandleW(NULL),NULL);
            SendMessageW(hP,WM_SETFONT,(WPARAM)hFB,TRUE);
            CreateWindowExW(0,L"STATIC",L"3 attempts remaining",WS_CHILD|WS_VISIBLE|SS_CENTER,12,90,480,18,hw,(HMENU)IDC_SUBLABEL,GetModuleHandleW(NULL),NULL);
            for(int i=0;i<5;i++){ int ci=g_chal.boxColors[i]; hBox[i]=CreateSolidBrush(CVALS[ci]); g_mouseBoxHwnd[i]=CreateWindowExW(WS_EX_CLIENTEDGE,L"BUTTON",CNAMES[ci],WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,12+i*92,116,86,62,hw,(HMENU)(UINT_PTR)(IDC_T1+i),GetModuleHandleW(NULL),NULL); }
            CreateWindowExW(0,L"BUTTON",L"Deny Access",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,185,194,120,30,hw,(HMENU)IDC_DENY,GetModuleHandleW(NULL),NULL);
        } else {
            HWND hDisp=CreateWindowExW(0,L"STATIC",g_chal.display.c_str(),WS_CHILD|WS_VISIBLE|SS_CENTER,12,60,480,52,hw,(HMENU)IDC_LABEL,GetModuleHandleW(NULL),NULL);
            SendMessageW(hDisp,WM_SETFONT,(WPARAM)hFB,TRUE);
            CreateWindowExW(0,L"STATIC",g_chal.hint.c_str(),WS_CHILD|WS_VISIBLE|SS_CENTER,12,116,480,18,hw,(HMENU)IDC_SUBLABEL,GetModuleHandleW(NULL),NULL);
            HWND hE=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",WS_CHILD|WS_VISIBLE|ES_CENTER|ES_AUTOHSCROLL,148,142,196,28,hw,(HMENU)IDC_INPUT,GetModuleHandleW(NULL),NULL);
            SendMessageW(hE,WM_SETFONT,(WPARAM)hFM,TRUE);
            HWND hSub=CreateWindowExW(0,L"BUTTON",L"Submit",WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,108,182,114,32,hw,(HMENU)IDC_SUBMIT,GetModuleHandleW(NULL),NULL);
            SendMessageW(hSub,WM_SETFONT,(WPARAM)hFB,TRUE);
            CreateWindowExW(0,L"BUTTON",L"Deny Access",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,270,182,114,32,hw,(HMENU)IDC_DENY,GetModuleHandleW(NULL),NULL);
            SetFocus(GetDlgItem(hw,IDC_INPUT));
        }
        g_wrong=0; g_timing.Reset(); return 0;
    }
    case WM_COMMAND:{
        int id=LOWORD(wp);
        if(id==IDC_SUBMIT||id==IDOK){
            wchar_t buf[128]={}; GetDlgItemTextW(hw,IDC_INPUT,buf,127);
            std::wstring input(buf);
            auto b=input.find_first_not_of(L" \t"); auto e=input.find_last_not_of(L" \t");
            input=(b==std::wstring::npos)?L"":input.substr(b,e-b+1);
            if(!g_timing.IsHuman()){ g_wrong++; g_timing.Reset(); MessageBeep(MB_ICONEXCLAMATION); if(g_wrong>=MAX_WRONG) goto deny; SetDlgItemTextW(hw,IDC_SUBLABEL,(L"Robotic input! "+std::to_wstring(MAX_WRONG-g_wrong)+L" left").c_str()); g_chal=GenKBChallenge(); SetDlgItemTextW(hw,IDC_LABEL,g_chal.display.c_str()); SetDlgItemTextW(hw,IDC_INPUT,L""); SetFocus(GetDlgItem(hw,IDC_INPUT)); return 0; }
            if(WEqCI(input,g_chal.answer)){ ApproveDevice(g_chalDev); Cleanup(); DestroyWindow(hw); PostQuitMessage(0); }
            else{ g_wrong++; g_timing.Reset(); MessageBeep(MB_ICONEXCLAMATION); if(g_wrong>=MAX_WRONG){ MessageBoxW(hw,L"Max attempts. Device blocked.",L"Blocked",MB_OK|MB_ICONERROR|MB_TOPMOST); goto deny; } SetDlgItemTextW(hw,IDC_SUBLABEL,(L"Wrong. "+std::to_wstring(MAX_WRONG-g_wrong)+L" left").c_str()); g_chal=GenKBChallenge(); SetDlgItemTextW(hw,IDC_LABEL,g_chal.display.c_str()); SetDlgItemTextW(hw,IDC_INPUT,L""); SetFocus(GetDlgItem(hw,IDC_INPUT)); }
            return 0;
        }
        if(id>=IDC_T1&&id<=IDC_T5){ int clicked=id-IDC_T1; if(clicked==g_chal.targetBox){ ApproveDevice(g_chalDev); Cleanup(); DestroyWindow(hw); PostQuitMessage(0); } else{ g_wrong++; MessageBeep(MB_ICONEXCLAMATION); if(g_wrong>=MAX_WRONG) goto deny; SetDlgItemTextW(hw,IDC_SUBLABEL,(L"Wrong box. "+std::to_wstring(MAX_WRONG-g_wrong)+L" left").c_str()); g_chal=GenMouseChallenge(); SetDlgItemTextW(hw,IDC_LABEL,g_chal.display.c_str()); for(int i=0;i<5;i++){ int ci=g_chal.boxColors[i]; SetWindowTextW(g_mouseBoxHwnd[i],CNAMES[ci]); if(hBox[i])DeleteObject(hBox[i]); hBox[i]=CreateSolidBrush(CVALS[ci]); InvalidateRect(g_mouseBoxHwnd[i],NULL,TRUE); } } return 0; }
        if(id==IDC_DENY||id==IDCANCEL){ deny: DenyDevice(g_chalDev); Cleanup(); DestroyWindow(hw); PostQuitMessage(0); return 0; }
        return 0;
    }
    case WM_KEYDOWN:{ if((HWND)GetFocus()==GetDlgItem(hw,IDC_INPUT)) g_timing.Add((double)GetTickCount64()); return DefWindowProcW(hw,msg,wp,lp); }
    case WM_CTLCOLORBTN:{ HWND hC=(HWND)lp; for(int i=0;i<5;i++) if(hC==g_mouseBoxHwnd[i]&&hBox[i]){ SetTextColor((HDC)wp,RGB(255,255,255)); SetBkMode((HDC)wp,TRANSPARENT); return(LRESULT)hBox[i]; } return DefWindowProcW(hw,msg,wp,lp); }
    case WM_ERASEBKGND:{ RECT rc; GetClientRect(hw,&rc); FillRect((HDC)wp,&rc,hBg); return 1; }
    case WM_CTLCOLORSTATIC:{ SetBkMode((HDC)wp,TRANSPARENT); SetTextColor((HDC)wp,RGB(200,215,255)); return(LRESULT)hBg; }
    case WM_CTLCOLOREDIT:{ SetBkColor((HDC)wp,RGB(30,35,60)); SetTextColor((HDC)wp,RGB(220,235,255)); return(LRESULT)hEdit; }
    case WM_CLOSE: SendMessageW(hw,WM_COMMAND,IDC_DENY,0); return 0;
    case WM_DESTROY: Cleanup(); return 0;
    }
    return DefWindowProcW(hw,msg,wp,lp);
}

// ─────────────────────────────────────────────────────────────────────────────
// CAPTCHA thread
// ─────────────────────────────────────────────────────────────────────────────
DWORD WINAPI CaptchaThread(LPVOID)
{
    g_wrong=0; g_timing.Reset();
    if(g_chalDC==DevClass::Mouse) g_chal=GenMouseChallenge();
    else                           g_chal=GenKBChallenge();
    int sw=GetSystemMetrics(SM_CXSCREEN), sh=GetSystemMetrics(SM_CYSCREEN);
    static bool regKB=false, regM=false;
    if(g_chalDC==DevClass::Mouse&&!regM){ WNDCLASSW wc={}; wc.lpfnWndProc=CaptchaProc; wc.hInstance=GetModuleHandleW(NULL); wc.hbrBackground=(HBRUSH)GetStockObject(BLACK_BRUSH); wc.lpszClassName=L"CaptchaMouse"; wc.hCursor=LoadCursorW(NULL,IDC_ARROW); RegisterClassW(&wc); regM=true; }
    if(g_chalDC!=DevClass::Mouse&&!regKB){ WNDCLASSW wc={}; wc.lpfnWndProc=CaptchaProc; wc.hInstance=GetModuleHandleW(NULL); wc.hbrBackground=(HBRUSH)GetStockObject(BLACK_BRUSH); wc.lpszClassName=L"CaptchaKeyboard"; wc.hCursor=LoadCursorW(NULL,IDC_ARROW); RegisterClassW(&wc); regKB=true; }
    const wchar_t* cls=(g_chalDC==DevClass::Mouse)?L"CaptchaMouse":L"CaptchaKeyboard";
    int w=510, h=(g_chalDC==DevClass::Mouse?244:270);
    g_hCaptcha=CreateWindowExW(WS_EX_TOPMOST|WS_EX_DLGMODALFRAME,cls,L"USB Gatekeeper",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_VISIBLE,(sw-w)/2,(sh-h)/2,w,h,NULL,NULL,GetModuleHandleW(NULL),NULL);
    ShowWindow(g_hCaptcha,SW_SHOWNORMAL); UpdateWindow(g_hCaptcha); SetForegroundWindow(g_hCaptcha);
    MSG msg; while(GetMessageW(&msg,NULL,0,0)>0){ if(!IsDialogMessageW(g_hCaptcha,&msg)){ TranslateMessage(&msg); DispatchMessageW(&msg); } }
    g_captchaActive=false; return 0;
}

void ShowCaptcha(HANDLE hDev, DevClass dc)
{
    bool expected=false;
    if(!g_captchaActive.compare_exchange_strong(expected,true)) return;
    if(g_pending.count(hDev)){ g_captchaActive=false; return; }
    g_chalDev=hDev; g_chalDC=dc;
    { std::lock_guard<std::mutex> lk(g_devMutex); g_pending.insert(hDev); }
    HANDLE ht=CreateThread(NULL,0,CaptchaThread,hDev,0,NULL);
    if(ht) CloseHandle(ht); else g_captchaActive=false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Hook
//
// Two cases block a keystroke — nothing else:
//
//   1. LLKHF_INJECTED — software injection (AutoHotkey, SendInput etc).
//      Always blocked unconditionally.
//
//   2. g_lastRawDevice is in g_blocked — the physical device that sent
//      this keystroke is one we're waiting on a CAPTCHA for.
//      Only THAT device's keystrokes are swallowed. The user's trusted
//      keyboard types freely at all times — including into the CAPTCHA
//      answer field.
//
// We deliberately do NOT block "all typing outside captcha window".
// That approach broke: trusted keyboard blocked after manual unblock,
// and couldn't type into CAPTCHA after forget/reset.
// ─────────────────────────────────────────────────────────────────────────────
LRESULT CALLBACK LowLevelKBProc(int nCode, WPARAM wp, LPARAM lp)
{
    if(nCode==HC_ACTION){
        auto* kb=reinterpret_cast<KBDLLHOOKSTRUCT*>(lp);

        // Case 1: software injection — block always
        if(kb->flags & LLKHF_INJECTED){
            wchar_t kn[32]=L"?"; UINT sc=MapVirtualKeyW(kb->vkCode,MAPVK_VK_TO_VSC);
            GetKeyNameTextW((LONG)(sc<<16),kn,32);
            AppLog(L"[BLOCKED] Injection: VK=0x"+[&](){std::wostringstream s;s<<std::hex<<std::uppercase<<kb->vkCode;return s.str();}()+L" ("+kn+L")");
            return 1;
        }

        // Case 2: keystroke from a specifically blocked physical device
        {
            std::lock_guard<std::mutex> lk(g_devMutex);
            if(g_lastRawDevice && g_blocked.count(g_lastRawDevice)){
                wchar_t kn[32]=L"?"; UINT sc=MapVirtualKeyW(kb->vkCode,MAPVK_VK_TO_VSC);
                GetKeyNameTextW((LONG)(sc<<16),kn,32);
                AppLog(L"[BLOCKED] Device key: ("+std::wstring(kn)+L")");
                return 1;
            }
        }
    }
    return CallNextHookEx(g_kbHook,nCode,wp,lp);
}

// ─────────────────────────────────────────────────────────────────────────────
// Main GUI window
// ─────────────────────────────────────────────────────────────────────────────
LRESULT CALLBACK MainWndProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp)
{
    switch(msg){
    case WM_CREATE:{
        HFONT hF=CreateFontW(14,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");

        // Static labels
        HWND hsl=CreateWindowExW(0,L"STATIC",L"Event Log",WS_CHILD|WS_VISIBLE,8,8,200,16,hw,(HMENU)IDC_STATIC_LOG,GetModuleHandleW(NULL),NULL);
        SendMessageW(hsl,WM_SETFONT,(WPARAM)hF,TRUE);
        HWND hsd=CreateWindowExW(0,L"STATIC",L"Device Database (VID / PID / Serial / Name)",WS_CHILD|WS_VISIBLE,8,228,500,16,hw,(HMENU)IDC_STATIC_DEV,GetModuleHandleW(NULL),NULL);
        SendMessageW(hsd,WM_SETFONT,(WPARAM)hF,TRUE);

        // Log listbox
        g_hLog=CreateWindowExW(WS_EX_CLIENTEDGE,L"LISTBOX",NULL,
            WS_CHILD|WS_VISIBLE|WS_VSCROLL|LBS_NOSEL|LBS_NOINTEGRALHEIGHT,
            8,26,784,194,hw,(HMENU)IDC_LOG,GetModuleHandleW(NULL),NULL);
        SendMessageW(g_hLog,WM_SETFONT,(WPARAM)hF,TRUE);

        // Device ListView
        g_hDevList=CreateWindowExW(WS_EX_CLIENTEDGE,WC_LISTVIEWW,NULL,
            WS_CHILD|WS_VISIBLE|LVS_REPORT|LVS_SINGLESEL|LVS_SHOWSELALWAYS,
            8,248,784,230,hw,(HMENU)IDC_DEVLIST,GetModuleHandleW(NULL),NULL);
        SendMessageW(g_hDevList,LVM_SETEXTENDEDLISTVIEWSTYLE,0,LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES);
        SendMessageW(g_hDevList,WM_SETFONT,(WPARAM)hF,TRUE);

        // ListView columns
        LVCOLUMNW col={};
        col.mask=LVCF_TEXT|LVCF_WIDTH;
        col.cx=80;  col.pszText=(LPWSTR)L"Status";   SendMessageW(g_hDevList,LVM_INSERTCOLUMNW,0,(LPARAM)&col);
        col.cx=70;  col.pszText=(LPWSTR)L"VID";       SendMessageW(g_hDevList,LVM_INSERTCOLUMNW,1,(LPARAM)&col);
        col.cx=70;  col.pszText=(LPWSTR)L"PID";       SendMessageW(g_hDevList,LVM_INSERTCOLUMNW,2,(LPARAM)&col);
        col.cx=160; col.pszText=(LPWSTR)L"Serial";    SendMessageW(g_hDevList,LVM_INSERTCOLUMNW,3,(LPARAM)&col);
        col.cx=380; col.pszText=(LPWSTR)L"Device";    SendMessageW(g_hDevList,LVM_INSERTCOLUMNW,4,(LPARAM)&col);

        // Buttons
        HWND hBA=CreateWindowExW(0,L"BUTTON",L"Allow Selected",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,8,486,130,28,hw,(HMENU)IDC_BTN_ALLOW,GetModuleHandleW(NULL),NULL);
        SendMessageW(hBA,WM_SETFONT,(WPARAM)hF,TRUE);
        HWND hBB=CreateWindowExW(0,L"BUTTON",L"Block Selected",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,146,486,130,28,hw,(HMENU)IDC_BTN_BLOCK,GetModuleHandleW(NULL),NULL);
        SendMessageW(hBB,WM_SETFONT,(WPARAM)hF,TRUE);
        HWND hBC=CreateWindowExW(0,L"BUTTON",L"Clear Log",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,284,486,100,28,hw,(HMENU)IDC_BTN_CLEAR,GetModuleHandleW(NULL),NULL);
        SendMessageW(hBC,WM_SETFONT,(WPARAM)hF,TRUE);
        HWND hBF=CreateWindowExW(0,L"BUTTON",L"Forget Device",WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,392,486,130,28,hw,(HMENU)IDC_BTN_FORGET,GetModuleHandleW(NULL),NULL);
        SendMessageW(hBF,WM_SETFONT,(WPARAM)hF,TRUE);
        return 0;
    }
    case WM_COMMAND:{
        int id=LOWORD(wp);
        if(id==IDC_BTN_ALLOW||id==IDC_BTN_BLOCK){
            int sel=(int)SendMessageW(g_hDevList,LVM_GETNEXTITEM,-1,LVNI_SELECTED);
            if(sel<0){ MessageBoxW(hw,L"Select a device first.",L"No Selection",MB_OK|MB_ICONINFORMATION); return 0; }
            // Get fullName from DB by index
            int row=0; std::wstring targetName;
            { std::lock_guard<std::mutex> lk(g_devMutex);
              for(auto& kv:g_db){ if(row==sel){targetName=kv.first;break;} row++; } }
            if(targetName.empty()) return 0;
            if(id==IDC_BTN_ALLOW) ManualAllow(targetName);
            else                   ManualBlock(targetName);
        }
        if(id==IDC_BTN_CLEAR){ SendMessageW(g_hLog,LB_RESETCONTENT,0,0); }
        if(id==IDC_BTN_FORGET){
            int sel=(int)SendMessageW(g_hDevList,LVM_GETNEXTITEM,-1,LVNI_SELECTED);
            if(sel<0){ MessageBoxW(hw,L"Select a device first.",L"No Selection",MB_OK|MB_ICONINFORMATION); return 0; }
            int row=0; std::wstring targetKey;
            { std::lock_guard<std::mutex> lk(g_devMutex);
              for(auto& kv:g_db){ if(row==sel){targetKey=kv.first;break;} row++; } }
            if(targetKey.empty()) return 0;
            if(MessageBoxW(hw,L"Forget this device? It will be treated as brand new on next plug-in and require a fresh CAPTCHA.",L"Confirm Forget",MB_YESNO|MB_ICONQUESTION)!=IDYES) return 0;
            ManualForget(targetKey);
        }
        return 0;
    }
    case WM_SIZE:{
        int W=LOWORD(lp), H=HIWORD(lp);
        if(g_hLog)     SetWindowPos(g_hLog,NULL,8,26,W-16,194,SWP_NOZORDER);
        if(g_hDevList) SetWindowPos(g_hDevList,NULL,8,248,W-16,H-290,SWP_NOZORDER);
        return 0;
    }
    case WM_CLOSE: ShowWindow(hw,SW_HIDE); return 0; // hide instead of close
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hw,msg,wp,lp);
}

// ─────────────────────────────────────────────────────────────────────────────
// Background message window (WM_INPUT + WM_DEVICECHANGE)
// ─────────────────────────────────────────────────────────────────────────────
LRESULT CALLBACK MsgWndProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg){
    case WM_INPUT:{
        UINT sz=0; GetRawInputData((HRAWINPUT)lParam,RID_INPUT,NULL,&sz,sizeof(RAWINPUTHEADER));
        std::vector<BYTE> buf(sz);
        if(GetRawInputData((HRAWINPUT)lParam,RID_INPUT,buf.data(),&sz,sizeof(RAWINPUTHEADER))==sz){
            auto* raw=reinterpret_cast<RAWINPUT*>(buf.data());
            if(raw->header.dwType==RIM_TYPEKEYBOARD||raw->header.dwType==RIM_TYPEMOUSE){
                g_lastRawDevice=raw->header.hDevice; g_rawReady=true;
            }
        }
        return DefWindowProcW(hWnd,uMsg,wParam,lParam);
    }
    case WM_DEVICECHANGE:{
        if(wParam==DBT_DEVICEARRIVAL){
            auto* hdr=reinterpret_cast<DEV_BROADCAST_HDR*>(lParam);
            if(hdr&&hdr->dbch_devicetype==DBT_DEVTYP_DEVICEINTERFACE){
                Sleep(300);
                HANDLE newDev=NULL; DevClass dc=DevClass::Unknown;
                auto kbs=EnumByType(RIM_TYPEKEYBOARD);
                { std::lock_guard<std::mutex> lk(g_devMutex);
                  for(HANDLE h:kbs){
                      if(IsTrusted(h)||g_blocked.count(h)||g_pending.count(h)) continue;
                      auto st=DBStatus(h);
                      if(st==DevRecord::Status::Blocked){
                          // Previously blocked (failed CAPTCHA or manually blocked)
                          // Silently re-block, no CAPTCHA
                          g_blocked.insert(h);
                          AppLog(L"[SILENTLY BLOCKED] "+ShortName(h));
                          continue;
                      }
                      // Unknown (forgotten) or not in DB at all → block + show CAPTCHA
                      g_blocked.insert(h); newDev=h; dc=DevClass::Keyboard;
                      AppLog(L"[ALERT] New keyboard: "+ShortName(h)); break;
                  }
                }
                if(!newDev){
                    auto mice=EnumByType(RIM_TYPEMOUSE);
                    std::lock_guard<std::mutex> lk(g_devMutex);
                    for(HANDLE h:mice){
                        if(IsTrusted(h)||g_blocked.count(h)||g_pending.count(h)) continue;
                        auto st=DBStatus(h);
                        if(st==DevRecord::Status::Blocked){
                            g_blocked.insert(h);
                            AppLog(L"[SILENTLY BLOCKED] "+ShortName(h));
                            continue;
                        }
                        newDev=h; dc=DevClass::Mouse;
                        AppLog(L"[ALERT] New mouse: "+ShortName(h)); break;
                    }
                }
                // Record new device in DB as Unknown if not seen before
                // NOTE: ShowCaptcha must be called WITHOUT holding g_devMutex
                // because it acquires g_devMutex internally — deadlock otherwise.
                if(newDev){
                    {
                        std::lock_guard<std::mutex> lk(g_devMutex);
                        DevRecord r=BuildRecord(newDev);
                        std::wstring dbk=MakeDBKey(r.fullName);
                        if(!g_db.count(dbk)){ g_db[dbk]=r; }
                    }
                    SaveDB();
                    RefreshDevList();
                    ShowCaptcha(newDev,dc);  // called outside the lock
                }
            }
        } else if(wParam==DBT_DEVICEREMOVECOMPLETE){
            auto kbs=EnumByType(RIM_TYPEKEYBOARD); auto mice=EnumByType(RIM_TYPEMOUSE);
            std::set<HANDLE> all; all.insert(kbs.begin(),kbs.end()); all.insert(mice.begin(),mice.end());
            std::lock_guard<std::mutex> lk(g_devMutex);
            for(auto it=g_blocked.begin();it!=g_blocked.end();) it=all.count(*it)?++it:g_blocked.erase(it);
            for(auto it=g_pending.begin();it!=g_pending.end();) it=all.count(*it)?++it:g_pending.erase(it);
            if(g_chalDev&&!all.count(g_chalDev)){ if(g_hCaptcha){DestroyWindow(g_hCaptcha);g_hCaptcha=NULL;} g_chalDev=NULL; g_captchaActive=false; }
        }
        return TRUE;
    }
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hWnd,uMsg,wParam,lParam);
}

// ─────────────────────────────────────────────────────────────────────────────
// System tray
// ─────────────────────────────────────────────────────────────────────────────
#define WM_TRAYICON (WM_USER+1)
#define IDI_TRAY 1
NOTIFYICONDATAW g_nid={};

void AddTrayIcon(HWND hw)
{
    g_nid.cbSize=sizeof(g_nid); g_nid.hWnd=hw; g_nid.uID=IDI_TRAY;
    g_nid.uFlags=NIF_ICON|NIF_MESSAGE|NIF_TIP;
    g_nid.uCallbackMessage=WM_TRAYICON;
    g_nid.hIcon=LoadIconW(NULL,IDI_SHIELD);
    wcscpy_s(g_nid.szTip,L"USB Gatekeeper — Active");
    Shell_NotifyIconW(NIM_ADD,&g_nid);
}
void RemoveTrayIcon(){ Shell_NotifyIconW(NIM_DELETE,&g_nid); }

LRESULT CALLBACK TrayWndProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp)
{
    if(msg==WM_TRAYICON){
        if(lp==WM_LBUTTONDBLCLK||lp==WM_RBUTTONUP){
            ShowWindow(g_hWnd,IsWindowVisible(g_hWnd)?SW_HIDE:SW_SHOW);
            if(IsWindowVisible(g_hWnd)) SetForegroundWindow(g_hWnd);
        }
        return 0;
    }
    return DefWindowProcW(hw,msg,wp,lp);
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────
int WINAPI WinMain(HINSTANCE hInst, HINSTANCE, LPSTR, int)
{
    // Init common controls for ListView
    INITCOMMONCONTROLSEX icc={sizeof(icc),ICC_LISTVIEW_CLASSES};
    InitCommonControlsEx(&icc);

    // No console — logs go to the GUI log panel only

    // DB path: same folder as exe
    wchar_t exePath[MAX_PATH]; GetModuleFileNameW(NULL,exePath,MAX_PATH);
    wchar_t* sl=wcsrchr(exePath,L'\\');
    if(sl){ wcscpy_s(sl+1,MAX_PATH-(sl-exePath)-1,L"usb_gatekeeper_db.txt"); g_dbPath=exePath; }

    // Load persistent DB
    LoadDB();
    AppLog(L"[INFO] Loaded DB: "+std::to_wstring(g_db.size())+L" entries");

    // BCrypt check
    BYTE test[4]={}; if(!CryptoRandomBytes(test,4)){ MessageBoxW(NULL,L"BCrypt failed",L"Fatal",MB_OK|MB_ICONERROR); return 1; }

    // Populate runtime trust sets from DB (Allowed entries → g_trustedNames/VIDs)
    { std::lock_guard<std::mutex> lk(g_devMutex); RebuildTrustFromDB(); }

    // Snapshot devices present at startup
    // Rules:
    //   DB says Allowed  → trust it (add to runtime sets), update handle
    //   DB says Blocked  → add to g_blocked (still block it even if present)
    //   DB says Unknown / not in DB → trust it (it was here before we started)
    {
        std::lock_guard<std::mutex> lk(g_devMutex);
        bool dbDirty=false;
        auto processStartupDev=[&](HANDLE h){
            DevRecord r=BuildRecord(h);
            std::wstring dbk=MakeDBKey(r.fullName);
            auto it=g_db.find(dbk);
            if(it!=g_db.end()){
                if(it->second.status==DevRecord::Status::Blocked){
                    // Previously blocked — keep blocked
                    g_blocked.insert(h);
                    AppLog(L"[STARTUP] Blocked (DB): "+r.friendly);
                } else if(it->second.status==DevRecord::Status::Allowed) {
                    // Previously allowed — trust it silently
                    TrustDev(h);
                    it->second.fullName=r.fullName;
                    AppLog(L"[STARTUP] Trusted (DB): "+r.friendly);
                } else {
                    // Unknown (forgotten) — block it, CAPTCHA will be shown after startup
                    g_blocked.insert(h);
                    AppLog(L"[STARTUP] Forgotten device blocked — CAPTCHA required: "+r.friendly);
                }
            } else {
                // Never seen before — trust it (was present before we started)
                TrustDev(h);
                r.status=DevRecord::Status::Allowed;
                g_db[dbk]=r;
                dbDirty=true;
                AppLog(L"[STARTUP] Trusted (new): "+r.friendly);
            }
        };
        for(HANDLE h:EnumByType(RIM_TYPEKEYBOARD)) processStartupDev(h);
        for(HANDLE h:EnumByType(RIM_TYPEMOUSE))    processStartupDev(h);
        AppLog(L"[INFO] "+std::to_wstring(g_trusted.size())+L" trusted, "
               +std::to_wstring(g_blocked.size())+L" blocked at startup");
        if(dbDirty){} // SaveDB called below outside lock
    }
    SaveDB();

    // Show CAPTCHA for Unknown devices already plugged in at startup.
    // Blocked devices stay silently blocked — no CAPTCHA for them.
    // Must be outside the mutex — ShowCaptcha acquires it internally.
    {
        std::vector<std::pair<HANDLE,DevClass>> toChallenge;
        {
            std::lock_guard<std::mutex> lk(g_devMutex);
            for(HANDLE h:EnumByType(RIM_TYPEKEYBOARD))
                if(g_blocked.count(h)&&!g_pending.count(h)&&DBStatus(h)==DevRecord::Status::Unknown)
                    toChallenge.push_back({h,DevClass::Keyboard});
            for(HANDLE h:EnumByType(RIM_TYPEMOUSE))
                if(g_blocked.count(h)&&!g_pending.count(h)&&DBStatus(h)==DevRecord::Status::Unknown)
                    toChallenge.push_back({h,DevClass::Mouse});
        }
        for(auto& [h,dc]:toChallenge) ShowCaptcha(h,dc);
    }

    // Register main GUI window class
    WNDCLASSW wcMain={};
    wcMain.lpfnWndProc=MainWndProc; wcMain.hInstance=hInst;
    wcMain.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);
    wcMain.lpszClassName=L"USBGatekeeperMain";
    wcMain.hCursor=LoadCursorW(NULL,IDC_ARROW);
    wcMain.hIcon=LoadIconW(NULL,IDI_SHIELD);
    RegisterClassW(&wcMain);

    g_hWnd=CreateWindowExW(0,L"USBGatekeeperMain",L"USB Gatekeeper v4.0",
        WS_OVERLAPPEDWINDOW,CW_USEDEFAULT,CW_USEDEFAULT,820,560,
        NULL,NULL,hInst,NULL);
    ShowWindow(g_hWnd,SW_SHOW); UpdateWindow(g_hWnd);
    RefreshDevList();

    // Register tray icon wnd class
    WNDCLASSW wcTray={};
    wcTray.lpfnWndProc=TrayWndProc; wcTray.hInstance=hInst; wcTray.lpszClassName=L"USBTray";
    RegisterClassW(&wcTray);
    HWND hTray=CreateWindowExW(0,L"USBTray",L"",0,0,0,0,0,HWND_MESSAGE,NULL,hInst,NULL);
    AddTrayIcon(hTray);

    // Background message-only window for Raw Input + WM_DEVICECHANGE
    WNDCLASSW wcMsg={};
    wcMsg.lpfnWndProc=MsgWndProc; wcMsg.hInstance=hInst; wcMsg.lpszClassName=L"USBGatekeeperMsg";
    RegisterClassW(&wcMsg);
    g_hMsgWnd=CreateWindowExW(0,L"USBGatekeeperMsg",L"",0,0,0,0,0,HWND_MESSAGE,NULL,hInst,NULL);

    // Raw Input
    RAWINPUTDEVICE rids[2]={};
    rids[0].usUsagePage=HID_USAGE_PAGE_GENERIC; rids[0].usUsage=HID_USAGE_GENERIC_KEYBOARD; rids[0].dwFlags=RIDEV_INPUTSINK; rids[0].hwndTarget=g_hMsgWnd;
    rids[1].usUsagePage=HID_USAGE_PAGE_GENERIC; rids[1].usUsage=HID_USAGE_GENERIC_MOUSE;    rids[1].dwFlags=RIDEV_INPUTSINK; rids[1].hwndTarget=g_hMsgWnd;
    RegisterRawInputDevices(rids,2,sizeof(RAWINPUTDEVICE));

    // Device notifications
    DEV_BROADCAST_DEVICEINTERFACE nf={}; nf.dbcc_size=sizeof(nf); nf.dbcc_devicetype=DBT_DEVTYP_DEVICEINTERFACE;
    nf.dbcc_classguid={0x4D1E55B2,0xF16F,0x11CF,{0x88,0xCB,0x00,0x11,0x11,0x00,0x00,0x30}};
    g_hDevNotify=RegisterDeviceNotificationW(g_hMsgWnd,&nf,DEVICE_NOTIFY_WINDOW_HANDLE);

    // Keyboard hook
    g_kbHook=SetWindowsHookExW(WH_KEYBOARD_LL,LowLevelKBProc,hInst,0);

    AppLog(L"[INFO] USB Gatekeeper active");

    MSG msg;
    while(GetMessageW(&msg,NULL,0,0)>0){ TranslateMessage(&msg); DispatchMessageW(&msg); }

    UnhookWindowsHookEx(g_kbHook);
    UnregisterDeviceNotification(g_hDevNotify);
    RemoveTrayIcon();
    SaveDB();
    return 0;
}