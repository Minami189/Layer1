/*
 * USB Gatekeeper — BadUSB Interceptor
 *
 * BUILD (MSYS2 UCRT64, run as Admin):
 *   g++ -std=c++17 -o usb_gatekeeper.exe usb_gatekeeper.cpp \
 *       -luser32 -lgdi32 -lhid -lsetupapi -lbcrypt -mwindows
 */

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE

#include <windows.h>
#include <bcrypt.h>
#include <dbt.h>
#include <hidusage.h>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <vector>
#include <set>
#include <string>
#include <mutex>
#include <atomic>
#include <cmath>

#define IDC_LABEL    101
#define IDC_SUBLABEL 102
#define IDC_INPUT    103
#define IDC_SUBMIT   104
#define IDC_DENY     105
#define IDC_T1 201
#define IDC_T2 202
#define IDC_T3 203
#define IDC_T4 204
#define IDC_T5 205

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
static const wchar_t* CNAMES[]=
{L"RED",L"GREEN",L"BLUE",L"YELLOW",L"ORANGE"};
static const COLORREF CVALS[]=
{RGB(210,45,45),RGB(45,170,45),RGB(45,90,210),RGB(210,190,0),RGB(210,110,0)};

std::wstring ScrambleWord(const std::wstring& w)
{
    std::wstring s=w; int t=0;
    do{ for(int i=(int)s.size()-1;i>0;--i)
            std::swap(s[i],s[CryptoRandRange(i+1)]); }
    while(s==w && ++t<20);
    return s;
}
std::wstring SpaceLetters(const std::wstring& w)
{
    std::wstring o;
    for(size_t i=0;i<w.size();++i){ if(i)o+=L' '; o+=w[i]; }
    return o;
}
std::wstring MakeToken()
{
    const wchar_t L2[]=L"ABCDEFGHJKLMNPQRSTUVWXYZ";
    const wchar_t D2[]=L"23456789";
    std::wstring t;
    for(int g=0;g<3;++g){
        if(g)t+=L'-';
        t+=L2[CryptoRandRange((DWORD)wcslen(L2))];
        t+=D2[CryptoRandRange((DWORD)wcslen(D2))];
    }
    return t;
}
Challenge GenKBChallenge()
{
    Challenge c; c.type=(ChalType)CryptoRandRange(3);
    switch(c.type){
    case ChalType::Scramble:{
        std::wstring w=WORDS[CryptoRandRange(20)];
        c.display=SpaceLetters(ScrambleWord(w));
        c.hint=L"Unscramble into a word"; c.answer=w; break;
    }
    case ChalType::Hex:{
        BYTE code=(BYTE)(0x41+CryptoRandRange(26));
        std::wostringstream ss;
        ss<<L"0x"<<std::uppercase<<std::hex
          <<std::setw(2)<<std::setfill(L'0')<<(int)code;
        c.display=ss.str();
        c.hint=L"Type the letter this hex value represents";
        c.answer=std::wstring(1,(wchar_t)code); break;
    }
    case ChalType::Token:{
        std::wstring tok=MakeToken();
        c.display=tok; c.hint=L"Type this code exactly";
        c.answer=tok; break;
    }
    default: break;
    }
    return c;
}
Challenge GenMouseChallenge()
{
    Challenge c; c.type=ChalType::MouseColor;
    c.colorIdx=(int)CryptoRandRange(5);
    int perm[5]={0,1,2,3,4};
    for(int i=4;i>0;--i) std::swap(perm[i],perm[CryptoRandRange(i+1)]);
    for(int i=0;i<5;i++) c.boxColors[i]=perm[i];
    for(int i=0;i<5;i++) if(c.boxColors[i]==c.colorIdx){ c.targetBox=i; break; }
    c.display=std::wstring(L"Click the ")+CNAMES[c.colorIdx]+L" box";
    return c;
}
bool WEqCI(const std::wstring& a, const std::wstring& b)
{
    if(a.size()!=b.size()) return false;
    for(size_t i=0;i<a.size();++i)
        if(towupper(a[i])!=towupper(b[i])) return false;
    return true;
}

// ─────────────────────────────────────────────────────────────────────────────
// Timing analyzer
// ─────────────────────────────────────────────────────────────────────────────
struct Timing {
    std::vector<double> ts;
    void Add(double t){ ts.push_back(t); }
    void Reset(){ ts.clear(); }
    bool IsHuman() const {
        if(ts.size()<4) return true;
        std::vector<double> gaps;
        for(size_t i=1;i<ts.size();++i) gaps.push_back(ts[i]-ts[i-1]);
        double mean=0; for(double g:gaps) mean+=g; mean/=gaps.size();
        double var=0;  for(double g:gaps) var+=(g-mean)*(g-mean); var/=gaps.size();
        return !(mean<50.0 && std::sqrt(var)<20.0);
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Globals
// ─────────────────────────────────────────────────────────────────────────────
std::set<HANDLE>        g_trusted;
std::set<std::wstring>  g_trustedNames;
std::set<std::wstring>  g_trustedVIDs;
std::set<HANDLE>        g_blocked;
std::set<HANDLE>        g_pending;
std::set<std::wstring>  g_deniedNames;  // permanently blocked by name
std::set<std::wstring>  g_deniedVIDs;   // permanently blocked by VID
std::mutex              g_devMutex;

static HANDLE            g_lastRawDevice = NULL;
static bool              g_rawReady      = false;
static std::atomic<bool> g_captchaActive{false};

HHOOK      g_kbHook     = NULL;
HWND       g_hWnd       = NULL;
HWND       g_hCaptcha   = NULL;
HDEVNOTIFY g_hDevNotify = NULL;

static Challenge  g_chal;
static HANDLE     g_chalDev = NULL;
static DevClass   g_chalDC  = DevClass::Unknown;
static int        g_wrong   = 0;
static const int  MAX_WRONG = 3;
static Timing     g_timing;
static HWND       g_mouseBoxHwnd[5]={};

// ─────────────────────────────────────────────────────────────────────────────
// Device helpers
// ─────────────────────────────────────────────────────────────────────────────
std::wstring GetDevName(HANDLE h)
{
    UINT sz=0;
    GetRawInputDeviceInfoW(h,RIDI_DEVICENAME,NULL,&sz);
    if(!sz) return L"<unknown>";
    std::wstring s(sz,L'\0');
    GetRawInputDeviceInfoW(h,RIDI_DEVICENAME,s.data(),&sz);
    return s;
}
std::wstring GetVID(const std::wstring& name)
{
    auto p=name.find(L"VID_");
    if(p==std::wstring::npos) return L"";
    return name.substr(p,8);
}
std::wstring ShortName(HANDLE h)
{
    std::wstring f=GetDevName(h);
    auto p=f.find(L"VID_");
    if(p!=std::wstring::npos && f.size()>p+16) return f.substr(p,16);
    return f.size()>40 ? f.substr(0,40)+L"..." : f;
}
std::set<HANDLE> EnumByType(DWORD type)
{
    std::set<HANDLE> out; UINT n=0;
    GetRawInputDeviceList(NULL,&n,sizeof(RAWINPUTDEVICELIST));
    if(!n) return out;
    std::vector<RAWINPUTDEVICELIST> list(n);
    if(GetRawInputDeviceList(list.data(),&n,sizeof(RAWINPUTDEVICELIST))==(UINT)-1) return out;
    for(auto& d:list) if(d.dwType==type) out.insert(d.hDevice);
    return out;
}
bool IsTrusted(HANDLE h)
{
    if(g_trusted.count(h)) return true;
    std::wstring n=GetDevName(h);
    if(g_trustedNames.count(n)) return true;
    std::wstring vid=GetVID(n);
    return !vid.empty() && g_trustedVIDs.count(vid);
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
        // Trust by name+VID first so IsTrusted() returns true for all sibling handles
        TrustDev(dev);
        // Remove ALL handles from g_blocked that are now trusted (covers MI_00 + MI_03)
        for(auto it=g_blocked.begin();it!=g_blocked.end();)
            it=IsTrusted(*it)?g_blocked.erase(it):++it;
        for(auto it=g_pending.begin();it!=g_pending.end();)
            it=IsTrusted(*it)?g_pending.erase(it):++it;
        g_lastRawDevice=NULL; // force fresh WM_INPUT read
    }
    std::wcout<<L"[APPROVED] "<<ShortName(dev)<<L"\n";
    g_chalDev=NULL; g_hCaptcha=NULL; g_captchaActive=false;
}
void DenyDevice(HANDLE dev)
{
    {
        std::lock_guard<std::mutex> lk(g_devMutex);
        g_pending.erase(dev);
        // stays in g_blocked for this session
        // Record name+VID so replug is also permanently blocked
        std::wstring n=GetDevName(dev), vid=GetVID(n);
        g_deniedNames.insert(n);
        if(!vid.empty()) g_deniedVIDs.insert(vid);
    }
    std::wcout<<L"[DENIED] "<<ShortName(dev)<<L"\n";
    g_chalDev=NULL; g_hCaptcha=NULL; g_captchaActive=false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Win32 CAPTCHA window
// ─────────────────────────────────────────────────────────────────────────────
LRESULT CALLBACK CaptchaProc(HWND hw, UINT msg, WPARAM wp, LPARAM lp)
{
    static HBRUSH hBg=NULL, hEdit=NULL;
    static HFONT  hFB=NULL, hFM=NULL;
    static HBRUSH hBox[5]={};

    auto Cleanup=[&](){
        if(hBg)  {DeleteObject(hBg);  hBg=NULL;}
        if(hEdit){DeleteObject(hEdit);hEdit=NULL;}
        if(hFB)  {DeleteObject(hFB);  hFB=NULL;}
        if(hFM)  {DeleteObject(hFM);  hFM=NULL;}
        for(auto& b:hBox)if(b){DeleteObject(b);b=NULL;}
    };

    switch(msg){
    case WM_CREATE:{
        hBg  = CreateSolidBrush(RGB(18,22,40));
        hEdit= CreateSolidBrush(RGB(30,35,60));
        hFB  = CreateFontW(18,0,0,0,FW_SEMIBOLD,0,0,0,DEFAULT_CHARSET,
                           OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        hFM  = CreateFontW(17,0,0,0,FW_NORMAL,0,0,0,DEFAULT_CHARSET,
                           OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,
                           CLEARTYPE_QUALITY,FIXED_PITCH,L"Consolas");

        // Icon + title
        HWND hIcon=CreateWindowExW(0,L"STATIC",NULL,WS_CHILD|WS_VISIBLE|SS_ICON,
            16,14,32,32,hw,(HMENU)200,GetModuleHandleW(NULL),NULL);
        SendMessageW(hIcon,STM_SETICON,(WPARAM)LoadIconW(NULL,IDI_WARNING),0);

        std::wstring title = (g_chalDC==DevClass::Mouse)
            ? L"New USB Mouse Detected — Security Challenge"
            : L"New USB Keyboard Detected — Security Challenge";
        HWND hTitle=CreateWindowExW(0,L"STATIC",title.c_str(),
            WS_CHILD|WS_VISIBLE|SS_LEFT,56,16,440,22,
            hw,(HMENU)201,GetModuleHandleW(NULL),NULL);
        SendMessageW(hTitle,WM_SETFONT,(WPARAM)hFB,TRUE);

        // Divider
        CreateWindowExW(0,L"STATIC",NULL,WS_CHILD|WS_VISIBLE|SS_ETCHEDHORZ,
            12,50,480,2,hw,(HMENU)202,GetModuleHandleW(NULL),NULL);

        if(g_chalDC==DevClass::Mouse){
            // Prompt
            HWND hP=CreateWindowExW(0,L"STATIC",g_chal.display.c_str(),
                WS_CHILD|WS_VISIBLE|SS_CENTER,12,60,480,28,
                hw,(HMENU)IDC_LABEL,GetModuleHandleW(NULL),NULL);
            SendMessageW(hP,WM_SETFONT,(WPARAM)hFB,TRUE);
            // Attempts
            CreateWindowExW(0,L"STATIC",L"3 attempts remaining",
                WS_CHILD|WS_VISIBLE|SS_CENTER,12,90,480,18,
                hw,(HMENU)IDC_SUBLABEL,GetModuleHandleW(NULL),NULL);
            // Color boxes
            for(int i=0;i<5;i++){
                int ci=g_chal.boxColors[i];
                hBox[i]=CreateSolidBrush(CVALS[ci]);
                g_mouseBoxHwnd[i]=CreateWindowExW(WS_EX_CLIENTEDGE,L"BUTTON",
                    CNAMES[ci],WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
                    12+i*92,116,86,62,hw,(HMENU)(UINT_PTR)(IDC_T1+i),
                    GetModuleHandleW(NULL),NULL);
            }
            CreateWindowExW(0,L"BUTTON",L"Deny Access",
                WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
                185,194,120,30,hw,(HMENU)IDC_DENY,GetModuleHandleW(NULL),NULL);
        } else {
            // Challenge display
            HWND hDisp=CreateWindowExW(0,L"STATIC",g_chal.display.c_str(),
                WS_CHILD|WS_VISIBLE|SS_CENTER,12,60,480,52,
                hw,(HMENU)IDC_LABEL,GetModuleHandleW(NULL),NULL);
            SendMessageW(hDisp,WM_SETFONT,(WPARAM)hFB,TRUE);
            // Hint
            CreateWindowExW(0,L"STATIC",g_chal.hint.c_str(),
                WS_CHILD|WS_VISIBLE|SS_CENTER,12,116,480,18,
                hw,(HMENU)IDC_SUBLABEL,GetModuleHandleW(NULL),NULL);
            // Input
            HWND hE=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"",
                WS_CHILD|WS_VISIBLE|ES_CENTER|ES_AUTOHSCROLL,
                148,142,196,28,hw,(HMENU)IDC_INPUT,GetModuleHandleW(NULL),NULL);
            SendMessageW(hE,WM_SETFONT,(WPARAM)hFM,TRUE);
            // Buttons
            HWND hSub=CreateWindowExW(0,L"BUTTON",L"Submit",
                WS_CHILD|WS_VISIBLE|BS_DEFPUSHBUTTON,
                108,182,114,32,hw,(HMENU)IDC_SUBMIT,GetModuleHandleW(NULL),NULL);
            SendMessageW(hSub,WM_SETFONT,(WPARAM)hFB,TRUE);
            CreateWindowExW(0,L"BUTTON",L"Deny Access",
                WS_CHILD|WS_VISIBLE|BS_PUSHBUTTON,
                270,182,114,32,hw,(HMENU)IDC_DENY,GetModuleHandleW(NULL),NULL);
            SetFocus(GetDlgItem(hw,IDC_INPUT));
        }
        g_wrong=0; g_timing.Reset();
        return 0;
    }

    case WM_COMMAND:{
        int id=LOWORD(wp);

        // ── Submit keyboard answer ──────────────────────────────────────────
        if(id==IDC_SUBMIT || id==IDOK){
            wchar_t buf[128]={}; GetDlgItemTextW(hw,IDC_INPUT,buf,127);
            std::wstring input(buf);
            auto b=input.find_first_not_of(L" \t");
            auto e=input.find_last_not_of(L" \t");
            input=(b==std::wstring::npos)?L"":input.substr(b,e-b+1);

            // Robotic check
            if(!g_timing.IsHuman()){
                g_wrong++; g_timing.Reset(); MessageBeep(MB_ICONEXCLAMATION);
                if(g_wrong>=MAX_WRONG) goto deny;
                SetDlgItemTextW(hw,IDC_SUBLABEL,
                    (L"Robotic input detected! "+std::to_wstring(MAX_WRONG-g_wrong)+L" attempt(s) left").c_str());
                g_chal=GenKBChallenge();
                SetDlgItemTextW(hw,IDC_LABEL,g_chal.display.c_str());
                SetDlgItemTextW(hw,IDC_INPUT,L"");
                SetFocus(GetDlgItem(hw,IDC_INPUT));
                return 0;
            }

            if(WEqCI(input,g_chal.answer)){
                ApproveDevice(g_chalDev);
                Cleanup(); DestroyWindow(hw); PostQuitMessage(0);
            } else {
                g_wrong++; g_timing.Reset(); MessageBeep(MB_ICONEXCLAMATION);
                if(g_wrong>=MAX_WRONG){
                    MessageBoxW(hw,L"Maximum attempts exceeded. Device blocked.",
                        L"Blocked",MB_OK|MB_ICONERROR|MB_TOPMOST);
                    goto deny;
                }
                SetDlgItemTextW(hw,IDC_SUBLABEL,
                    (L"Wrong answer. "+std::to_wstring(MAX_WRONG-g_wrong)+L" attempt(s) left").c_str());
                g_chal=GenKBChallenge();
                SetDlgItemTextW(hw,IDC_LABEL,g_chal.display.c_str());
                SetDlgItemTextW(hw,IDC_INPUT,L"");
                SetFocus(GetDlgItem(hw,IDC_INPUT));
            }
            return 0;
        }

        // ── Mouse box click ─────────────────────────────────────────────────
        if(id>=IDC_T1 && id<=IDC_T5){
            int clicked=id-IDC_T1;
            if(clicked==g_chal.targetBox){
                ApproveDevice(g_chalDev);
                Cleanup(); DestroyWindow(hw); PostQuitMessage(0);
            } else {
                g_wrong++; MessageBeep(MB_ICONEXCLAMATION);
                if(g_wrong>=MAX_WRONG) goto deny;
                SetDlgItemTextW(hw,IDC_SUBLABEL,
                    (L"Wrong box. "+std::to_wstring(MAX_WRONG-g_wrong)+L" attempt(s) left").c_str());
                g_chal=GenMouseChallenge();
                SetDlgItemTextW(hw,IDC_LABEL,g_chal.display.c_str());
                for(int i=0;i<5;i++){
                    int ci=g_chal.boxColors[i];
                    SetWindowTextW(g_mouseBoxHwnd[i],CNAMES[ci]);
                    if(hBox[i]) DeleteObject(hBox[i]);
                    hBox[i]=CreateSolidBrush(CVALS[ci]);
                    InvalidateRect(g_mouseBoxHwnd[i],NULL,TRUE);
                }
            }
            return 0;
        }

        // ── Deny ────────────────────────────────────────────────────────────
        if(id==IDC_DENY || id==IDCANCEL){
            deny:
            DenyDevice(g_chalDev);
            Cleanup(); DestroyWindow(hw); PostQuitMessage(0);
            return 0;
        }
        return 0;
    }

    // Key timing — record timestamps as user types
    case WM_KEYDOWN:{
        if((HWND)GetFocus()==GetDlgItem(hw,IDC_INPUT))
            g_timing.Add((double)GetTickCount64());
        return DefWindowProcW(hw,msg,wp,lp);
    }

    case WM_CTLCOLORBTN:{
        HWND hC=(HWND)lp;
        for(int i=0;i<5;i++)
            if(hC==g_mouseBoxHwnd[i] && hBox[i]){
                SetTextColor((HDC)wp,RGB(255,255,255));
                SetBkMode((HDC)wp,TRANSPARENT);
                return (LRESULT)hBox[i];
            }
        return DefWindowProcW(hw,msg,wp,lp);
    }
    case WM_ERASEBKGND:{
        RECT rc; GetClientRect(hw,&rc);
        FillRect((HDC)wp,&rc,hBg); return 1;
    }
    case WM_CTLCOLORSTATIC:{
        SetBkMode((HDC)wp,TRANSPARENT);
        SetTextColor((HDC)wp,RGB(200,215,255));
        return (LRESULT)hBg;
    }
    case WM_CTLCOLOREDIT:{
        SetBkColor((HDC)wp,RGB(30,35,60));
        SetTextColor((HDC)wp,RGB(220,235,255));
        return (LRESULT)hEdit;
    }
    case WM_CLOSE:
        SendMessageW(hw,WM_COMMAND,IDC_DENY,0);
        return 0;
    case WM_DESTROY:
        Cleanup(); return 0;
    }
    return DefWindowProcW(hw,msg,wp,lp);
}

// ─────────────────────────────────────────────────────────────────────────────
// CAPTCHA thread
// ─────────────────────────────────────────────────────────────────────────────
DWORD WINAPI CaptchaThread(LPVOID param)
{
    g_wrong=0; g_timing.Reset();
    if(g_chalDC==DevClass::Mouse) g_chal=GenMouseChallenge();
    else                           g_chal=GenKBChallenge();

    int sw=GetSystemMetrics(SM_CXSCREEN), sh=GetSystemMetrics(SM_CYSCREEN);

    static bool regKB=false, regM=false;
    if(g_chalDC==DevClass::Mouse && !regM){
        WNDCLASSW wc={}; wc.lpfnWndProc=CaptchaProc;
        wc.hInstance=GetModuleHandleW(NULL);
        wc.hbrBackground=(HBRUSH)GetStockObject(BLACK_BRUSH);
        wc.lpszClassName=L"CaptchaMouse";
        wc.hCursor=LoadCursorW(NULL,IDC_ARROW);
        RegisterClassW(&wc); regM=true;
    }
    if(g_chalDC!=DevClass::Mouse && !regKB){
        WNDCLASSW wc={}; wc.lpfnWndProc=CaptchaProc;
        wc.hInstance=GetModuleHandleW(NULL);
        wc.hbrBackground=(HBRUSH)GetStockObject(BLACK_BRUSH);
        wc.lpszClassName=L"CaptchaKeyboard";
        wc.hCursor=LoadCursorW(NULL,IDC_ARROW);
        RegisterClassW(&wc); regKB=true;
    }

    const wchar_t* cls = (g_chalDC==DevClass::Mouse) ? L"CaptchaMouse" : L"CaptchaKeyboard";
    int w=510, h=(g_chalDC==DevClass::Mouse ? 244 : 270);

    g_hCaptcha=CreateWindowExW(
        WS_EX_TOPMOST|WS_EX_DLGMODALFRAME,
        cls, L"USB Gatekeeper",
        WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_VISIBLE,
        (sw-w)/2,(sh-h)/2,w,h,
        NULL,NULL,GetModuleHandleW(NULL),NULL);

    ShowWindow(g_hCaptcha,SW_SHOWNORMAL);
    UpdateWindow(g_hCaptcha);
    SetForegroundWindow(g_hCaptcha);

    MSG msg;
    while(GetMessageW(&msg,NULL,0,0)>0){
        if(!IsDialogMessageW(g_hCaptcha,&msg)){
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }
    g_captchaActive=false;
    return 0;
}

// ─────────────────────────────────────────────────────────────────────────────
// Show CAPTCHA — atomic to prevent duplicate spawns from repeated WM_DEVICECHANGE
// ─────────────────────────────────────────────────────────────────────────────
void ShowCaptcha(HANDLE hDev, DevClass dc)
{
    bool expected=false;
    if(!g_captchaActive.compare_exchange_strong(expected,true)) return;
    if(g_pending.count(hDev)){ g_captchaActive=false; return; }
    g_chalDev=hDev; g_chalDC=dc;
    { std::lock_guard<std::mutex> lk(g_devMutex); g_pending.insert(hDev); }
    HANDLE ht=CreateThread(NULL,0,CaptchaThread,hDev,0,NULL);
    if(ht) CloseHandle(ht);
    else   g_captchaActive=false;
}

// ─────────────────────────────────────────────────────────────────────────────
// Low-level keyboard hook
// When any device is pending: block ALL keystrokes except navigation keys
// and keystrokes while our own captcha window has focus.
// ─────────────────────────────────────────────────────────────────────────────
LRESULT CALLBACK LowLevelKBProc(int nCode, WPARAM wp, LPARAM lp)
{
    if(nCode==HC_ACTION){
        std::lock_guard<std::mutex> lk(g_devMutex);
        if(!g_blocked.empty()){
            // Allow if our captcha window is foreground
            HWND fg=GetForegroundWindow();
            DWORD fgPid=0; GetWindowThreadProcessId(fg,&fgPid);
            if(fgPid==GetCurrentProcessId())
                return CallNextHookEx(g_kbHook,nCode,wp,lp);

            // Block blocked device keystrokes
            if(g_lastRawDevice && g_blocked.count(g_lastRawDevice))
                return 1;

            // Block software injection
            if(g_rawReady && g_lastRawDevice==NULL)
                return 1;

            // Allow navigation so user can alt-tab to captcha
            auto* kb=reinterpret_cast<KBDLLHOOKSTRUCT*>(lp);
            DWORD vk=kb->vkCode;
            bool nav=(vk==VK_TAB||vk==VK_LMENU||vk==VK_RMENU||
                      vk==VK_LWIN||vk==VK_RWIN||vk==VK_ESCAPE||
                      vk==VK_LCONTROL||vk==VK_RCONTROL);
            if(nav) return CallNextHookEx(g_kbHook,nCode,wp,lp);

            return 1; // block everything else outside captcha
        }
    }
    return CallNextHookEx(g_kbHook,nCode,wp,lp);
}

// ─────────────────────────────────────────────────────────────────────────────
// Background message window
// ─────────────────────────────────────────────────────────────────────────────
LRESULT CALLBACK WindowProc(HWND hWnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch(uMsg){
    case WM_INPUT:{
        UINT sz=0;
        GetRawInputData((HRAWINPUT)lParam,RID_INPUT,NULL,&sz,sizeof(RAWINPUTHEADER));
        std::vector<BYTE> buf(sz);
        if(GetRawInputData((HRAWINPUT)lParam,RID_INPUT,
                           buf.data(),&sz,sizeof(RAWINPUTHEADER))==sz){
            auto* raw=reinterpret_cast<RAWINPUT*>(buf.data());
            if(raw->header.dwType==RIM_TYPEKEYBOARD||
               raw->header.dwType==RIM_TYPEMOUSE){
                g_lastRawDevice=raw->header.hDevice;
                g_rawReady=true;
            }
        }
        return DefWindowProcW(hWnd,uMsg,wParam,lParam);
    }
    case WM_DEVICECHANGE:{
        if(wParam==DBT_DEVICEARRIVAL){
            auto* hdr=reinterpret_cast<DEV_BROADCAST_HDR*>(lParam);
            if(hdr && hdr->dbch_devicetype==DBT_DEVTYP_DEVICEINTERFACE){
                Sleep(300);
                HANDLE newDev=NULL; DevClass dc=DevClass::Unknown;
                // Check keyboards
                auto kbs=EnumByType(RIM_TYPEKEYBOARD);
                { std::lock_guard<std::mutex> lk(g_devMutex);
                  for(HANDLE h:kbs){
                      std::wstring hn=GetDevName(h),hvid=GetVID(hn);
                      bool denied=g_deniedNames.count(hn)||(!hvid.empty()&&g_deniedVIDs.count(hvid));
                      if(!IsTrusted(h)&&!denied&&!g_blocked.count(h)&&!g_pending.count(h)){
                          g_blocked.insert(h); newDev=h; dc=DevClass::Keyboard;
                          std::wcout<<L"[ALERT] New keyboard: "<<ShortName(h)<<L"\n";
                          break;
                      }
                  }
                }
                // Check mice if no keyboard found
                if(!newDev){
                    auto mice=EnumByType(RIM_TYPEMOUSE);
                    std::lock_guard<std::mutex> lk(g_devMutex);
                    for(HANDLE h:mice){
                        std::wstring hn=GetDevName(h),hvid=GetVID(hn);
                        bool denied=g_deniedNames.count(hn)||(!hvid.empty()&&g_deniedVIDs.count(hvid));
                        if(!IsTrusted(h)&&!denied&&!g_blocked.count(h)&&!g_pending.count(h)){
                            newDev=h; dc=DevClass::Mouse;
                            std::wcout<<L"[ALERT] New mouse: "<<ShortName(h)<<L"\n";
                            break;
                        }
                    }
                }
                if(newDev) ShowCaptcha(newDev,dc);
            }
        } else if(wParam==DBT_DEVICEREMOVECOMPLETE){
            auto kbs=EnumByType(RIM_TYPEKEYBOARD);
            auto mice=EnumByType(RIM_TYPEMOUSE);
            std::set<HANDLE> all;
            all.insert(kbs.begin(),kbs.end());
            all.insert(mice.begin(),mice.end());
            std::lock_guard<std::mutex> lk(g_devMutex);
            for(auto it=g_blocked.begin();it!=g_blocked.end();)
                it=all.count(*it)?++it:g_blocked.erase(it);
            for(auto it=g_pending.begin();it!=g_pending.end();)
                it=all.count(*it)?++it:g_pending.erase(it);
            if(g_chalDev && !all.count(g_chalDev)){
                if(g_hCaptcha){ DestroyWindow(g_hCaptcha); g_hCaptcha=NULL; }
                g_chalDev=NULL; g_captchaActive=false;
            }
        }
        return TRUE;
    }
    case WM_DESTROY:
        PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hWnd,uMsg,wParam,lParam);
}

// ─────────────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────────────
int main()
{
    BYTE test[4]={};
    if(!CryptoRandomBytes(test,4)){ std::wcerr<<L"[FATAL] BCrypt init failed\n"; return 1; }
    std::wcout<<L"[INFO] BCryptGenRandom OK\n";

    // Snapshot trusted devices at startup
    { std::lock_guard<std::mutex> lk(g_devMutex);
      for(HANDLE h:EnumByType(RIM_TYPEKEYBOARD)) TrustDev(h);
      for(HANDLE h:EnumByType(RIM_TYPEMOUSE))    TrustDev(h);
      std::wcout<<L"[INFO] "<<g_trusted.size()<<L" trusted devices at startup\n"; }

    // Background message window
    WNDCLASSW wc={};
    wc.lpfnWndProc=WindowProc;
    wc.hInstance=GetModuleHandleW(NULL);
    wc.lpszClassName=L"USBGatekeeperBg";
    RegisterClassW(&wc);
    g_hWnd=CreateWindowExW(0,L"USBGatekeeperBg",L"",0,0,0,0,0,
                           HWND_MESSAGE,NULL,wc.hInstance,NULL);
    if(!g_hWnd){ std::wcerr<<L"[ERROR] "<<GetLastError()<<L"\n"; return 1; }

    // Raw Input — track which physical device is typing
    RAWINPUTDEVICE rids[2]={};
    rids[0].usUsagePage=HID_USAGE_PAGE_GENERIC;
    rids[0].usUsage=HID_USAGE_GENERIC_KEYBOARD;
    rids[0].dwFlags=RIDEV_INPUTSINK; rids[0].hwndTarget=g_hWnd;
    rids[1].usUsagePage=HID_USAGE_PAGE_GENERIC;
    rids[1].usUsage=HID_USAGE_GENERIC_MOUSE;
    rids[1].dwFlags=RIDEV_INPUTSINK; rids[1].hwndTarget=g_hWnd;
    RegisterRawInputDevices(rids,2,sizeof(RAWINPUTDEVICE));

    // Device arrival notifications
    DEV_BROADCAST_DEVICEINTERFACE nf={};
    nf.dbcc_size=sizeof(nf);
    nf.dbcc_devicetype=DBT_DEVTYP_DEVICEINTERFACE;
    nf.dbcc_classguid={0x4D1E55B2,0xF16F,0x11CF,
                       {0x88,0xCB,0x00,0x11,0x11,0x00,0x00,0x30}};
    g_hDevNotify=RegisterDeviceNotificationW(g_hWnd,&nf,DEVICE_NOTIFY_WINDOW_HANDLE);

    // Keyboard hook
    g_kbHook=SetWindowsHookExW(WH_KEYBOARD_LL,LowLevelKBProc,
                                GetModuleHandleW(NULL),0);

    std::wcout<<L"\n[USB Gatekeeper] Active. Plug in a device to test.\n\n";

    MSG msg;
    while(GetMessageW(&msg,NULL,0,0)>0){
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    UnhookWindowsHookEx(g_kbHook);
    UnregisterDeviceNotification(g_hDevNotify);
    DestroyWindow(g_hWnd);
    return 0;
}