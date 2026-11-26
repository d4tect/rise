#include <windows.h>
#include <winternl.h>
#include <aclapi.h>
#include <sddl.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#ifndef OBJ_CASE_INSENSITIVE
#define OBJ_CASE_INSENSITIVE 0x00000040
#endif

#define FILE_ALL 0x001F01FF

typedef NTSTATUS (NTAPI *NtOpenFile_t)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
typedef VOID (NTAPI *RtlInitUnicodeString_t)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS (NTAPI *NtQueryInformationFile_t)(
    HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);

static NtOpenFile_t pNtOpenFile;
static RtlInitUnicodeString_t pRtlInitUnicodeString;
static NtQueryInformationFile_t pNtQueryInformationFile;

static int gReadable;
static int gOpenFail;
static int gFlagged;
static int gCandidates;

typedef struct
{
    ULONG NumberOfProcessIdsInList;
    ULONG_PTR ProcessIdList[64];
} PIDS_USING_FILE;

typedef struct
{
    char who[320];
    ACCESS_MASK mask;
} WeakEntry;

static const wchar_t *gBuiltinRpc[] = {
    L"initshutdown", L"lsass", L"ntsvcs", L"epmapper", L"lsm_api_service",
    L"atsvc", L"eventlog", L"wkssvc", L"trkwks", L"srvsvc", L"w32time_alt",
    L"router", L"scerpc", L"plugplay", L"winreg", L"spoolss", L"netdfs",
    L"browser", L"efsrpc", L"dav rpc service", L"protected_storage",
    L"keysvc", L"tapsrv", L"wmiep"
};

static BOOL IsBuiltinRpc(PCWSTR name)
{
    wchar_t low[260];
    wcsncpy(low, name, 259);
    low[259] = 0;
    _wcslwr(low);

    for (int i = 0; i < (int)(sizeof(gBuiltinRpc) / sizeof(gBuiltinRpc[0])); i++)
    {
        if (wcscmp(low, gBuiltinRpc[i]) == 0)
        {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL IsWeakSid(PSID sid)
{
    static const WELL_KNOWN_SID_TYPE weak[] = {
        WinWorldSid,
        WinAuthenticatedUserSid,
        WinBuiltinUsersSid,
        WinInteractiveSid,
        WinAnonymousSid
    };

    for (int i = 0; i < (int)(sizeof(weak) / sizeof(weak[0])); i++)
    {
        BYTE buf[SECURITY_MAX_SID_SIZE];
        DWORD sz = sizeof(buf);
        if (CreateWellKnownSid(weak[i], NULL, buf, &sz) && EqualSid(sid, (PSID)buf))
        {
            return TRUE;
        }
    }
    return FALSE;
}

static BOOL IsWriteMask(ACCESS_MASK mask)
{
    const ACCESS_MASK writeBits =
        GENERIC_ALL | GENERIC_WRITE | WRITE_DAC | WRITE_OWNER |
        FILE_WRITE_DATA | FILE_APPEND_DATA;

    return (mask & writeBits) != 0;
}

static BOOL IsHighMask(ACCESS_MASK mask)
{
    if (mask & GENERIC_ALL)
    {
        return TRUE;
    }
    if ((mask & FILE_ALL) == FILE_ALL)
    {
        return TRUE;
    }
    if (mask & (WRITE_DAC | WRITE_OWNER))
    {
        return TRUE;
    }
    return FALSE;
}

static const char *MaskWords(ACCESS_MASK mask)
{
    if (mask & WRITE_DAC)
    {
        return "can rewrite permissions";
    }
    if (IsHighMask(mask))
    {
        return "full control";
    }
    return "read/write";
}

static void SidToText(PSID sid, char *out, DWORD outLen)
{
    char *s = NULL;
    if (!ConvertSidToStringSidA(sid, &s))
    {
        snprintf(out, outLen, "<sid?>");
        return;
    }

    char name[256];
    char dom[256];
    DWORD n = sizeof(name);
    DWORD d = sizeof(dom);
    SID_NAME_USE use;

    if (LookupAccountSidA(NULL, sid, name, &n, dom, &d, &use))
    {
        snprintf(out, outLen, "%s\\%s", dom, name);
    }
    else
    {
        snprintf(out, outLen, "%s", s);
    }

    LocalFree(s);
}

static HANDLE OpenPipeForQuery(PCWSTR name, NTSTATUS *outStatus)
{
    WCHAR full[1024];
    swprintf(full, 1024, L"\\Device\\NamedPipe\\%s", name);

    UNICODE_STRING u;
    pRtlInitUnicodeString(&u, full);

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &u, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE h = NULL;
    IO_STATUS_BLOCK iosb;
    NTSTATUS st = pNtOpenFile(
        &h,
        READ_CONTROL,
        &oa,
        &iosb,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        0);

    *outStatus = st;
    if (st < 0)
    {
        return NULL;
    }
    return h;
}

static ULONG ServerPid(HANDLE h)
{
    if (!pNtQueryInformationFile)
    {
        return 0;
    }

    PIDS_USING_FILE info;
    IO_STATUS_BLOCK iosb;
    NTSTATUS st = pNtQueryInformationFile(h, &iosb, &info, sizeof(info), 47);
    if (st < 0)
    {
        return 0;
    }

    ULONG self = GetCurrentProcessId();
    for (ULONG i = 0; i < info.NumberOfProcessIdsInList; i++)
    {
        ULONG pid = (ULONG)info.ProcessIdList[i];
        if (pid != self && pid != 0)
        {
            return pid;
        }
    }
    return 0;
}

static void ProcImage(ULONG pid, wchar_t *out, DWORD cap, BOOL *underWindows)
{
    *underWindows = FALSE;
    if (pid == 0)
    {
        wcsncpy(out, L"(server pid unknown)", cap);
        out[cap - 1] = 0;
        return;
    }

    HANDLE p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!p)
    {
        swprintf(out, cap, L"pid %lu (no access)", pid);
        return;
    }

    WCHAR path[1024];
    DWORD n = 1024;
    if (QueryFullProcessImageNameW(p, 0, path, &n))
    {
        swprintf(out, cap, L"pid %lu  %s", pid, path);

        wchar_t low[1024];
        wcsncpy(low, path, 1023);
        low[1023] = 0;
        _wcslwr(low);
        if (wcsstr(low, L"\\windows\\"))
        {
            *underWindows = TRUE;
        }
    }
    else
    {
        swprintf(out, cap, L"pid %lu (image?)", pid);
    }

    CloseHandle(p);
}

static void InspectPipe(PCWSTR name)
{
    NTSTATUS st = 0;
    HANDLE h = OpenPipeForQuery(name, &st);
    if (h == NULL)
    {
        gOpenFail++;
        return;
    }

    PACL dacl = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    DWORD err = GetSecurityInfo(
        h, SE_KERNEL_OBJECT, DACL_SECURITY_INFORMATION,
        NULL, NULL, &dacl, NULL, &sd);

    if (err != ERROR_SUCCESS)
    {
        CloseHandle(h);
        return;
    }

    gReadable++;

    BOOL nullDacl = (dacl == NULL);
    WeakEntry entries[16];
    int ne = 0;
    BOOL highAccess = nullDacl;

    if (!nullDacl)
    {
        for (WORD i = 0; i < dacl->AceCount && ne < 16; i++)
        {
            LPVOID ace = NULL;
            if (!GetAce(dacl, i, &ace))
            {
                continue;
            }

            ACE_HEADER *hdr = (ACE_HEADER *)ace;
            if (hdr->AceType != ACCESS_ALLOWED_ACE_TYPE)
            {
                continue;
            }

            ACCESS_ALLOWED_ACE *aa = (ACCESS_ALLOWED_ACE *)ace;
            PSID sid = (PSID)&aa->SidStart;

            if (IsWeakSid(sid) && IsWriteMask(aa->Mask))
            {
                SidToText(sid, entries[ne].who, sizeof(entries[ne].who));
                entries[ne].mask = aa->Mask;
                if (IsHighMask(aa->Mask))
                {
                    highAccess = TRUE;
                }
                ne++;
            }
        }
    }

    if (nullDacl || ne > 0)
    {
        gFlagged++;

        BOOL builtin = IsBuiltinRpc(name);
        ULONG pid = ServerPid(h);
        wchar_t image[1100];
        BOOL underWin = FALSE;
        ProcImage(pid, image, 1100, &underWin);

        BOOL candidate = (!builtin && !underWin && highAccess);
        if (candidate)
        {
            gCandidates++;
        }

        printf("[%s] %ws  %ws%s\n",
               builtin ? "rpc" : "3rd",
               name,
               image,
               candidate ? "   <== POSSIBLE LPE CANDIDATE" : "");

        if (nullDacl)
        {
            printf("       null DACL (everyone, full control)\n");
        }
        else
        {
            for (int i = 0; i < ne; i++)
            {
                printf("       %s  mask=0x%08lx (%s)\n",
                       entries[i].who,
                       (unsigned long)entries[i].mask,
                       MaskWords(entries[i].mask));
            }
        }
    }

    if (sd) LocalFree(sd);
    CloseHandle(h);
}

int main()
{
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    pNtOpenFile = (NtOpenFile_t)GetProcAddress(nt, "NtOpenFile");
    pRtlInitUnicodeString = (RtlInitUnicodeString_t)GetProcAddress(nt, "RtlInitUnicodeString");
    pNtQueryInformationFile = (NtQueryInformationFile_t)GetProcAddress(nt, "NtQueryInformationFile");

    if (!pNtOpenFile || !pRtlInitUnicodeString)
    {
        printf("failed to resolve ntdll exports\n");
        return 1;
    }

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(L"\\\\.\\pipe\\*", &fd);
    if (h == INVALID_HANDLE_VALUE)
    {
        printf("enum failed: %lu\n", GetLastError());
        return 1;
    }

    printf("named pipe triage ([3rd] = third-party, [rpc] = built-in Windows)\n\n");

    int total = 0;
    do
    {
        if (wcscmp(fd.cFileName, L".") == 0 || wcscmp(fd.cFileName, L"..") == 0)
        {
            continue;
        }

        InspectPipe(fd.cFileName);
        total++;
    } while (FindNextFileW(h, &fd));

    FindClose(h);

    printf("\n%d pipes, readable=%d, open_failed=%d, flagged=%d, candidates=%d\n",
           total, gReadable, gOpenFail, gFlagged, gCandidates);
    return 0;
}
