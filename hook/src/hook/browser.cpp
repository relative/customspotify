#include "browser.h"
#include "../display.h"
#include "../state.h"

/**
 * UpdateProcThreadAttribute hook is used to strip binary signature mitigation policy
 * we can't inject our DLL into renderer process without it
 */
upta orig_UpdateProcThreadAttribute;
BOOL __stdcall new_UpdateProcThreadAttribute(
    _Inout_ LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
    _In_ DWORD dwFlags,
    _In_ DWORD_PTR Attribute,
    _In_ PVOID lpValue,
    _In_ SIZE_T cbSize,
    _Out_opt_ PVOID lpPreviousValue,
    _In_opt_ PSIZE_T lpReturnSize
) {
  if (Attribute == PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY) {
    auto policy = reinterpret_cast<DWORD64*>(lpValue);
    // PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
    *policy = 0;
  }
  return orig_UpdateProcThreadAttribute(lpAttributeList, dwFlags,
                                        Attribute, lpValue,
                                        cbSize, lpPreviousValue, lpReturnSize);
}

namespace {
  typedef NTSTATUS (NTAPI *_NtQueryInformationProcess)(
      HANDLE ProcessHandle,
      DWORD ProcessInformationClass,
      PVOID ProcessInformation,
      DWORD ProcessInformationLength,
      PDWORD ReturnLength
  );
  PVOID get_ep(HANDLE hProc) {
    _NtQueryInformationProcess NtQueryInformationProcess =
        (_NtQueryInformationProcess)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    // we already checked for NtQueryInformationProcess
    PROCESS_BASIC_INFORMATION pbi;
    NtQueryInformationProcess(hProc, 0, &pbi, sizeof(pbi), nullptr);
    PEB pPEB;
    ReadProcessMemory(hProc,
                      pbi.PebBaseAddress,
                      &pPEB,
                      sizeof(PEB),
                      nullptr);
    PVOID pImage = reinterpret_cast<PVOID>(pPEB.ImageBaseAddress);
    IMAGE_DOS_HEADER pDosHeader;
    IMAGE_NT_HEADERS pNtHeaders;
    ReadProcessMemory(hProc,
                      pImage,
                      &pDosHeader,
                      sizeof(IMAGE_DOS_HEADER),
                      nullptr);
    ReadProcessMemory(hProc,
                      (PCHAR)pImage + pDosHeader.e_lfanew,
                      &pNtHeaders,
                      sizeof(IMAGE_NT_HEADERS),
                      nullptr);

    return reinterpret_cast<PVOID>(pNtHeaders.OptionalHeader.ImageBase + pNtHeaders.OptionalHeader.AddressOfEntryPoint);
  }
}

/**
 * CreateProcessAsUserW hook is used to inject ourselves into newly spawned renderer processes
 * we cannot access the V8 context from the browser (main) process
 * we remove the security token (first arg) because it has the Untrusted mandatory level (breaks a lot of things)
 */
cpauw orig_CreateProcessAsUserW;
BOOL __stdcall new_CreateProcessAsUserW(
    _In_opt_ HANDLE _hToken,
    _In_opt_ LPCWSTR lpApplicationName,
    _Inout_opt_ LPWSTR lpCommandLine,
    _In_opt_ LPSECURITY_ATTRIBUTES lpProcessAttributes,
    _In_opt_ LPSECURITY_ATTRIBUTES lpThreadAttributes, // TODO replace UPTA hk
    _In_ BOOL bInheritHandles,
    _In_ DWORD dwCreationFlags,
    _In_opt_ LPVOID lpEnvironment,
    _In_opt_ LPCWSTR lpCurrentDirectory,
    _In_ LPSTARTUPINFOEXW lpStartupInfo,
    _Out_ LPPROCESS_INFORMATION lpProcessInformation
) {
  bool bIsRenderer = wcsstr(lpCommandLine, L"type=renderer") != nullptr;
  HANDLE hToken = bIsRenderer ? nullptr : _hToken;
  auto ret = orig_CreateProcessAsUserW(
      hToken,
      lpApplicationName,
      lpCommandLine,
      lpProcessAttributes,
      lpThreadAttributes,
      bInheritHandles, dwCreationFlags,
      lpEnvironment,
      lpCurrentDirectory,
      lpStartupInfo,
      lpProcessInformation
  );
  if (bIsRenderer) {
    MessageBoxVA("Created new renderer process (%d)", lpProcessInformation->dwProcessId);
    auto hProc = lpProcessInformation->hProcess;

    // write our DLL path
    wchar_t dllPath[260] = L"";
    wcscpy_s(dllPath, _countof(dllPath), g_State->path);
    SIZE_T dwSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);
    auto pathAddress = VirtualAllocEx(hProc,
        nullptr, dwSize,
        MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
    if (!WriteProcessMemory(hProc,
        pathAddress, dllPath, dwSize,
        nullptr)) {
      MessageBoxVA("Failed WPM: %08x", GetLastError());
      return FALSE;
    }



    // write our new entry point loop
    auto ep = get_ep(hProc);
    unsigned char chLoopCode[3] = "\xEB\xFE";
    unsigned char chOldCode[3];
    DWORD dwOldPageProtect = 0;
    VirtualProtectEx(hProc,
                     ep, sizeof(chLoopCode),
                     PAGE_EXECUTE_READWRITE, &dwOldPageProtect);
    ReadProcessMemory(hProc,
                      ep, &chOldCode, sizeof(chOldCode),
                      nullptr);
    WriteProcessMemory(hProc,
                       ep, chLoopCode, sizeof(chLoopCode),
                       nullptr);

    Sleep(150);
    auto pLoadLibrary = reinterpret_cast<PAPCFUNC>
        (GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW"));

    //ResumeThread(lpProcessInformation->hThread);

    //QueueUserAPC(pLoadLibrary, lpProcessInformation->hThread, (ULONG_PTR)pathAddress);
    HANDLE hLoadThread = CreateRemoteThread(hProc,
                                         nullptr, 0,
                                         reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibrary), pathAddress,
                                         0, nullptr);
    WaitForSingleObject(hLoadThread, INFINITE);
    Sleep(150);

    // restore old entry point
    SuspendThread(lpProcessInformation->hThread);
    WriteProcessMemory(hProc, ep, chOldCode, sizeof(chOldCode), nullptr);
    VirtualProtectEx(hProc,
                     ep, sizeof(chOldCode),
                     dwOldPageProtect, nullptr);
    Sleep(150);
    ResumeThread(lpProcessInformation->hThread);
  }
  return ret;
}

ci orig_cef_initialize;
int __cdecl new_cef_initialize(const struct _cef_main_args_t* args,
                               const struct _cef_settings_t* settings,
                               cef_app_t* app,
                               void* windows_sandbox_info) {
  //msgboxva("args: %p\napp: %p\nsettings: %p", args, app, settings);
  const_cast<_cef_settings_t*>(settings)->remote_debugging_port = 9229;
  return orig_cef_initialize(args, settings, app, windows_sandbox_info);
}