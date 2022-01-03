//
// Created by relative on 12/20/2021.
//

#include "loader.h"
#include "../windows/MainWindow.h"
#include <TlHelp32.h>
#include <vector>
#include <Psapi.h>
#include <Shlwapi.h>
#include <filesystem>
#include <QtDebug>
#include "eventsink.h"

#define NOINLINE __declspec(noinline)

namespace fs = std::filesystem;

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

void subscribe_wmi(IWbemLocator* pLoc,
                   IWbemServices* pSvc,
                   IUnsecuredApartment* pApp,
                   EventSink* pSink,
                   IUnknown* pStubUnk,
                   IWbemObjectSink* pStubSink) {
  HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  if (FAILED(hr))
    throw std::runtime_error("Failed to initialize COM: " + std::to_string(hr));
  hr = CoInitializeSecurity(
      nullptr,
      -1,
      nullptr,
      nullptr,
      RPC_C_AUTHN_LEVEL_DEFAULT,
      RPC_C_IMP_LEVEL_IMPERSONATE,
      nullptr,
      EOAC_NONE,
      nullptr);
  if (FAILED(hr)) {
    CoUninitialize();
    throw std::runtime_error("Failed to initialize COM security level: " + std::to_string(hr));
  }

  hr = CoCreateInstance(
      CLSID_WbemLocator,
      nullptr,
      CLSCTX_INPROC_SERVER,
      IID_IWbemLocator, reinterpret_cast<void**>(&pLoc));
  if (FAILED(hr)) {
    CoUninitialize();
    throw std::runtime_error("Failed to create WbemLocator instance: " + std::to_string(hr));
  }

  hr = pLoc->ConnectServer(
      _bstr_t(L"ROOT\\CIMV2"),
      nullptr,
      nullptr,
      0,
      0,
      0,
      0,
      &pSvc);
  if (FAILED(hr)) {
    pLoc->Release();
    CoUninitialize();
    throw std::runtime_error("Failed to connect to WMI: " + std::to_string(hr));
  }

  hr = CoSetProxyBlanket(
      pSvc,
      RPC_C_AUTHN_WINNT,
      RPC_C_AUTHZ_NONE,
      nullptr,
      RPC_C_AUTHN_LEVEL_CALL,
      RPC_C_IMP_LEVEL_IMPERSONATE,
      nullptr,
      EOAC_NONE);
  if (FAILED(hr)) {
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    throw std::runtime_error("Failed to set proxy blanket: " + std::to_string(hr));
  }

  hr = CoCreateInstance(
      CLSID_UnsecuredApartment,
      nullptr,
      CLSCTX_LOCAL_SERVER,
      IID_IUnsecuredApartment, reinterpret_cast<void**>(&pApp));
  if (FAILED(hr)) {
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    throw std::runtime_error("Failed to create UnsecuredApartment instance: " + std::to_string(hr));
  }

  pApp->CreateObjectStub(pSink, &pStubUnk);

  pStubUnk->QueryInterface(IID_IWbemObjectSink, reinterpret_cast<void**>(&pStubSink));

  hr = pSvc->ExecNotificationQueryAsync(
      _bstr_t("WQL"),
      _bstr_t("SELECT * FROM __InstanceCreationEvent WITHIN 1 WHERE " // PollingInterval = 1.fsec
              "TargetInstance ISA 'Win32_Process' AND TargetInstance.Name = 'Spotify.exe'"),
      WBEM_FLAG_SEND_STATUS,
      nullptr,
      pStubSink);
  if (FAILED(hr)) {
    pSvc->Release();
    pLoc->Release();
    pApp->Release();
    pStubUnk->Release();
    pSink->Release();
    pStubSink->Release();
    CoUninitialize();
    throw std::runtime_error("Failed to setup WMI notification for Spotify.exe: " + std::to_string(hr));
  }
}

Loader::Loader() {
  this->start();
}

void Loader::run() {
  _NtQueryInformationProcess NtQueryInformationProcess =
      (_NtQueryInformationProcess)GetProcAddress(
          GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
  if (NtQueryInformationProcess == nullptr) {
    g_MainWindow->add_log_entry("NtQueryInformationProcess does not exist in your version of Windows.");
    g_MainWindow->add_log_entry("Please submit a bug report with your Windows version.");
    return;
  }
  IWbemLocator* pLoc = nullptr;
  IWbemServices* pSvc = nullptr;
  IUnsecuredApartment* pApp = nullptr;
  EventSink* pSink = new EventSink();
  IUnknown* pStubUnk = nullptr;
  IWbemObjectSink* pStubSink = nullptr;
  try {
    subscribe_wmi(pLoc, pSvc, pApp, pSink, pStubUnk, pStubSink);
    bSubscription = true;
  } catch(std::exception &ex) {
    qDebug() << "couldn't subscribe to wmi evts:" << ex.what();
  }
  DWORD ourPID = GetCurrentProcessId();
  while (!isInterruptionRequested()) {
    if (bSubscription) {
      Sleep(1500);
    } else {
      HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS | TH32CS_SNAPTHREAD, 0);
      if (snap == INVALID_HANDLE_VALUE)
        continue;
      PROCESSENTRY32 pe = {sizeof(pe)};

      if (Process32First(snap, &pe)) {
        while(Process32Next(snap, &pe)) {
          if (strstr(pe.szExeFile, "Spotify.exe") == nullptr)
            continue; // not Spotify.exe

          if (pe.th32ParentProcessID == ourPID)
            continue; // we already loaded ourselves

          // i hate windows
          HANDLE hProc;
          if ((hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE, FALSE, pe.th32ProcessID)) == nullptr) {
            g_MainWindow->add_log_entry("Failed to open PID %ld: %08x", pe.th32ProcessID, GetLastError());
            continue;
          }
          PROCESS_BASIC_INFORMATION pbi;
          NtQueryInformationProcess(hProc, 0, &pbi, sizeof(pbi), nullptr);
          PVOID rtlUserProcParamsAddress;

          if(!ReadProcessMemory(hProc,
                                &pbi.PebBaseAddress->ProcessParameters,
                                &rtlUserProcParamsAddress,
                                sizeof(PVOID),
                                nullptr)) {
            // this happens a lot
            //g_MainWindow->add_log_entry("Failed to read ProcessParameters address: %08x", GetLastError());
            continue;
          }

          UNICODE_STRING commandLine;
          if(!ReadProcessMemory(hProc,
                                &reinterpret_cast<_RTL_USER_PROCESS_PARAMETERS *>(rtlUserProcParamsAddress)->CommandLine,
                                &commandLine,
                                sizeof(commandLine),
                                nullptr)) {
            g_MainWindow->add_log_entry("Failed to read CommandLine address: %08x", GetLastError());
            continue;
          }

          wchar_t* commandLineContents = reinterpret_cast<wchar_t*>(malloc(commandLine.Length));
          if(!ReadProcessMemory(hProc,
                                commandLine.Buffer,
                                commandLineContents,
                                commandLine.Length,
                                nullptr)) {
            g_MainWindow->add_log_entry("Failed to read CommandLine buffer: %08x", GetLastError());
            continue;
          }
          if (wcsstr(commandLineContents, L"--type") != nullptr) {
            free(commandLineContents);
            continue; // this isn't the main Spotify process, also this is stupid
          }
          g_MainWindow->add_log_entry("Found main Spotify hProc: %ld", pe.th32ProcessID);
          char path[MAX_PATH];
          GetModuleFileNameEx(hProc, nullptr, path, sizeof(path));


          // this could be a Qsignal probably
          spotify_process_found(hProc, pe.th32ProcessID, path);
        }
      }
      CloseHandle(snap);
    }
  }

  if (bSubscription) {
    if (pSvc != nullptr) pSvc->Release();
    if (pLoc != nullptr) pLoc->Release();
    if (pApp != nullptr) pApp->Release();
    if (pStubUnk != nullptr) pStubUnk->Release();
    if (pSink != nullptr) pSink->Release();
    if (pStubSink != nullptr) pStubSink->Release();
    CoUninitialize();
  }
}

uint32_t Loader::spotify_process_found(HANDLE hOrigProc, DWORD dwPid, char path[MAX_PATH]) {
  if (!TerminateProcess(hOrigProc, 0)) {
    g_MainWindow->add_log_entry("Failed to terminate Spotify: %08x", GetLastError());
    return 0;
  }
  CloseHandle(hOrigProc);

  char startPath[MAX_PATH];
  strcpy_s(startPath, sizeof(startPath), path);
  // PathCchRemoveFileSpec is only available Win8+ and I'm lazy
  if (!PathRemoveFileSpecA(startPath)) {
    g_MainWindow->add_log_entry("PathRemoveFileSpecA failed: %08x", GetLastError());
    return 0;
  }
  STARTUPINFO si;
  PROCESS_INFORMATION pi;

  RtlSecureZeroMemory(&si, sizeof(si));
  RtlSecureZeroMemory(&pi, sizeof(pi));
  si.cb = sizeof(si);

  if (!CreateProcessA(path,
                     nullptr,
                     nullptr,
                     nullptr,
                     FALSE,
                     CREATE_SUSPENDED,
                     nullptr,
                     startPath,
                     &si,
                     &pi)) {
    g_MainWindow->add_log_entry("Failed to create new Spotify process: %08x", GetLastError());
    return 0;
  }
  HANDLE hProc = pi.hProcess;
  HANDLE hThread = pi.hThread;
  g_MainWindow->add_log_entry("Main proc %08x (%d)", GetProcessId(hProc), GetProcessId(hProc));
  g_MainWindow->add_log_entry("Main thread %08x (%d)", GetThreadId(hThread), GetThreadId(hThread));

  SIZE_T byteBuf;

  // Write DLL path to new process
  // TODO: verify signature in rel builds
  auto dllp = fs::current_path();
  if (fs::exists(dllp / "hook.dll")) {
    dllp =  dllp/"hook.dll";
  } else if (fs::exists(dllp / "hook/hook.dll")) {
    dllp = dllp/"hook/hook.dll";
  }
  if (!fs::is_regular_file(dllp)) return 0;
  auto st = dllp.wstring();
  const wchar_t* dllPath = st.c_str();
  SIZE_T dwSize = (wcslen(dllPath) + 1) * sizeof(wchar_t);

  auto pathAddress = VirtualAllocEx(hProc,
                                    nullptr, dwSize,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  if (!WriteProcessMemory(hProc,
                          pathAddress, dllPath, dwSize,
                          &byteBuf)) {
    g_MainWindow->add_log_entry("Failed to write DLL path to Spotify process: %08x", GetLastError());
    TerminateProcess(hProc, 0);
    return 0;
  }
  g_MainWindow->add_log_entry("Allocated DLL path at %08x and wrote %ld bytes", pathAddress, byteBuf);

  // create our new thread
  // if we don't start another thread in the process the windows ldr won't load kernel32.dll
  // https://github.com/EasyHook/EasyHook/issues/9
  unsigned char chLoopCode[3] = "\xEB\xFE";

  auto pThreadAddr = VirtualAllocEx(hProc,
                                    nullptr,
                                    sizeof(chLoopCode),
                                    MEM_COMMIT,
                                    PAGE_EXECUTE_READWRITE);
  WriteProcessMemory(hProc, pThreadAddr, chLoopCode, sizeof(chLoopCode), nullptr);
  g_MainWindow->add_log_entry("Allocated %d bytes at %08x for our thread", sizeof(chLoopCode), pThreadAddr);
  DWORD dwThreadId = 0;
  HANDLE hLoopThread = CreateRemoteThread(hProc,
                                          nullptr,
                                          0,
                                          reinterpret_cast<LPTHREAD_START_ROUTINE>(pThreadAddr),
                                          nullptr,
                                          0,
                                          &dwThreadId);
  g_MainWindow->add_log_entry("Loop thread spawned id = %08x (%d)", dwThreadId, dwThreadId);

  LPTHREAD_START_ROUTINE pLoadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>
      (GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryW"));
  HANDLE hInjectThread = CreateRemoteThread(hProc,
                     nullptr,
                     0,
                     pLoadLibrary,
                     pathAddress,
                     0,
                     nullptr);
  g_MainWindow->add_log_entry("Injecting DLL into Spotify");
  if (WaitForSingleObject(hInjectThread, 10000) == WAIT_TIMEOUT) {
    g_MainWindow->add_log_entry("Waiting for inject thread timed out (10 seconds)");
    TerminateProcess(hProc, 1);
    return 0;
  }
  Sleep(3000);
  g_MainWindow->add_log_entry("Injection complete!");
  TerminateThread(hLoopThread, 0);
  ResumeThread(hThread);
  // TODO: free DLL path from proc mem
  return pi.dwProcessId;
}


