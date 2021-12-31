#include "ntdll.h" // #include <Windows.h>
#include <exception>
#include <thread>

#include "state.h"
#include "hook/hook.h"
#include "display.h"

// Spotify libcef version @ 95.7.12+g99c4ac0+chromium-95.0.4638.54
// https://cef-builds.spotifycdn.com/index.html#windows32:95.7.12+g99c4ac0

State* g_State = new State();
Hook* g_Hook = new Hook();
int MessageBoxVA(const char* fmt, ...) {
  char buf[4096];
  va_list argptr;
      va_start(argptr, fmt);
  vsnprintf(buf, sizeof(buf), fmt, argptr);
      va_end(argptr);
  return MessageBoxA(nullptr, buf, "customspotify/hook", MB_OK);
}

DWORD WINAPI OnDllAttach(LPVOID lpBase) {
  try {
    if (strstr(GetCommandLineA(), "type=renderer") != nullptr) {
      g_State->bIsRenderer = true;
      g_State->bIsMain = false;
    }
    // timestamp of our injection
    g_State->llTimestamp = std::chrono::duration_cast<std::chrono::seconds>
        (std::chrono::system_clock::now().time_since_epoch()).count();
    GetModuleFileNameW(g_State->hBase, g_State->path, _countof(g_State->path));
    g_Hook->Startup(g_State->bIsRenderer);
    // hopefully we don't need to keep our thread running lol
  } catch (std::exception& ex) {
    if (g_State->bIsRenderer) {
      // we can't show message boxes from the renderer (invalid mem read inside gdi32.CreateFontIndirect)
      // TODO: display error somehow
    } else {
      MessageBoxVA("Exception caught while loading: %s", ex.what());
    }
  }
  return 0;
}

BOOL WINAPI DllMain(
    _In_ HINSTANCE hinstDLL,
    _In_ DWORD fdwReason,
    _In_opt_ LPVOID lpvReserved) {
  if (fdwReason == DLL_PROCESS_ATTACH) {
    DisableThreadLibraryCalls(hinstDLL);
    g_State->hBase = hinstDLL;

    CreateThread(nullptr, 0, OnDllAttach, hinstDLL, 0, nullptr);
  }
  return TRUE;
}