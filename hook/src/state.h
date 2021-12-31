#ifndef HOOK_STATE_H
#define HOOK_STATE_H

#include "ntdll.h" // #include <Windows.h>

class State {
public:
  State()                   = default;

  HINSTANCE hBase	          = nullptr;
  wchar_t   path[260]       = L"";

  // == Spotify
  bool      bIsMain         = true;
  bool      bIsRenderer     = false;

  long long llTimestamp     = 0;

  // == Module handles
  HMODULE   mHandleCEF	    = nullptr;			// libcef.dll
  HMODULE   mHandleKernel32 = nullptr;      // kernel32.dll
  HMODULE   mHandleAdvapi32 = nullptr;      // advapi32.dll
};

extern State* g_State;

#endif //HOOK_STATE_H
