#ifndef CUSTOMSPOTIFY_RENDERER_H
#define CUSTOMSPOTIFY_RENDERER_H
#include "../ntdll.h"
#include "../include/capi/cef_app_capi.h"
#include "../include/capi/cef_v8_capi.h"
#include "../include/cef_v8.h"
// SetProcessMitigationPolicy
typedef BOOL(__stdcall* spmp)(
    _In_ PROCESS_MITIGATION_POLICY,
    _In_ PVOID,
    _In_ SIZE_T
);
extern spmp orig_SetProcessMitigationPolicy;
BOOL __stdcall new_SetProcessMitigationPolicy(
    _In_ PROCESS_MITIGATION_POLICY,
    _In_ PVOID,
    _In_ SIZE_T
);

// SetTokenInformation
typedef BOOL(__stdcall* sti)(
    _In_ HANDLE,
    _In_ TOKEN_INFORMATION_CLASS,
    _In_ LPVOID,
    _In_ DWORD
);
extern sti orig_SetTokenInformation;
BOOL __stdcall new_SetTokenInformation(
    _In_ HANDLE,
    _In_ TOKEN_INFORMATION_CLASS,
    _In_ LPVOID,
    _In_ DWORD
);

typedef cef_v8context_t*(__cdecl* cv8gcc)();
typedef int(__cdecl* csu8tu16)(const char*, size_t, cef_string_utf16_t*);
extern csu8tu16 orig_cef_string_utf8_to_utf16;
int __cdecl new_cef_string_utf8_to_utf16(const char*,
                                         size_t,
                                         cef_string_utf16_t*);

#endif //CUSTOMSPOTIFY_RENDERER_H
