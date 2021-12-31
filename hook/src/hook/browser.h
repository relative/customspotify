#ifndef CUSTOMSPOTIFY_BROWSER_H
#define CUSTOMSPOTIFY_BROWSER_H

#include "../ntdll.h"
#include "../include/capi/cef_app_capi.h"

// CreateProcessAsUserW
typedef BOOL(__stdcall* cpauw)(
    _In_opt_ HANDLE,
    _In_opt_ LPCWSTR,
    _Inout_opt_ LPWSTR,
    _In_opt_ LPSECURITY_ATTRIBUTES,
    _In_opt_ LPSECURITY_ATTRIBUTES,
    _In_ BOOL,
    _In_ DWORD,
    _In_opt_ LPVOID,
    _In_opt_ LPCWSTR,
    _In_ LPSTARTUPINFOEXW,
    _Out_ LPPROCESS_INFORMATION
);
extern cpauw orig_CreateProcessAsUserW;
BOOL __stdcall new_CreateProcessAsUserW(
    _In_opt_ HANDLE,
    _In_opt_ LPCWSTR,
    _Inout_opt_ LPWSTR,
    _In_opt_ LPSECURITY_ATTRIBUTES,
    _In_opt_ LPSECURITY_ATTRIBUTES,
    _In_ BOOL,
    _In_ DWORD,
    _In_opt_ LPVOID,
    _In_opt_ LPCWSTR,
    _In_ LPSTARTUPINFOEXW,
    _Out_ LPPROCESS_INFORMATION
);

// UpdateProcThreadAttribute
typedef BOOL(__stdcall* upta)(
    _Inout_ LPPROC_THREAD_ATTRIBUTE_LIST,
    _In_ DWORD,
    _In_ DWORD_PTR,
    _In_ PVOID,
    _In_ SIZE_T,
    _Out_opt_ PVOID,
    _In_opt_ PSIZE_T
);
extern upta orig_UpdateProcThreadAttribute;
BOOL __stdcall new_UpdateProcThreadAttribute(
    _Inout_ LPPROC_THREAD_ATTRIBUTE_LIST,
    _In_ DWORD,
    _In_ DWORD_PTR,
    _In_ PVOID,
    _In_ SIZE_T,
    _Out_opt_ PVOID,
    _In_opt_ PSIZE_T
);

typedef int(__cdecl* ci)(const struct _cef_main_args_t*,
                         const struct _cef_settings_t*,
                         cef_app_t*,
                         void*);
extern ci orig_cef_initialize;
int __cdecl new_cef_initialize(const struct _cef_main_args_t*,
                               const struct _cef_settings_t*,
                               cef_app_t*,
                               void*);

#endif //CUSTOMSPOTIFY_BROWSER_H
