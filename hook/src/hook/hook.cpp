#include "hook.h"
#include <stdexcept>
#include <MinHook.h>

#include "../ntdll.h"
#include "../state.h"
#include "../display.h"

#include "renderer.h"
#include "browser.h"

void Hook::Startup(bool bIsRenderer) {
  if (MH_Initialize() != MH_OK)
    throw std::runtime_error("MH_Initialize() failed");

  if ((g_State->mHandleKernel32 = LoadLibraryA("kernel32.dll")) == nullptr)
    throw std::runtime_error("Could not open handle to 'kernel32.dll'");
  if ((g_State->mHandleAdvapi32 = LoadLibraryA("Advapi32.dll")) == nullptr)
    throw std::runtime_error("Could not open handle to 'Advapi32.dll'");
  if ((g_State->mHandleCEF = LoadLibraryA("libcef.dll")) == nullptr)
    throw std::runtime_error("Could not open handle to 'libcef.dll'");

  if (bIsRenderer) {
    // We should only hook SetProcessMitigationPolicy and SetTokenInformation here (in renderer subproc)

    const auto setprocessmitigationpolicy_address = reinterpret_cast<void*>
        (GetProcAddress(g_State->mHandleKernel32, "SetProcessMitigationPolicy"));
    if (MH_CreateHook(
        setprocessmitigationpolicy_address,
        reinterpret_cast<void*>(&new_SetProcessMitigationPolicy),
        reinterpret_cast<void**>(&orig_SetProcessMitigationPolicy)) != MH_OK)
      throw std::runtime_error("MH_CreateHook(SetProcessMitigationPolicy) failed");

    const auto settokeninformation_address = reinterpret_cast<void*>
        (GetProcAddress(g_State->mHandleAdvapi32, "SetTokenInformation"));
    if (MH_CreateHook(
        settokeninformation_address,
        reinterpret_cast<void*>(&new_SetTokenInformation),
        reinterpret_cast<void**>(&orig_SetTokenInformation)) != MH_OK)
      throw std::runtime_error("MH_CreateHook(SetTokenInformation) failed");


    const auto cef_string_utf8_to_utf16_address = reinterpret_cast<void*>
        (GetProcAddress(g_State->mHandleCEF, "cef_string_utf8_to_utf16"));
    if (MH_CreateHook(cef_string_utf8_to_utf16_address,
                      reinterpret_cast<void*>(&new_cef_string_utf8_to_utf16),
                      reinterpret_cast<void**>(&orig_cef_string_utf8_to_utf16)) != MH_OK)
      throw std::runtime_error("MH_CreateHook(cef_string_utf8_to_utf16) failed");
    
    // hook cef_v8value_create_string(cef_string_t*) if you'd like to hook cosmos API responses (in json)
  } else {
    // We should only hook CreateProcessAsUserW and UpdateProcThreadAttribute here (in browser proc)

    const auto createprocessasuserw_address = reinterpret_cast<void*>(
        GetProcAddress(g_State->mHandleAdvapi32, "CreateProcessAsUserW"));
    if (MH_CreateHook(
        createprocessasuserw_address,
        reinterpret_cast<void*>(&new_CreateProcessAsUserW),
        reinterpret_cast<void**>(&orig_CreateProcessAsUserW)) != MH_OK)
      throw std::runtime_error("MH_CreateHook(CreateProcessAsUserW) failed");

    const auto updateprocthreadattribute_address = reinterpret_cast<void*>
        (GetProcAddress(g_State->mHandleKernel32, "UpdateProcThreadAttribute"));
    if (MH_CreateHook(
        updateprocthreadattribute_address,
        reinterpret_cast<void*>(&new_UpdateProcThreadAttribute),
        reinterpret_cast<void**>(&orig_UpdateProcThreadAttribute)) != MH_OK)
      throw std::runtime_error("MH_CreateHook(UpdateProcThreadAttribute) failed");

    const auto cef_initialize_address = reinterpret_cast<void*>
        (GetProcAddress(g_State->mHandleCEF,"cef_initialize"));
    if (MH_CreateHook(
        cef_initialize_address,
        reinterpret_cast<void*>(&new_cef_initialize),
        reinterpret_cast<void**>(&orig_cef_initialize)) != MH_OK)
      throw std::runtime_error("MH_CreateHook(cef_initialize) failed");
  }

  if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
    throw std::runtime_error("MH_EnableHook(MH_ALL_HOOKS) failed");
}