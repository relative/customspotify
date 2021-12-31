#include "renderer.h"
#include "../state.h"
/**
 * SetProcessMitigationPolicy hook is functionally identical to UpdateProcThreadAttribute
 */
spmp orig_SetProcessMitigationPolicy;
BOOL __stdcall new_SetProcessMitigationPolicy(
    _In_ PROCESS_MITIGATION_POLICY mitigationPolicy,
    _In_ PVOID lpBuffer,
    _In_ SIZE_T dwLength
) {
  // TODO: Restore requested mitigation policies later
  // TODO: Only ignore on ProcessSignaturePolicy
  // until resolved, this breaks chrome sandboxing and security
  return TRUE;
}

/**
 * SetTokenInformation hook is to prevent renderer proc from
 * de-escalating itself to untrusted mandatory label
 */
sti orig_SetTokenInformation;
BOOL __stdcall new_SetTokenInformation(
    _In_ HANDLE tokenHandle,
    _In_ TOKEN_INFORMATION_CLASS tokenInformationClass,
    _In_ LPVOID tokenInformation,
    _In_ DWORD tokenInformationLength
) {
  // TODO: Restore requested mandatory label later (need IPC for file operations etc.)
  // TODO: Only ignore when attempting to change mandatory label
  // until resolved, this breaks chrome sandboxing and security
  return TRUE;
}

csu8tu16 orig_cef_string_utf8_to_utf16;

// v8context will be undefined or invalid (wrong context) if we don't run it when _getSpotifyModule is being defined
// on the window
bool go() {
  auto get_current_context_address = GetProcAddress(g_State->mHandleCEF,
                                                    "cef_v8context_get_current_context");
  auto get_current_context = reinterpret_cast<cv8gcc>(get_current_context_address);
  /*auto utf8_to_utf16_address = GetProcAddress(g_State->mHandleCEF,
                                              "cef_string_utf8_to_utf16");
  auto utf8_to_utf16 = reinterpret_cast<csu8tu16>(utf8_to_utf16_address);*/

  auto ctx = get_current_context();

  //pipe_write("v8context @ %08x, *(U8->U16) @ %08x", ctx, utf8_to_utf16_address);


  int start_line = 1;

  char strCode[] = "alert(1);";
  cef_string_t cfCode = {};
  orig_cef_string_utf8_to_utf16(strCode, strlen(strCode), &cfCode);
  char strUrl[] = "B";
  cef_string_t cfUrl = {};
  orig_cef_string_utf8_to_utf16(strUrl, strlen(strUrl), &cfUrl);

  _cef_v8value_t* myRetVal = nullptr;
  _cef_v8exception_t* myv8Exception = nullptr;
  ctx->eval(ctx, &cfCode, &cfUrl, start_line, &myRetVal, &myv8Exception);

  return true;
}

int __cdecl new_cef_string_utf8_to_utf16(const char* src,
                                         size_t src_len,
                                         cef_string_utf16_t* output) {
  if (strstr(src, "_getSpotifyModule") != nullptr) {
    static bool r = false;
    if (!r) r = go();
  }
  return orig_cef_string_utf8_to_utf16(src, src_len, output);
}