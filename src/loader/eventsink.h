#ifndef CUSTOMSPOTIFY_EVENTSINK_H
#define CUSTOMSPOTIFY_EVENTSINK_H

#include "ntdll.h"
#include <comdef.h>
#include <Wbemidl.h>

// https://docs.microsoft.com/en-us/windows/win32/wmisdk/example--receiving-event-notifications-through-wmi-
// COM/WMI is weird
class EventSink : public IWbemObjectSink {
  LONG m_lRef;
  bool bDone;
public:
  EventSink() { m_lRef = 0; }
  ~EventSink() { bDone = true; }

  virtual ULONG STDMETHODCALLTYPE AddRef();
  virtual ULONG STDMETHODCALLTYPE Release();
  virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** ppv);

  virtual HRESULT STDMETHODCALLTYPE Indicate(
      LONG lObjectCount,
      IWbemClassObject __RPC_FAR *__RPC_FAR *apObjArray
  );

  virtual HRESULT STDMETHODCALLTYPE SetStatus(
      /* [in] */ LONG lFlags,
      /* [in] */ HRESULT hResult,
      /* [in] */ BSTR strParam,
      /* [in] */ IWbemClassObject __RPC_FAR *pObjParam
  );
private:
  uint32_t newProcId;
};


#endif //CUSTOMSPOTIFY_EVENTSINK_H
