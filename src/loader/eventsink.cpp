#include "eventsink.h"
#include <QtDebug>
#include "loader.h"

ULONG EventSink::AddRef() {
  return InterlockedIncrement(&m_lRef);
}

ULONG EventSink::Release() {
  LONG lRef = InterlockedDecrement(&m_lRef);
  if(lRef == 0)
    delete this;
  return lRef;
}

HRESULT EventSink::QueryInterface(REFIID riid, void** ppv) {
  if (riid == IID_IUnknown || riid == IID_IWbemObjectSink) {
    *ppv = (IWbemObjectSink *) this;
    AddRef();
    return WBEM_S_NO_ERROR;
  }
  else return E_NOINTERFACE;
}

HRESULT EventSink::Indicate(long lObjectCount, IWbemClassObject **apObjArray) {
  HRESULT hr;

  _variant_t var;
  _variant_t varT;
  IWbemClassObject* apObj;
  for (int i = 0; i < lObjectCount; i++) {
    apObj = apObjArray[i];
    hr = apObj->Get(_bstr_t(L"TargetInstance"), 0, &var, nullptr, nullptr);
    if (FAILED(hr)) {
      continue;
    }
    IUnknown* proc = var;

    hr = proc->QueryInterface(IID_IWbemClassObject, reinterpret_cast<void**>(&apObj));
    if (FAILED(hr)) {
      VariantClear(&var);
      continue;
    }
    uint32_t procId;
    BSTR cl;
    BSTR ep;

    apObj->Get(_bstr_t(L"ProcessId"), 0, &varT, nullptr, nullptr);
    procId = varT.uintVal;
    VariantClear(&varT);

    apObj->Get(_bstr_t(L"CommandLine"), 0, &varT, nullptr, nullptr);
    cl = varT.bstrVal;
    VariantClear(&varT);

    apObj->Get(_bstr_t(L"ExecutablePath"), 0, &varT, nullptr, nullptr);
    ep = varT.bstrVal;
    VariantClear(&varT);

    char* chCmdLine = _com_util::ConvertBSTRToString(cl);
    char* chExePath = _com_util::ConvertBSTRToString(ep);

    if (procId != this->newProcId && strstr(chCmdLine, "--type=") == nullptr) {
      // correct process
      HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
                  false,
                  procId);
      if (hProc == nullptr) {
        delete[] chCmdLine;
        delete[] chExePath;
        proc->Release();
        VariantClear(&var);
        qDebug() << "Failed to open process with PQLI|PT" << Qt::hex << GetLastError();
        continue;
      }

      this->newProcId = g_Loader->spotify_process_found(hProc, procId, chExePath);
      if (this->newProcId == 0) {
        qDebug() << "inj failed";
      }
    }

    delete[] chCmdLine; // ConvertBSTRToString allocs new string
    delete[] chExePath;

    proc->Release();
    VariantClear(&var);
  }

  return WBEM_S_NO_ERROR;
}

HRESULT EventSink::SetStatus(LONG lFlags, HRESULT hResult, BSTR strParam, IWbemClassObject __RPC_FAR *pObjParam) {
  if(lFlags == WBEM_STATUS_COMPLETE) {
    printf("Call complete. hResult = 0x%X\n", hResult);
  } else if(lFlags == WBEM_STATUS_PROGRESS) {
    printf("Call in progress.\n");
  }

  return WBEM_S_NO_ERROR;
}
