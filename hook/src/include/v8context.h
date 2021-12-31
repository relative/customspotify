//
// Created by relative on 12/19/2021.
//

#ifndef HOOK_V8CONTEXT_H
#define HOOK_V8CONTEXT_H

class cef_v8_context {
public:
  virtual void* GetTaskRunner() = 0;
  virtual bool IsValid() = 0;
  virtual void* GetBrowser() = 0;
  virtual void* GetFrame() = 0;
  virtual void* GetGlobal() = 0;
  virtual bool Enter() = 0;
  virtual bool Exit() = 0;
  virtual bool IsSame(void* that) = 0;
  virtual bool Eval(const void*& code,
                    const void*& script_url,
                    int start_line,
                    void*& retval,
                    void*& exception) = 0;

};

#endif //HOOK_V8CONTEXT_H
