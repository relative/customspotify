//
// Created by relative on 12/20/2021.
//

#ifndef CUSTOMSPOTIFY_LOADER_H
#define CUSTOMSPOTIFY_LOADER_H
#include <QThread>
#include "ntdll.h" // #include <Windows.h>

class Loader : public QThread {
  Q_OBJECT
public:
  explicit Loader();
  [[noreturn]] void run() override;

  /// returns new process ID
  uint32_t spotify_process_found(HANDLE hProc, DWORD dwPid, char path[MAX_PATH]);
private:
  bool bSubscription = false;
};

extern Loader* g_Loader;

#endif //CUSTOMSPOTIFY_LOADER_H
