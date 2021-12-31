//
// Created by relative on 12/20/2021.
//

#ifndef CUSTOMSPOTIFY_LOADER_H
#define CUSTOMSPOTIFY_LOADER_H
#include <QThread>
#include <Windows.h>

class Loader : public QThread {
  Q_OBJECT
  [[noreturn]] void run() override;
  void spotify_process_found(HANDLE hProc, DWORD dwPid, char path[MAX_PATH]);
};

extern Loader* g_Loader;

#endif //CUSTOMSPOTIFY_LOADER_H
