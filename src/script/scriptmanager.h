#ifndef CUSTOMSPOTIFY_SCRIPTMANAGER_H
#define CUSTOMSPOTIFY_SCRIPTMANAGER_H

#include <QObject>
#include <QString>
#include <QDir>
#include <vector>
#include "script.h"
#include <map>
#include <string>

#include <efsw/efsw.hpp>

class ScriptManager : public QObject, public efsw::FileWatchListener {
  Q_OBJECT
public:
  ScriptManager();

  std::map<std::string, Script*> scripts;
  std::string directory;
  void handleFileAction( efsw::WatchID watchId, const std::string& dir, const std::string& filename, efsw::Action action, std::string oldFilename ) override;
signals:
  void scriptAdded(const std::string& filename, Script* script);
  void scriptRemoved(const std::string& filename, Script* script);
  void scriptUpdated(const std::string& filename, Script* script);
private:
  efsw::FileWatcher* watcher;
  efsw::WatchID watcherID;
};

extern ScriptManager* g_ScriptManager;

#endif //CUSTOMSPOTIFY_SCRIPTMANAGER_H
