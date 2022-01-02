#include "scriptmanager.h"
#include <filesystem>
#include <algorithm>
#include "../windows/MainWindow.h"

namespace fs = std::filesystem;

ScriptManager::ScriptManager() {
  auto p = std::filesystem::current_path() / "scripts";

  this->watcher = new efsw::FileWatcher(true);
  this->watcherID = watcher->addWatch(p.string(), this, true);
  watcher->watch();

  Script* script;
  for(auto const& dirent : fs::directory_iterator(p)) {
    auto entPath = dirent.path();
    auto filename = entPath.filename().string();
    script = new Script(filename, entPath.string());
    script->reload();
    scripts.insert(std::pair(filename, script));
    emit scriptAdded(filename, script);
  }
}

void ScriptManager::handleFileAction(efsw::WatchID watchId, const std::string &dir, const std::string &filename,
                                     efsw::Action action, std::string oldFilename) {

  auto fullPath = fs::path(dir) / filename;
  if (action != efsw::Actions::Delete && !fs::is_regular_file(fullPath)) return;

  auto iter = scripts.find(filename);
  bool scriptInMap = iter != scripts.end();
  Script* script;
  switch (action) {
    case efsw::Actions::Add:
      script = new Script(filename, fullPath.string());
      script->reload();
      scripts.insert(std::pair(filename, script));
      emit scriptAdded(filename, script);
      break;
    case efsw::Actions::Delete:
      emit scriptRemoved(filename, iter->second);
      scripts.erase(iter);
      break;
    case efsw::Actions::Modified:
      // Script modified
      if (scriptInMap) {
        script = iter->second;
        script->reload();
        emit scriptUpdated(filename, script);
      } else {
        // script doesn't exist in map?
        script = new Script(filename, fullPath.string());
        script->reload();
        scripts.insert(std::pair(filename, script));
        emit scriptAdded(filename, script);
      }
      break;
    case efsw::Actions::Moved:
      // Script moved... (oldFilename)
      if (scripts.find(oldFilename) == scripts.end()) break;
      auto nh = scripts.extract(oldFilename);
      nh.key() = filename;
      scripts.insert(std::move(nh));
      script = scripts.find(filename)->second;
      emit scriptRemoved(oldFilename, script);
      emit scriptAdded(filename, script);
      // script moved signal?
      g_MainWindow->add_log_entry("Script moved: %s => %s", oldFilename.c_str(), filename.c_str());
      break;
  }
}



