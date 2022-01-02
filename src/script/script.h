#ifndef CUSTOMSPOTIFY_SCRIPT_H
#define CUSTOMSPOTIFY_SCRIPT_H
#include <QString>

class Script {
public:
  explicit Script(std::string fileName, std::string path);
public:
  /**
   * Reload script content + meta from disk
   * @return validity of metadata (isValid)
   */
  bool reload();
  bool isValid = false;
  QString name = "Not defined";
  QString author = "Not defined";
  QString version = "Not defined";
  int32_t versionId = 10101010;
  std::string filename;
private:
  std::string content;
  std::string path;
};


#endif //CUSTOMSPOTIFY_SCRIPT_H
