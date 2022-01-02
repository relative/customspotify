#include "script.h"
#include <QFile>
#include <QTextStream>
#include <QRegularExpression>
#include <QtDebug>
#include <nlohmann/json.hpp>
#include <fstream>
#include <sstream>


using json = nlohmann::json;

Script::Script(std::string filename, std::string path) {
  this->filename = filename;
  this->path = path;
}

bool Script::reload() {
  std::ifstream ifs(this->path);
  std::stringstream stream;
  std::string metaLine;
  std::getline(ifs, metaLine);

  stream << ifs.rdbuf();
  this->content = stream.str();

  QRegularExpression re("\\/\\/ ?cspscript ?({.+})",
                        QRegularExpression::CaseInsensitiveOption);
  auto match = re.match(QString::fromStdString(metaLine));
  if (!match.hasMatch()) {
    return this->isValid = false;
  }
  QString metaStr = match.captured(1);
  auto metaJson = json::parse(metaStr.toStdString());
  if (metaJson.contains("name"))
    this->name = QString::fromStdString(metaJson["name"].get<std::string>());
  if (metaJson.contains("author"))
    this->author = QString::fromStdString(metaJson["author"].get<std::string>());
  if (metaJson.contains("ver"))
    this->version = QString::fromStdString(metaJson["ver"].get<std::string>());
  if (metaJson.contains("vid"))
    this->versionId = metaJson["vid"].get<int32_t>();

  return this->isValid = true;
}