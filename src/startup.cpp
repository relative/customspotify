#include "startup.h"
#include <filesystem>

namespace fs = std::filesystem;

void startup_create_directories() {
  fs::create_directory("themes/");
  fs::create_directory("extensions/");
  fs::create_directory("scripts/");
}