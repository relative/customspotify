//
// Created by relative on 12/18/2021.
//

#ifndef CUSTOMSPOTIFY_MAINWINDOW_H
#define CUSTOMSPOTIFY_MAINWINDOW_H

#include <QMainWindow>
#include <string>
#include "../script/script.h"

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
  Q_OBJECT
public:
  MainWindow(QWidget *parent = nullptr);
  ~MainWindow();

  void setup_scripts();
  void add_script(const std::string& filename, Script* script);
  void add_log_entry(const char* fmt, ...);
public slots:
  void scriptAdded(const std::string& filename, Script* script);
  void scriptRemoved(const std::string& filename, Script* script);
  void scriptUpdated(const std::string& filename, Script* script);
  void openScriptsFolder();
private:
  Ui::MainWindow *ui;
};

extern MainWindow* g_MainWindow; // gross

#endif //CUSTOMSPOTIFY_MAINWINDOW_H
