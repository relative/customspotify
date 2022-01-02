//
// Created by relative on 12/18/2021.
//

#include "MainWindow.h"
#include "ui_mainwindow.h"
#include <QScrollBar>
#include <QtDebug>
#include "ScriptWidget.h"
#include "../script/scriptmanager.h"

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
  ui->setupUi(this);

  this->setup_scripts();
  connect(g_ScriptManager, &ScriptManager::scriptAdded, this, &MainWindow::scriptAdded);
  connect(g_ScriptManager, &ScriptManager::scriptRemoved, this, &MainWindow::scriptRemoved);
  connect(g_ScriptManager, &ScriptManager::scriptUpdated, this, &MainWindow::scriptUpdated);
}

MainWindow::~MainWindow() noexcept {
  delete ui;
}

void MainWindow::setup_scripts() {
  for(auto const& [filename, script] : g_ScriptManager->scripts) {
    this->add_script(filename, script);
  }
}
void MainWindow::add_script(const std::string& filename, Script *script) {
  auto listItem = new QListWidgetItem();
  auto scriptItem = new ScriptWidget(this, script);
  listItem->setSizeHint(scriptItem->sizeHint());
  ui->lstScripts->addItem(listItem);
  ui->lstScripts->setItemWidget(listItem, scriptItem);
}
void MainWindow::scriptAdded(const std::string& filename, Script* script) {
  this->add_script(filename, script);
}

void MainWindow::scriptRemoved(const std::string& filename, Script* script) {
  for (int i = 0; i < ui->lstScripts->count(); ++i) {
    auto listItem = ui->lstScripts->item(i);
    if (listItem == nullptr) continue;

    auto scriptItem = dynamic_cast<ScriptWidget*>
        (ui->lstScripts->itemWidget(listItem));
    if (scriptItem == nullptr) continue;
    if (scriptItem->script->filename == filename) {
      ui->lstScripts->removeItemWidget(listItem);
      delete listItem; // dtor or it wont remove
      break;
    }
  }
}
void MainWindow::scriptUpdated(const std::string& filename, Script* script) {
  for (int i = 0; i < ui->lstScripts->count(); ++i) {
    auto listItem = ui->lstScripts->item(i);
    if (listItem == nullptr) continue;

    auto scriptItem = dynamic_cast<ScriptWidget*>
        (ui->lstScripts->itemWidget(listItem));
    if (scriptItem == nullptr) continue;

    if (scriptItem->script->filename == filename) {
      scriptItem->update_data();
      break;
    }
  }
}

void MainWindow::add_log_entry(const char* fmt, ...) {
  char buf[4096];
  va_list argptr;
  va_start(argptr, fmt);
  vsnprintf(buf, sizeof(buf), fmt, argptr);
  va_end(argptr);
  ui->txtLog->append(QString::fromStdString(buf));
  auto scrollBar = ui->txtLog->verticalScrollBar();
  int max = scrollBar->maximum();
  if (scrollBar->value() < max - 30) return;
  scrollBar->setValue(max);
}