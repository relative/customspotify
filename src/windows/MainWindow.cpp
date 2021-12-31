//
// Created by relative on 12/18/2021.
//

#include "MainWindow.h"
#include "ui_mainwindow.h"
#include <QScrolLBar>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow) {
  ui->setupUi(this);

}

MainWindow::~MainWindow() noexcept {
  delete ui;
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