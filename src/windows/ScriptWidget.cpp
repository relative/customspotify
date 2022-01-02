#include "ScriptWidget.h"
#include "ui_scriptwidget.h"
#include "../script/script.h"

ScriptWidget::ScriptWidget(QWidget *parent, const Script* script) : QWidget(parent), ui(new Ui::ScriptWidget) {
  ui->setupUi(this);
  this->script = script;
  this->update_data();
}

void ScriptWidget::update_data() {
  ui->lblName->setText(this->script->name);
  ui->lblAuthor->setText(this->script->author);
  ui->lblVersion->setText(this->script->version);

  ui->chkEnable->setDisabled(!this->script->isValid);
  if (!this->script->isValid) {
    ui->chkEnable->setToolTip("Script is invalid");
  } else if (ui->chkEnable->isChecked()) {
    ui->chkEnable->setToolTip("Disable script");
  } else {
    ui->chkEnable->setToolTip("Enable script");
  }
}

ScriptWidget::~ScriptWidget() noexcept {
  delete ui;
}
