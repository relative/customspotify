#ifndef CUSTOMSPOTIFY_SCRIPTWIDGET_H
#define CUSTOMSPOTIFY_SCRIPTWIDGET_H

#include <QWidget>

#include <QMainWindow>
#include <string>

QT_BEGIN_NAMESPACE
namespace Ui { class ScriptWidget; }
QT_END_NAMESPACE

class Script;
class ScriptWidget : public QWidget {
Q_OBJECT
public:
  ScriptWidget(QWidget* parent = nullptr, const Script* script = nullptr);
  ~ScriptWidget();

  void update_data();
  const Script* script;
private:
  Ui::ScriptWidget *ui;
};

#endif //CUSTOMSPOTIFY_SCRIPTWIDGET_H
