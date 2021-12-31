#include <QApplication>
#include <QStyleFactory>
#include <QSettings>
#include "windows/MainWindow.h"
#include "loader/loader.h"

Loader* g_Loader = new Loader();
MainWindow* g_MainWindow;
namespace {
  void init_theme() {
    qApp->setStyle(QStyleFactory::create("fusion"));
#ifdef Q_OS_WIN
    QSettings settings("HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",QSettings::NativeFormat);
    if(settings.value("AppsUseLightTheme")==0){
      QPalette darkPalette;
      QColor darkColor = QColor(45,45,45);
      QColor disabledColor = QColor(127,127,127);
      darkPalette.setColor(QPalette::Window, darkColor);
      darkPalette.setColor(QPalette::WindowText, Qt::white);
      darkPalette.setColor(QPalette::Base, QColor(18,18,18));
      darkPalette.setColor(QPalette::AlternateBase, darkColor);
      darkPalette.setColor(QPalette::ToolTipBase, Qt::white);
      darkPalette.setColor(QPalette::ToolTipText, Qt::white);
      darkPalette.setColor(QPalette::Text, Qt::white);
      darkPalette.setColor(QPalette::Disabled, QPalette::Text, disabledColor);
      darkPalette.setColor(QPalette::Button, darkColor);
      darkPalette.setColor(QPalette::ButtonText, Qt::white);
      darkPalette.setColor(QPalette::Disabled, QPalette::ButtonText, disabledColor);
      darkPalette.setColor(QPalette::BrightText, Qt::red);
      darkPalette.setColor(QPalette::Link, QColor(42, 130, 218));

      darkPalette.setColor(QPalette::Highlight, QColor(42, 130, 218));
      darkPalette.setColor(QPalette::HighlightedText, Qt::black);
      darkPalette.setColor(QPalette::Disabled, QPalette::HighlightedText, disabledColor);

      qApp->setPalette(darkPalette);

      qApp->setStyleSheet("QToolTip { color: #ffffff; background-color: #2a82da; border: 1px solid white; }");
    }
#endif

  }
}

int main(int argc, char** argv) {
  QApplication app(argc, argv);

  init_theme();

  g_MainWindow = new MainWindow();
  g_MainWindow->show();

  /*if (false) {
    HANDLE hToken, hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (OpenProcessToken(hProc, TOKEN_ALL_ACCESS, &hToken) ==0){
      return 0;
    }
    LUID hLuid;
    if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &hLuid) == 0){
      return 0;
    }
    TOKEN_PRIVILEGES token_privileges;
    token_privileges.PrivilegeCount = 1;
    token_privileges.Privileges[0].Luid = hLuid;
    token_privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if(AdjustTokenPrivileges(hToken, FALSE, &token_privileges, 0, NULL,
                             NULL) == 0) {
      return 0;
    }
    CloseHandle(hToken);
    CloseHandle(hProc);
  }*/

  g_Loader->start();

  return app.exec();
}
