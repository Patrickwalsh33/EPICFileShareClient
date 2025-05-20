#include <QApplication>
#include <QPushButton>

int main(int argc, char *argv[]) {
    QApplication a(argc, argv);
    QPushButton button("Hello world! Checking new branch approval", nullptr);
    button.resize(200, 100);
    button.show();
    return QApplication::exec();
}
