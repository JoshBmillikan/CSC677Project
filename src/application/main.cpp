#include <QApplication>
#include <pcap/pcap.h>

#include "window.h"

int main(int argc, char *argv[]) {
    pcap_init(PCAP_CHAR_ENC_UTF_8, nullptr);
    QApplication a(argc, argv);
    Window w;
    w.show();
    return QApplication::exec();
}
