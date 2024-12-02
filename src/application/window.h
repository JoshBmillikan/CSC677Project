//
// Created by josh on 11/27/24.
//

#pragma once
#include <QWidget>
#include <pcap/pcap.h>


QT_BEGIN_NAMESPACE

namespace Ui {
class Window;
}

QT_END_NAMESPACE

class Window : public QWidget {
    Q_OBJECT

public:
    explicit Window(QWidget* parent = nullptr);
    ~Window() override;

private:
    static constexpr int IP_HEADER_OFFSET = 14;
    Ui::Window* ui;
    pcap_t* pcap = nullptr;
    std::vector<std::tuple<std::vector<uint8_t>, time_t>> packets;

    void capturePackets(int count);
    void addPacket(const pcap_pkthdr* pktHdr, const u_char* packet);

private slots:
    void interfaceSelected(int index);
    void capturePacketButtonClicked();
    void packetSelected(int index);
};
