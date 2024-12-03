//
// Created by josh on 11/27/24.
//

// You may need to build the project (run Qt uic code generator) to get "ui_Window.h" resolved

#include "window.h"

#include <iostream>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>
#include <qmessagebox.h>
#include "ui_window.h"

Window::Window(QWidget* parent) : QWidget(parent), ui(new Ui::Window)
{
    ui->setupUi(this);
    pcap_if_t* interfaces;
    char errBuff[PCAP_ERRBUF_SIZE];
    if (pcap_findalldevs(&interfaces, errBuff) != 0)
        std::cerr << "Failed to list interfaces: " << errBuff << std::endl;
    for (const pcap_if_t* d = interfaces; d != nullptr; d = d->next) {
        ui->comboBox->addItem(d->name);
    }

    pcap_freealldevs(interfaces);
    connect(ui->comboBox, SIGNAL(currentIndexChanged(int)), this, SLOT(interfaceSelected(int)));
    connect(ui->captureButton, SIGNAL(clicked()), this, SLOT(capturePacketButtonClicked()));
    connect(ui->packetList, SIGNAL(currentRowChanged(int)), this, SLOT(packetSelected(int)));
}

Window::~Window()
{
    delete ui;
}

static QString getIpString(const in_addr_t* addr)
{
    char str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, addr, str, INET_ADDRSTRLEN);
    return QString(str);
}

void Window::capturePackets(const int count)
{
    packets.clear();
    packets.reserve(count);
    int result = pcap_dispatch(
        pcap,
        count,
        [](u_char* arg, const pcap_pkthdr* pktHdr, const u_char* packet) {
            const auto self = reinterpret_cast<Window*>(arg);
            self->addPacket(pktHdr, packet);
        },
        reinterpret_cast<u_char*>(this)
    );
    if (result > 0) {
        ui->packetList->unsetCursor();
        ui->packetList->clear();
        ui->packetFrame->setEnabled(true);
        int i = 1;
        for (auto& [packet, time] : packets) {
            const auto header = reinterpret_cast<ip*>(packet.data() + IP_HEADER_OFFSET);
            QString s = QString::number(i);
            s += ": ";
            s += getIpString(&header->ip_src.s_addr);
            ui->packetList->addItem(s);
            i++;
        }
    }
}

void Window::addPacket(const pcap_pkthdr* pktHdr, const u_char* packet)
{
    auto& [data, timestamp] = packets.emplace_back();
    data.resize(pktHdr->len);
    memcpy(data.data(), packet, pktHdr->len);
    timestamp = pktHdr->ts.tv_sec;
}

void Window::interfaceSelected(const int index)
{
    if (index == 0)
        return;
    const auto name = ui->comboBox->itemText(index).toStdString();
    char errBuff[PCAP_ERRBUF_SIZE];
    pcap = pcap_open_live(name.c_str(), 65535, 1, 30 * 1000, errBuff);
    if (pcap == nullptr) {
        QMessageBox::critical(this, tr("CSC 677 project"), tr("Failed to open interface: ") + errBuff);
    }

    bpf_u_int32 netmask, netP;
    pcap_lookupnet(name.c_str(), &netP, &netmask, errBuff);
    bpf_program program{};
    pcap_compile(pcap, &program, "ip", 1, netmask);
    pcap_setfilter(pcap, &program);
}

void Window::capturePacketButtonClicked()
{
    if (pcap) {
        const int count = ui->packetCountSpinBox->value();
        capturePackets(count);
    } else
        QMessageBox::information(this, tr("CSC 677 project"), tr("Please select an interface"));
}

/// Returns string representation of the protocol number
static QString getProtocolString(const uint8_t protocol)
{
    switch (protocol) {
        case IPPROTO_ICMP: return "ICMP";
        case IPPROTO_IGMP: return "IGMP";
        case IPPROTO_TCP: return "TCP";
        case IPPROTO_UDP: return "UDP";
        case IPPROTO_ENCAP: return "ENCAP";
        case IPPROTO_SCTP: return "SCTP";
        default: return "Unknown";
    }
}

void Window::packetSelected(const int index)
{
    if (index < 0)
        return;
    auto& [packet, timestamp] = packets.at(index);
    const auto header = reinterpret_cast<ip*>(packet.data() + IP_HEADER_OFFSET);

    //display header fields
    ui->ipLabel->setText(QString::number(header->ip_v));
    ui->destinationLabel->setText(getIpString(&header->ip_dst.s_addr));
    ui->sourceLabel->setText(getIpString(&header->ip_src.s_addr));
    ui->sizeLabel->setText(QString::number(packet.size()));
    ui->timestampLabel->setText(QString::fromStdString(ctime(&timestamp)));
    ui->headerLengthLabel->setText(QString::number(header->ip_hl * 4));
    ui->idLabel->setText(QString::number(header->ip_id));
    ui->fragmentLabel->setText(QString::number(header->ip_off & IP_OFFMASK));
    ui->ttlLabel->setText(QString::number(header->ip_ttl));
    ui->protocolLabel->setText(getProtocolString(header->ip_p));
    ui->checksumLabel->setText(QString::number(header->ip_sum));
    QString flags = "None Set";
    if (header->ip_off & IP_DF)
        flags = " DF";
    if (header->ip_off & IP_MF)
        flags += " MF";
    ui->flagsLabel->setText(flags);

    // Display packet bytes in hex
    int i = 0;
    const auto table = ui->packetTable;
    table->setRowCount(0);
    table->insertRow(table->rowCount());
    table->setColumnCount(10);
    for (const uint8_t byte : packet) {
        char buf[4];
        sprintf(buf, "%02X", byte);
        auto str = QString::fromStdString(buf);
        table->setColumnWidth(i, 5);
        table->setItem(table->rowCount() - 1, i++, new QTableWidgetItem(str));
        if (i >= 10) {
            table->insertRow(table->rowCount());
            i = 0;
        }
    }
    table->resizeColumnsToContents();
    table->resizeRowsToContents();
}
