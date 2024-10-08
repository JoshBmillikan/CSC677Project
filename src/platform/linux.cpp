//
// Created by josh on 10/1/24.
//
#include <cstring>
#include <format>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <unistd.h>
#include "platform.h"

Socket::Socket() : Socket(ETH_P_IP) {}

Socket::Socket(const int protocol)
{
    sock = socket(AF_INET, SOCK_RAW, protocol);
    if (sock < 0)
        throw std::runtime_error(std::format("Failed to create raw socket: {}", strerror(errno)));
}

Socket::~Socket()
{
    close(sock);
}
