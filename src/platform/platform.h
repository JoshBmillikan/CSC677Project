//
// Created by josh on 10/1/24.
//

#pragma once

class Socket {
public:
    explicit Socket(int protocol);
    Socket();
    ~Socket();
    Socket(const Socket& other) = delete;

    Socket(Socket&& other) noexcept : sock(other.sock) {}

    Socket& operator=(const Socket& other) = delete;

    Socket& operator=(Socket&& other) noexcept
    {
        if (this == &other)
            return *this;
        sock = other.sock;
        return *this;
    }

private:
    int sock;
};
