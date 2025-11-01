#include <cstddef>
#include <print>
#include <print>
#include <sys/socket.h>


import socketcpp;


int main()
{
    auto ip_addr = socketcpp::IpAddress::v4_any(3456).value();
    auto server_socket = socketcpp::TcpListener::create(
        ip_addr).value();

    std::println("Listening on : {}:{}", ip_addr.address_string(), ip_addr.port());
    auto [client_socket, addrs] = server_socket.accept().value();

    std::println("Connection from: {}:{}", addrs.address_string(), addrs.port());
    std::byte buffer[1024]{};

    auto res = client_socket.recv(buffer).value();
    
    auto recv_data = std::string_view(reinterpret_cast<char *>(buffer), res);
    std::println("Received : {}", recv_data);
    
}