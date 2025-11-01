module;
#include <cstdlib>
#include <cstddef>
#include <type_traits>
#include <utility>
#include <system_error>
#include <string>
#include <string_view>
#include <cstdint>
#include <errno.h>
#include <sys/socket.h>
#include <expected>
#include <unistd.h>
#include <variant>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cstring>
#include <cassert>
#include <span>

export module socketcpp;


namespace socketcpp {
    template<typename... Ts>
    struct overloaded: Ts... {using Ts::operator()...; };

    auto system_error() {
        return std::unexpected(std::error_code{errno, std::system_category()});
    }


    export enum class AddressFamily : int 
    {
        Ipv4 = AF_INET,
        Ipv6 = AF_INET6,
        Unspec = AF_UNSPEC
    };

    export enum class SockType : int
    {
        Stream = SOCK_STREAM,
        Datagram = SOCK_DGRAM,
    };

    export class IpAddress
    {
        template<typename F1, typename F2>
        auto do_visit(F1&& Fv4, F2&& Fv6) const {
            return std::visit([&](auto &&e) {
                using T = std::decay_t<decltype(e)>;
                if constexpr(std::is_same_v<T, sockaddr_in>) {
                    return Fv4(std::forward<decltype(e)>(e));
                } else {
                    return Fv6(std::forward<decltype(e)>(e));
                }
            }, m_addr);
        }

        struct private_token{};
    
    
    public:
        // To Make sure only v4 and v6 static functions can call this public constructor
        IpAddress(private_token, const sockaddr_in& s) : m_addr(s) {}
        IpAddress(private_token, const sockaddr_in6& s) : m_addr(s) {}

        auto family() const noexcept -> AddressFamily {
            return do_visit(
                [](const sockaddr_in& e) {return AddressFamily::Ipv4;},
                [](const sockaddr_in6& e) {return AddressFamily::Ipv6;}
            );
        }

        auto address_string() const noexcept -> std::string {
            return do_visit(
                [](const sockaddr_in& e) -> std::string  { 
                    // Create an address string on heap and return as managed string
                    std::string addrs;

                    addrs.resize_and_overwrite(INET_ADDRSTRLEN, 
                        [&e](char* buf, size_t buf_size) {

                            auto *res = inet_ntop(AF_INET, &e.sin_addr, buf, buf_size);
                            assert(res != nullptr && "inet_ntop failed for v4");

                            return strlen(buf);
                        }
                    );

                    return addrs;

                },
                [](const sockaddr_in6& e) -> std::string {
                    std::string addrs;

                    addrs.resize_and_overwrite(INET6_ADDRSTRLEN, 
                        [&e](char* buf, size_t buf_size) {

                            auto *res = inet_ntop(AF_INET6, &e.sin6_addr, buf, buf_size);
                            assert(res != nullptr && "inet_ntop failed for v6"); 

                            return strlen(buf);
                        }
                    );

                    return addrs;
                }
            ); 
            
        }

        auto port() const noexcept -> int {
            return do_visit(
                [](const sockaddr_in& e) {return ntohs(e.sin_port);},
                [](const sockaddr_in6& e) {return ntohs(e.sin6_port);}
            );
        }

        [[nodiscard]] // Leak a pointer to the internal address. To be used with bind call
        auto get_sockaddr() const noexcept -> std::pair<const sockaddr* , socklen_t> {
            return std::visit([](const auto& sa) -> std::pair<const sockaddr *, socklen_t> {
                return {
                    reinterpret_cast<const sockaddr*>(&sa),
                    static_cast<socklen_t>(sizeof(sa))
                };
            }, m_addr);
        }

        friend bool operator==(const IpAddress& left, const IpAddress& right) {
            return left.family() == right.family() && 
                std::visit(overloaded{
                    [](const sockaddr_in& l, const sockaddr_in& r) -> bool {
                        return l.sin_port == r.sin_port 
                                && l.sin_addr.s_addr == r.sin_addr.s_addr;
                    },
                    [](const sockaddr_in6& l, const sockaddr_in6& r) -> bool {
                        return l.sin6_port == r.sin6_port 
                            && memcmp(&l.sin6_addr, &r.sin6_addr, sizeof(l.sin6_addr));
                    },
                    [](auto &e, auto& r) {
                        return false;
                    }
                }, left.m_addr, right.m_addr);
                
        }
        

        [[nodiscard]]
        static auto v4(std::string_view address, uint16_t port) noexcept
            -> std::expected<IpAddress, std::error_code> {
            sockaddr_in s{};

            s.sin_family = AF_INET;
            s.sin_port = htons(port);

            // string_view are not guaranteed to be null terminated
            char safe_buffer[INET_ADDRSTRLEN];
            memcpy(safe_buffer, address.data(), address.size());
            safe_buffer[address.size()] = '\0';

            auto res = inet_pton(AF_INET, safe_buffer, &s.sin_addr);

            
            if (res == 0) {
                return std::unexpected(std::make_error_code(std::errc::invalid_argument));
            }

            if (res < 0) {
                return system_error();
            }

            return IpAddress{private_token{}, s};
        }

        [[nodiscard]]
        static auto v6(std::string_view address, uint16_t port) noexcept
            -> std::expected<IpAddress, std::error_code> {
            sockaddr_in6 s{};

            s.sin6_family = AF_INET6;
            s.sin6_port = htons(port);

            // string_view are not guaranteed to be null terminated
            char safe_buffer[INET6_ADDRSTRLEN];
            memcpy(safe_buffer, address.data(), address.size());
            safe_buffer[address.size()] = '\0';

            auto res = inet_pton(AF_INET6,safe_buffer, &s.sin6_addr);

            if (res == 0) {
                return std::unexpected(std::make_error_code(std::errc::invalid_argument));
            }

            if (res < 0) {
                return system_error();
            }

            return IpAddress{private_token{}, s};
        }

        [[nodiscard]]
        static auto v4_any(uint16_t port) noexcept
            -> std::expected<IpAddress, std::error_code> {
            sockaddr_in s{};
            
            s.sin_family = AF_INET;
            s.sin_addr.s_addr = INADDR_ANY;
            s.sin_port = htons(port);
            return IpAddress{private_token{}, s};
        }

        [[nodiscard]]
        static auto v6_any(uint16_t port) noexcept
            -> std::expected<IpAddress, std::error_code> {
            sockaddr_in6 s{};
            
            s.sin6_family = AF_INET6;
            s.sin6_addr = in6addr_any;
            s.sin6_port = htons(port);
            return IpAddress{private_token{}, s};
        }

        [[nodiscard]]
        static auto from_sockaddr_storage(sockaddr_storage& addr) {
            if (addr.ss_family == AF_INET) {
                return IpAddress{private_token{}, *(reinterpret_cast<sockaddr_in*>(&addr))};
            } else if (addr.ss_family == AF_INET6) {
                return IpAddress{private_token{}, *(reinterpret_cast<sockaddr_in6*>(&addr))};
            } else {
                assert(false && "Only support Ipv4 and Ipv6 sockets");

                std::abort();
            }
        }

    private:
    std::variant<sockaddr_in, sockaddr_in6> m_addr;

    };

    class SocketHandle
    {
        int m_fd;
        SocketHandle(const SocketHandle& ) = delete;
        SocketHandle& operator=(const SocketHandle& other) = delete;
        
    public:
        SocketHandle(int _fd) : m_fd(_fd) {}
        SocketHandle(SocketHandle&& other) : m_fd(other.m_fd) {other.m_fd = -1;}
        SocketHandle& operator=(SocketHandle&& other) {
            if (this != &other)
            {
                if (m_fd > 0) {
                    close(m_fd);
                }
                m_fd = other.m_fd;
                other.m_fd = -1;
            }

            return *this;
        }

        ~SocketHandle() {
            if (m_fd >= 0)
                close(m_fd);
        }

        auto bind(const IpAddress& addrs) && -> std::expected<SocketHandle, std::error_code> const {
            auto [addr, addrlen] = addrs.get_sockaddr();
            auto res = ::bind(m_fd, addr, addrlen);

            if (res == -1) {
                return system_error();
            }

            return std::move(*this);
        }

        auto listen(int backlog = SOMAXCONN) && -> std::expected<SocketHandle, std::error_code> const {
            auto res = ::listen(m_fd, backlog);
            if (res == -1) {
                return system_error();
            }

            return std::move(*this);
        }

        auto accept() -> std::expected<std::pair<SocketHandle, IpAddress>, std::error_code> const {
            struct sockaddr_storage s;
            socklen_t addr_size = sizeof(s);
            auto res = ::accept(m_fd, reinterpret_cast<sockaddr *>(&s), &addr_size);
            if (res == -1) {
                return system_error();
            }

            auto ip = IpAddress::from_sockaddr_storage(s);
            return std::make_pair(SocketHandle(res), ip);
        }

        auto recv(std::span<std::byte> buffer) const -> std::expected<size_t, std::error_code> {
            auto res = ::recv(m_fd,  buffer.data(), buffer.size_bytes(), 0);
            if (res < 0)
                return system_error();
            return res;
        }

        auto send(std::span<std::byte> buffer) const -> std::expected<size_t, std::error_code> {
            auto res = ::send(m_fd, buffer.data(), buffer.size_bytes(), 0);
            if (res < 0)
                return system_error();

            return res;
        }

        auto shutdown() const {
            ::shutdown(m_fd, SHUT_RDWR);
        }

        auto valid() const {
            return m_fd >= 0;
        }

    };

    export [[nodiscard]]
    auto create_socket(AddressFamily domain, SockType type) -> std::expected<SocketHandle, std::error_code> 
    {
        auto fd = socket(static_cast<int>(domain), static_cast<int>(type), 0);
        if (fd < 0) // error
        {
            return system_error();
        }

        return SocketHandle(fd);

    }

    export class TcpStream {
        SocketHandle m_socket;

        public:
        explicit TcpStream(SocketHandle&& handle) : m_socket(std::move(handle)) {}
        TcpStream(TcpStream&& other) : m_socket(std::move(other.m_socket)) {}

        ~TcpStream() {
            if (m_socket.valid()) {
                m_socket.shutdown();
            }
        }

        auto recv(std::span<std::byte> buffer) {
            return m_socket.recv(buffer);
        }

        auto send(std::span<std::byte> buffer) {
            return m_socket.send(buffer);
        }
    };

    export class TcpListener {
        SocketHandle m_socket;

        explicit TcpListener(SocketHandle&& handle) : m_socket(std::move(handle)) {}

        public:
        TcpListener(TcpListener&& other) : m_socket(std::move(other.m_socket)) {}
        TcpListener& operator=(TcpListener&& other) {
            if (this != &other) {
                m_socket = std::move(other.m_socket);
            }

            return *this;
        }
        ~TcpListener() {
            if (m_socket.valid()) {
                m_socket.shutdown();
            }
        }

        auto accept() -> std::expected<std::pair<TcpStream, IpAddress>, std::error_code> {
            auto maybe_res = m_socket.accept();

            if (maybe_res) {
                auto p = std::move(maybe_res.value());
                return std::make_pair(TcpStream(std::move(p.first)), p.second);
            } else {
                return std::unexpected(maybe_res.error());
            }
        }

        [[nodiscard]]
        static auto create(const IpAddress& addrs) -> std::expected<TcpListener, std::error_code>
        {
            return create_socket(addrs.family(), SockType::Stream)
                .and_then([&addrs](auto handle) {
                    return std::move(handle).bind(addrs);
                }).and_then([](auto handle) {
                    return std::move(handle).listen();
                }).transform([](auto handle) {
                    return TcpListener(std::move(handle));
                });
        }
    };

    
}
