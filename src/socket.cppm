module;
#include <utility>
#include <system_error>
#include <string>
#include <errno.h>
#include <sys/socket.h>
#include <expected>
#include <unistd.h>

export module socketcpp;


namespace net {

    export enum class AddressFamily : int 
    {
        Ipv4 = AF_INET,
        Ipv6 = AF_INET6,
        Unspec = AF_UNSPEC
    };

    export enum class SockType : int
    {
        Strean = SOCK_STREAM,
        Datagram = SOCK_DGRAM,
    };

    class SocketHandle
    {
        int m_fd;
        SocketHandle(const SocketHandle& ) = delete;
        SocketHandle& operator=(const SocketHandle& other) = delete;
        
    public:
        SocketHandle(int _fd) : m_fd(_fd) {}
        SocketHandle(SocketHandle&& other) : m_fd(other.m_fd) {other.m_fd = -1;}
        SocketHandle& operator=(SocketHandle&& other)
        {
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

        ~SocketHandle() 
        {
            if (m_fd > 0)
                close(m_fd);
        }
    };

    export [[nodiscard]]
    auto create_socket(AddressFamily domain, SockType type) -> std::expected<SocketHandle, std::error_code> 
    {
        auto fd = socket(static_cast<int>(domain), static_cast<int>(type), 0);
        if (fd < 0) // error
        {
            return std::unexpected(std::error_code(errno, std::system_category()));
        }

        return SocketHandle(fd);

    }

    
}
