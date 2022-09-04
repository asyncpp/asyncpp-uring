#include <asyncpp/scope_guard.h>
#include <asyncpp/uring/io_service.h>
#include <liburing/io_uring.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace asyncpp;
using namespace asyncpp::uring;

task<> handle_connection(io_service& io, int socket, buffer_group& buffers) {
	std::cout << "(" << socket << ") Connection established" << std::endl;
	auto [res, buf] = co_await io.recv(socket, buffers, 0);
	while (res > 0) {
		//auto data = buf.typed<char>();
		//std::cout << "(" << socket << ") " << std::string_view{data.data(), data.size()} << std::endl;
		co_await io.send(socket, buf.get(), res, 0);
		std::tie(res, buf) = co_await io.recv(socket, buffers, 0);
	}
	std::cout << strerror(-res) << std::endl;
	co_await io.close(socket);
	std::cout << "(" << socket << ") Disconnected" << std::endl;
}

int main() {
	io_service io;
	buffer_group buffers{io, 32 * 1024, 32};
	io.launch([](io_service& io, buffer_group& buffers) -> task<> {
		// Try create a socket and fallback to sync if unsupported
		int sock = io.has_capability(IORING_OP_SOCKET)					//
					   ? co_await io.socket(AF_INET, SOCK_STREAM, 0, 0) //
					   : socket(AF_INET, SOCK_STREAM, 0);
		if (sock < 0) {
			std::cout << "failed to create socket: " << strerror(-sock) << std::endl;
			co_return;
		}
		scope_guard close_socket([sock]() noexcept { close(sock); });
		sockaddr_in bind_addr = {
			.sin_family = AF_INET,
			.sin_port = htons(1234),
			.sin_addr = {INADDR_ANY},
			.sin_zero = {},
		};
		if (auto res = bind(sock, reinterpret_cast<sockaddr*>(&bind_addr), sizeof(bind_addr)); res != 0) {
			std::cout << "failed to bind socket: " << strerror(errno) << std::endl;
			co_return;
		}
		if (auto res = listen(sock, 10); res != 0) {
			std::cout << "failed to listen on socket: " << strerror(errno) << std::endl;
			co_return;
		}
		while (auto new_con = co_await io.accept(sock, nullptr, nullptr, 0)) {
			io.launch(handle_connection(io, new_con, buffers));
		}
	}(io, buffers));
	io.run();
}