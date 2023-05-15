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
	asyncpp::stop_source exit;
	io_service io;
	io.launch([](io_service& io, asyncpp::stop_source& exit) -> task<> {
		std::cout << "Server started, type \"help\" to get a list of commands or \"quit\" to shut down the server" << std::endl;
		char buf[1024];
		std::string line;
		while (!exit.stop_requested()) {
			auto res = co_await io.read(STDIN_FILENO, buf, sizeof(buf), 0);
			if (res < 0) break;
			for (int i = 0; i < res; i++) {
				if (buf[i] == '\r') continue;
				if (buf[i] != '\n') {
					line += buf[i];
					continue;
				}
				if (line == "quit" || line == "q")
					exit.request_stop();
				else if (line == "help") {
					std::cout << "Valid commands:\n";
					std::cout << "help    Show this help\n";
					std::cout << "quit    Exit\n" << std::flush;
				}
				line.clear();
			}
		}
		std::cout << "Exiting..." << std::endl;
	}(io, exit));
	buffer_group buffers{io, 32 * 1024, 32};
	io.launch([](io_service& io, buffer_group& buffers, asyncpp::stop_source& exit) -> task<> {
	// Try create a socket and fallback to sync if unsupported
#if ASYNCPP_URING_OP_LAST >= 45
		int sock = io.has_capability(IORING_OP_SOCKET)					//
					   ? co_await io.socket(AF_INET, SOCK_STREAM, 0, 0) //
					   : socket(AF_INET, SOCK_STREAM, 0);
#else
		int sock = socket(AF_INET, SOCK_STREAM, 0);
#endif
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
		while (auto new_con = co_await io.accept(sock, nullptr, nullptr, 0, exit.get_token())) {
			if (new_con < 0) break;
			io.launch(handle_connection(io, new_con, buffers));
		}
	}(io, buffers, exit));
	io.run();
}
