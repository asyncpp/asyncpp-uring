#include <asyncpp/scope_guard.h>
#include <asyncpp/uring/io_service.h>
#include <bits/types/struct_iovec.h>
#include <chrono>
#include <liburing.h>
#include <liburing/io_uring.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace asyncpp;
using namespace asyncpp::uring;

int main() {
	io_service::params p;
	p.sqe_size(128);
	//p.enable_flags(IORING_SETUP_IOPOLL);
	//p.sq_poll(std::chrono::milliseconds{1000});
	io_service io{p};
	buffer_group buffers{io, 32 * 1024, 32};
	io.launch([](io_service& io, buffer_group& buffers) -> task<> {
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
		std::cout << "Connecting..." << std::endl;
		sockaddr_in connect_addr = {
			.sin_family = AF_INET,
			.sin_port = htons(1234),
			.sin_addr = {htonl(INADDR_LOOPBACK)},
			.sin_zero = {},
		};
		if (auto res = co_await io.connect(sock, reinterpret_cast<sockaddr*>(&connect_addr), sizeof(connect_addr)); res != 0) {
			std::cout << "failed to connect socket: " << strerror(-res) << std::endl;
			co_return;
		}
		std::cout << "Connected" << std::endl;
		io.launch([](int sock, io_service& io, buffer_group& buffers) -> task<> {
			auto [res, buf] = co_await io.recv(sock, buffers, 0);
			while (res > 0)
				std::tie(res, buf) = co_await io.recv(sock, buffers, 0);
			std::cout << "Done" << std::endl;
		}(sock, io, buffers));
		char buf[128 * 1024];
		constexpr size_t num_iterations = 500000;
		memset(buf, 0, sizeof(buf));
		auto start = std::chrono::high_resolution_clock::now();
		for (size_t i = 0; i < num_iterations; i++) {
			co_await io.send(sock, buf, sizeof(buf), 0);
		}
		auto end = std::chrono::high_resolution_clock::now();
		auto dur = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
		auto speed = ((static_cast<double>(sizeof(buf) * num_iterations) / dur.count()) * 1000) / 1024;
		std::cout << "Done sending " << sizeof(buf) * num_iterations << " Byte in " << dur.count() << "ms (" << std::fixed << speed << "kB/s)" << std::endl;
		co_await io.close(sock);
	}(io, buffers));
	io.run();
}
