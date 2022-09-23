#include <asyncpp/fire_and_forget.h>
#include <asyncpp/uring/io_service.h>
#include <chrono>
#include <cstdint>
#include <gtest/gtest.h>
#include <ratio>
#include <stop_token>

using namespace asyncpp::uring;
using namespace asyncpp;

#define COASSERT_EQ(a, b)                                                                                                                                      \
	{                                                                                                                                                          \
		bool failed{true};                                                                                                                                     \
		[&]() {                                                                                                                                                \
			ASSERT_EQ(a, b);                                                                                                                                   \
			failed = false;                                                                                                                                    \
		}();                                                                                                                                                   \
		if (failed) co_return;                                                                                                                                 \
	}

namespace {
	template<typename T, std::intmax_t Num, std::intmax_t Denom>
	T operator*(T val, std::ratio<Num, Denom>) {
		return (val / Num) * Denom;
	}

	struct stopwatch {
		stopwatch(std::string name, size_t num_ops) : m_name(name), m_num_ops{num_ops}, m_start{clock::now()} {}
		~stopwatch() {
			const auto end = clock::now();
			const auto dur = std::chrono::duration_cast<std::chrono::nanoseconds>(end - m_start);
			const auto ops = (static_cast<double>(m_num_ops) / dur.count()) * std::nano{};
			printf("%.20s %zu ns (%.2lf op/s)\n", m_name.c_str(), dur.count(), ops);
		}

		using clock = std::chrono::high_resolution_clock;
		const std::string m_name;
		const size_t m_num_ops;
		const clock::time_point m_start;
	};

	constexpr size_t num_samples = 10000000;
	constexpr size_t num_prewarm = 1000;

} // namespace

TEST(ASYNCPP_URING, IoServicePerformance) {
	io_service io;
	io.launch([](io_service& io) -> task<> {
		for (size_t i = 0; i < num_prewarm; i++)
			co_await io.nop();
		{
			stopwatch sw{"io.nop()", num_samples};
			for (size_t i = 0; i < num_samples; i++)
				co_await io.nop();
		}
		co_return;
	}(io));
	io.run();
}

TEST(ASYNCPP_URING, PlainPerformance) {
	io_service io;
	{
		auto ring = io.raw_handle();
		for (size_t i = 0; i < num_prewarm; i++) {
			auto* sqe = io_uring_get_sqe(ring);
			io_uring_prep_nop(sqe);
			io_uring_submit_and_wait(ring, 1);

			io_uring_cqe* cqe;
			io_uring_peek_cqe(ring, &cqe);
			(void)cqe->res;
			io_uring_cqe_seen(ring, cqe);
		}
	}
	{
		auto ring = io.raw_handle();
		stopwatch sw{"plain", num_samples};
		for (size_t i = 0; i < num_samples; i++) {
			auto* sqe = io_uring_get_sqe(ring);
			io_uring_prep_nop(sqe);
			io_uring_submit_and_wait(ring, 1);

			io_uring_cqe* cqe;
			io_uring_peek_cqe(ring, &cqe);
			(void)cqe->res;
			io_uring_cqe_seen(ring, cqe);
		}
	}
}

TEST(ASYNCPP_URING, IoServiceDispatch) {
	bool was_executed = false;
	io_service io;
	io.push([&]() { was_executed = true; });
	io.run_once();
	ASSERT_TRUE(was_executed);
}

TEST(ASYNCPP_URING, IoServiceBufferGroup) {
	int fds[2];
	ASSERT_GE(pipe2(fds, O_DIRECT), 0);

	io_service io;
	buffer_group buffers{io, 16 * 1024, 128};
	io.launch([](io_service& io, buffer_group& buffers, int write_fd, int read_fd) -> task<> {
		{
			auto res = co_await io.write(write_fd, "Hello", 5, 0);
			COASSERT_EQ(res, 5);
		}
		{
			int res;
			buffer_handle buf;
			std::tie(res, buf) = co_await io.read(read_fd, buffers, 0);
			COASSERT_EQ(res, 5);
			COASSERT_EQ(memcmp(buf.get(), "Hello", 5), 0);
		}
		co_return;
	}(io, buffers, fds[1], fds[0]));
	io.run();
}

TEST(ASYNCPP_URING, IoServiceBufferGroupENOBUFS) {
	int fds[2];
	ASSERT_GE(pipe2(fds, O_DIRECT), 0);

	io_service io;
	buffer_group buffers{io, 16 * 1024, 1};
	io.launch([](io_service& io, buffer_group& buffers, int write_fd, int read_fd) -> task<> {
		{
			auto res = co_await io.write(write_fd, "Hello", 5, 0);
			COASSERT_EQ(res, 5);
		}
		{
			int res;
			buffer_handle buf;
			std::tie(res, buf) = co_await io.read(read_fd, buffers, 0);
			COASSERT_EQ(res, 5);
			COASSERT_EQ(memcmp(buf.get(), "Hello", 5), 0);
			// Don't readd the buffer
			buf.release();
		}
		{
			auto res = co_await io.write(write_fd, "Hello", 5, 0);
			COASSERT_EQ(res, 5);
		}
		{
			int res;
			buffer_handle buf;
			std::tie(res, buf) = co_await io.read(read_fd, buffers, 0);
			COASSERT_EQ(res, -ENOBUFS);
			COASSERT_EQ(buf.get(), nullptr);
		}
		co_return;
	}(io, buffers, fds[1], fds[0]));
	io.run();
}
