#pragma once
#include <asyncpp/detail/std_import.h>
#include <asyncpp/dispatcher.h>
#include <asyncpp/launch.h>
#include <asyncpp/task.h>
#include <asyncpp/threadsafe_queue.h>
#include <asyncpp/uring/capability_set.h>
#include <asyncpp/uring/index_set.h>
#include <bits/types/struct_iovec.h>
#include <coroutine>
#include <initializer_list>
#include <liburing.h>
#include <liburing/io_uring.h>
#include <mutex>
#include <poll.h>
#include <span>
#include <stdexcept>
#include <stop_token>
#include <sys/eventfd.h>
#include <system_error>
#include <type_traits>
#include <unistd.h>
#include <utility>

#include <iostream>

namespace asyncpp::uring {
	struct io_service;
	class buffer_group;
	class buffer_handle;
	struct sqe_awaitable;
	struct sqe_buffer_awaitable;

	enum class ioseq_flag {
		none = 0,
		fixed_file = IOSQE_FIXED_FILE,
		io_drain = IOSQE_IO_DRAIN,
		io_link = IOSQE_IO_LINK,
		io_hardlink = IOSQE_IO_HARDLINK,
		async = IOSQE_ASYNC,
		buffer_select = IOSQE_BUFFER_SELECT,
		cqe_skip_success = IOSQE_CQE_SKIP_SUCCESS,
	};

	struct sqe_awaitable {
		const io_service& m_service;
		io_uring_sqe* const m_sqe;
		constexpr sqe_awaitable(const io_service& service, io_uring_sqe* sqe) noexcept : m_service{service}, m_sqe(sqe) {}
		constexpr sqe_awaitable(const sqe_awaitable& other) noexcept = default;
		sqe_awaitable& operator=(const sqe_awaitable& other) = delete;

		sqe_awaitable& config(const ioseq_flag flag) && noexcept {
			m_sqe->flags |= static_cast<unsigned char>(flag);
			return *this;
		}
		sqe_buffer_awaitable config(buffer_group& group) && noexcept;

		constexpr bool await_ready() const noexcept { return false; }
		void await_suspend(coroutine_handle<> handle) noexcept { io_uring_sqe_set_data(m_sqe, handle.address()); }
		constexpr int await_resume() const noexcept;
	};

	struct sqe_buffer_awaitable {
		const io_service& m_service;
		io_uring_sqe* const m_sqe;
		buffer_group& m_group;
		constexpr sqe_buffer_awaitable(const io_service& service, io_uring_sqe* sqe, buffer_group& group) noexcept
			: m_service{service}, m_sqe(sqe), m_group(group) {}
		constexpr sqe_buffer_awaitable(const sqe_buffer_awaitable& other) noexcept = default;
		sqe_buffer_awaitable& operator=(const sqe_buffer_awaitable& other) = delete;

		sqe_buffer_awaitable& config(const ioseq_flag flag) && noexcept {
			m_sqe->flags |= static_cast<unsigned char>(flag);
			return *this;
		}

		constexpr bool await_ready() const noexcept { return false; }
		void await_suspend(coroutine_handle<> handle) noexcept { io_uring_sqe_set_data(m_sqe, handle.address()); }
		std::pair<int, buffer_handle> await_resume() const noexcept;
	};

	class buffer_group {
		io_service& m_service;
		uint16_t m_group_index;
		size_t m_block_size;
		size_t m_block_count;
		std::unique_ptr<uint8_t[]> m_data;
		std::unique_ptr<size_t[]> m_refcount;

	public:
		buffer_group(io_service& service, size_t block_size, uint16_t block_count);
		buffer_group(const buffer_group&) = delete;
		buffer_group& operator=(const buffer_group&) = delete;
		~buffer_group() noexcept;

		uint16_t group_index() const noexcept { return m_group_index; }
		size_t block_size() const noexcept { return m_block_size; }
		size_t block_count() const noexcept { return m_block_count; }

		void* ref_buffer(uint16_t buf) noexcept;
		void unref_buffer(uint16_t buf) noexcept;
	};

	class buffer_handle {
		buffer_group* m_group{};
		uint16_t m_buffer_index{};
		void* m_pointer{};

	public:
		constexpr buffer_handle() noexcept = default;
		buffer_handle(buffer_group& group, uint16_t idx) noexcept;
		buffer_handle(const buffer_handle& other) noexcept;
		buffer_handle(buffer_handle&& other) noexcept;
		buffer_handle& operator=(const buffer_handle& other) noexcept;
		buffer_handle& operator=(buffer_handle&& other) noexcept;
		~buffer_handle() { this->reset(); }

		constexpr size_t byte_size() const noexcept { return m_group->block_size(); }
		constexpr void* get() const noexcept { return m_pointer; }
		template<typename T>
		requires std::is_trivial_v<T>
		constexpr std::span<T> typed() const noexcept { return std::span<T>{static_cast<T*>(get()), byte_size() / sizeof(T)}; }

		void* release() noexcept;
		void reset() noexcept;
	};

	class uring {
	public:
		class params {
			unsigned int m_sqe_size;
			io_uring_params m_params;

		public:
			params() : m_sqe_size{128}, m_params{} {}
			params& sqe_size(unsigned int size) noexcept {
				m_sqe_size = size;
				return *this;
			}
			params& cqe_size(unsigned int size) noexcept {
				m_params.cq_entries = size;
				return enable_flags(IORING_SETUP_CQSIZE);
			}
			params& enable_flags(uint32_t flags) noexcept {
				m_params.flags |= flags;
				return *this;
			}
			params& disable_flags(uint32_t flags) noexcept {
				m_params.flags &= ~flags;
				return *this;
			}
			params& attach_wq(uint32_t wq_fd) noexcept {
				m_params.wq_fd = wq_fd;
				return enable_flags(IORING_SETUP_ATTACH_WQ);
			}
			params& sq_affinity(uint32_t cpu) noexcept {
				m_params.sq_thread_cpu = cpu;
				return enable_flags(IORING_SETUP_SQ_AFF);
			}
			params& sq_poll(std::chrono::milliseconds timeout) noexcept {
				m_params.sq_thread_idle = timeout.count();
				return enable_flags(IORING_SETUP_SQPOLL);
			}

			io_uring_params& raw() noexcept { return m_params; }
			const io_uring_params& raw() const noexcept { return m_params; }
			unsigned int sqe_size() const noexcept { return m_sqe_size; }
		};

		uring(const params& p = params{}) : m_ring{}, m_caps{capability_set::no_parse_tag}, m_params{p} {

			auto res = io_uring_queue_init_params(m_params.sqe_size(), &m_ring, &m_params.raw());
			if (res < 0) throw std::system_error(-res, std::system_category());

			try {
				m_caps.parse(&m_ring);
				auto require_op = [this](size_t op) {
					if (!has_capability(op)) throw std::runtime_error("missing required operation " + std::string{capability_set::get_op_name(op)});
				};
				auto require_feature = [this](size_t feat) {
					if (!has_feature(feat)) throw std::runtime_error("missing required feature " + std::string{capability_set::get_feature_name(feat)});
				};

				require_op(IORING_OP_NOP);
				require_op(IORING_OP_READ);
				require_feature(IORING_FEAT_NODROP);
				// TODO: Add required ops as needed
			} catch (...) {
				io_uring_queue_exit(&m_ring);
				throw;
			}
		}
		~uring() noexcept { io_uring_queue_exit(&m_ring); }
		// TODO: Is it safe to move a io_uring instance ?
		uring(const uring&) = delete;
		uring& operator=(const uring&) = delete;

		const capability_set& caps() const noexcept { return m_caps; }
		constexpr bool has_capability(size_t op) const noexcept { return m_caps.has(op); }
		constexpr uint32_t features() const noexcept { return m_params.raw().features; }
		constexpr bool has_feature(uint32_t feature) const noexcept { return (m_params.raw().features & feature) != 0; }
		constexpr struct io_uring* raw_handle() noexcept { return &m_ring; }

		/**
         * \brief Get a submit queue entry.
         * 
         * By default we batch up sqe's until we return to the io loop,
         * where we submit them all and wait for results in a single syscall.
         * In the case we run out of sqe's before this we submit in here.
		 * \note This means you must not use the sqe after any suspension point
		 *		cause it might already have been submitted.
         * 
         * \return io_uring_sqe* sqe entry
         */
		[[nodiscard]] io_uring_sqe* get_sqe() noexcept {
			auto sqe = io_uring_get_sqe(&m_ring);
			if (sqe == nullptr) [[unlikely]] {
				// Submit queue is full, submit all existing ones and retry
				io_uring_submit(&m_ring);
				sqe = io_uring_get_sqe(&m_ring);
			}
			if (sqe == nullptr) [[unlikely]] {
				// If we reach this something is really really wrong....
				std::cerr << "========== Failed to get a sqe after submit ==========" << std::endl;
				std::terminate();
			}
			// Zero out the sqe to avoid dangling user_data
			memset(sqe, 0, sizeof(*sqe));
			return sqe;
		}

		void register_buffers(std::span<const struct iovec> buffers) {
			auto res = io_uring_register_buffers(raw_handle(), buffers.data(), buffers.size());
			if (res < 0) throw std::system_error(-res, std::system_category());
		}
		void register_buffers(std::initializer_list<struct iovec> args) { register_buffers({args.begin(), args.size()}); }
		template<size_t N>
		void register_buffers(const struct iovec (&bufs)[N]) {
			register_buffers({bufs, N});
		}
		void unregister_buffers() {
			auto res = io_uring_unregister_buffers(raw_handle());
			if (res < 0) throw std::system_error(-res, std::system_category());
		}

		void register_files(std::span<const int> fds) {
			auto res = io_uring_register_files(raw_handle(), fds.data(), fds.size());
			if (res < 0) throw std::system_error(-res, std::system_category());
		}
		void register_files(std::initializer_list<int> args) { register_files({args.begin(), args.size()}); }
		template<size_t N>
		void register_files(const int (&fds)[N]) {
			register_files({fds, N});
		}
		void unregister_files() {
			auto res = io_uring_unregister_files(raw_handle());
			if (res < 0) throw std::system_error(-res, std::system_category());
		}
		void register_files_update(unsigned int offset, std::span<const int> fds) {
			// TODO: Remove const_cast after https://github.com/axboe/liburing/pull/652 is merged
			auto res = io_uring_register_files_update(raw_handle(), offset, const_cast<int*>(fds.data()), fds.size());
			if (res < 0) throw std::system_error(-res, std::system_category());
		}
		void register_files_update(unsigned int offset, std::initializer_list<int> args) { register_files_update(offset, {args.begin(), args.size()}); }
		template<size_t N>
		void register_files_update(unsigned int offset, const int (&fds)[N]) {
			register_files_update(offset, {fds, N});
		}
		void register_eventfd(int efd) {
			auto res = io_uring_register_eventfd(raw_handle(), efd);
			if (res < 0) throw std::system_error(-res, std::system_category());
		}
		void register_eventfd_async(int efd) {
			auto res = io_uring_register_eventfd_async(raw_handle(), efd);
			if (res < 0) throw std::system_error(-res, std::system_category());
		}
		void unregister_eventfd() {
			auto res = io_uring_unregister_eventfd(raw_handle());
			if (res < 0) throw std::system_error(-res, std::system_category());
		}
		int register_personality() {
			auto res = io_uring_register_personality(raw_handle());
			if (res < 0) throw std::system_error(-res, std::system_category());
			return res;
		}
		void unregister_personality(int personality) {
			auto res = io_uring_unregister_personality(raw_handle(), personality);
			if (res < 0) throw std::system_error(-res, std::system_category());
		}

	private:
		params m_params;
		struct io_uring m_ring;
		capability_set m_caps;
	};

	struct io_service : uring, dispatcher {
		const ioseq_flag skip_success_flags;

		io_service(const params& params = io_service::params{}) //
			: uring{params}, m_want_exit{false},				//
			  m_dispatched_wake{eventfd(0, 0)},					//
			  skip_success_flags{has_feature(IORING_FEAT_CQE_SKIP) ? ioseq_flag::cqe_skip_success : ioseq_flag::none} {
			set_null_cqe_handler([](const io_uring_cqe* cqe) {
				if (cqe->res < 0) std::cerr << "Error on null sqe: " << cqe->res << " " << strerror(-cqe->res) << std::endl;
			});
		}
		~io_service() noexcept { close(m_dispatched_wake); }

		void set_null_cqe_handler(std::function<void(const struct io_uring_cqe*)> cb) { m_handle_null_cqe = std::move(cb); }

		/**
		 * \brief Run a loop submitting and polling for completions.
		 * This function runs until signal_shutdown() was called and all tasks passed to launch() have completed.
		 * \param stop_token A stop token for the operation. Signaling the token is equivalent to calling signal_shutdown().
		 */
		void run(std::stop_token stop_token = {}) noexcept;
		/**
		 * \brief Signal the loop to shutdown.
		 * \note This function is thread safe and can be called at any time, even if no loop is running.
		 */
		void signal_shutdown() noexcept {
			m_want_exit = true;
			eventfd_write(m_dispatched_wake, 1);
		}

		// Inherited from dispatcher
		void push(std::function<void()> fn) override {
			m_dispatched.emplace(std::move(fn));
			eventfd_write(m_dispatched_wake, 1);
		}

		/**
		 * \brief Spawn a new task for the given awaitable and keeps the loop running until it finished
		 * \param awaitable Awaitable to run
		 * \param allocator Allocator used for allocating the wrapper task
		 */
		template<typename Awaitable, ByteAllocator Allocator = default_allocator_type>
		void launch(Awaitable&& awaitable, const Allocator& allocator = {}) {
			m_async_scope.launch<Awaitable, Allocator>(std::move(awaitable), std::move(allocator));
		}

		const struct io_uring_cqe* current_cqe() const noexcept { return m_current_cqe; }

		uint16_t allocate_buffer_group_index() { return m_buffer_idx.allocate_index(); }
		void return_buffer_group_index(uint16_t idx) { m_buffer_idx.return_index(idx); }

		/**
		 * \brief Prepare a uring operation using the function passed using PrepareFN and returns an sqe_awaitable for it.
		 * 
		 * \tparam PrepareFN Function used to prepare the sqe
		 * \param args Arguments passed to PrepareFN
		 * \return sqe_awaitable 
		 */
		template<auto PrepareFN, typename... Args>
		sqe_awaitable do_call(Args&&... args) noexcept {
			auto sqe = get_sqe();
			PrepareFN(sqe, std::forward<Args>(args)...);
			return sqe_awaitable{*this, sqe};
		}

		sqe_awaitable nop() noexcept { return do_call<&io_uring_prep_nop>(); }
		sqe_awaitable readv(int fd, const struct iovec* iovecs, unsigned int nr_vecs, uint64_t offset) noexcept {
			return do_call<&io_uring_prep_readv>(fd, iovecs, nr_vecs, offset);
		}
		sqe_awaitable writev(int fd, const struct iovec* iovecs, unsigned int nr_vecs, uint64_t offset) noexcept {
			return do_call<&io_uring_prep_writev>(fd, iovecs, nr_vecs, offset);
		}
		sqe_awaitable fsync(int fd, unsigned int fsync_flags) noexcept { return do_call<&io_uring_prep_fsync>(fd, fsync_flags); }
		sqe_awaitable read_fixed(int fd, void* buf, unsigned int nbytes, uint64_t offset, int buf_index) noexcept {
			return do_call<&io_uring_prep_read_fixed>(fd, buf, nbytes, offset, buf_index);
		}
		sqe_awaitable write_fixed(int fd, const void* buf, unsigned int nbytes, uint64_t offset, int buf_index) noexcept {
			return do_call<&io_uring_prep_write_fixed>(fd, buf, nbytes, offset, buf_index);
		}
		sqe_awaitable poll_add(int fd, short mask) noexcept { return do_call<&io_uring_prep_poll_add>(fd, mask); }
		// TODO: How usefull is this ?
		sqe_awaitable poll_remove(uint64_t udata) noexcept { return do_call<&io_uring_prep_poll_remove>(udata); }
		sqe_awaitable sync_file_range(int fd, unsigned int len, uint64_t offset, int flags) noexcept {
			return do_call<&io_uring_prep_sync_file_range>(fd, len, offset, flags);
		}
		sqe_awaitable sendmsg(int fd, const struct msghdr* msg, unsigned int flags) noexcept { return do_call<&io_uring_prep_sendmsg>(fd, msg, flags); }
		sqe_awaitable recvmsg(int fd, struct msghdr* msg, unsigned int flags) noexcept { return do_call<&io_uring_prep_recvmsg>(fd, msg, flags); }
		sqe_awaitable timeout(__kernel_timespec* ts, unsigned int count = 0, unsigned int flags = 0) noexcept {
			return do_call<&io_uring_prep_timeout>(ts, count, flags);
		}
		// TODO: How usefull is this ?
		sqe_awaitable timeout_remove(uint64_t udata, unsigned int flags) noexcept { return do_call<&io_uring_prep_timeout_remove>(udata, flags); }
		sqe_awaitable accept(int fd, struct sockaddr* addr, socklen_t* addrlen, int flags) noexcept {
			return do_call<&io_uring_prep_accept>(fd, addr, addrlen, flags);
		}
		// TODO: How usefull is this ?
		sqe_awaitable cancel(void* user_data, int flags) noexcept { return do_call<&io_uring_prep_cancel>(user_data, flags); }
		sqe_awaitable link_timeout(struct __kernel_timespec* ts, unsigned int flags) noexcept { return do_call<&io_uring_prep_link_timeout>(ts, flags); }
		sqe_awaitable connect(int fd, const struct sockaddr* addr, socklen_t addrlen) noexcept { return do_call<&io_uring_prep_connect>(fd, addr, addrlen); }
		sqe_awaitable fallocate(int fd, int mode, off_t offset, off_t len) noexcept { return do_call<&io_uring_prep_fallocate>(fd, mode, offset, len); }
		sqe_awaitable openat(int dfd, const char* path, int flags, mode_t mode) noexcept { return do_call<&io_uring_prep_openat>(dfd, path, flags, mode); }
		sqe_awaitable close(int fd) noexcept { return do_call<&io_uring_prep_close>(fd); }
		sqe_awaitable files_update(int* fds, unsigned int nr_fds, int offset) noexcept { return do_call<&io_uring_prep_files_update>(fds, nr_fds, offset); }
		sqe_awaitable statx(int dfd, const char* path, int flags, unsigned int mask, struct statx* statxbuf) noexcept {
			return do_call<&io_uring_prep_statx>(dfd, path, flags, mask, statxbuf);
		}
		sqe_awaitable read(int fd, void* buf, unsigned nbytes, off_t offset = 0) noexcept { return do_call<&io_uring_prep_read>(fd, buf, nbytes, offset); }
		sqe_buffer_awaitable read(int fd, buffer_group& buffers, off_t offset = 0) noexcept {
			return do_call<&io_uring_prep_read>(fd, nullptr, buffers.block_size(), offset).config(buffers);
		}
		sqe_awaitable write(int fd, const void* buf, unsigned nbytes, off_t offset = 0) noexcept {
			return do_call<&io_uring_prep_write>(fd, buf, nbytes, offset);
		}
		sqe_awaitable fadvise(int fd, uint64_t offset, off_t len, int advice) noexcept { return do_call<&io_uring_prep_fadvise>(fd, offset, len, advice); }
		sqe_awaitable madvise(void* addr, off_t length, int advice) noexcept { return do_call<&io_uring_prep_madvise>(addr, length, advice); }
		sqe_awaitable send(int sockfd, const void* buf, size_t len, int flags) noexcept { return do_call<&io_uring_prep_send>(sockfd, buf, len, flags); }
		sqe_awaitable recv(int sockfd, void* buf, size_t len, int flags) noexcept { return do_call<&io_uring_prep_recv>(sockfd, buf, len, flags); }
		sqe_buffer_awaitable recv(int sockfd, buffer_group& buffers, int flags) noexcept {
			return do_call<&io_uring_prep_recv>(sockfd, nullptr, buffers.block_size(), flags).config(buffers);
		}
		sqe_awaitable openat(int dfd, const char* path, struct open_how* how) noexcept { return do_call<&io_uring_prep_openat2>(dfd, path, how); }
		sqe_awaitable epoll_ctl(int epfd, int fd, int op, struct epoll_event* ev) noexcept { return do_call<&io_uring_prep_epoll_ctl>(epfd, fd, op, ev); }
		sqe_awaitable splice(int fd_in, int64_t off_in, int fd_out, int64_t off_out, unsigned int nbytes, unsigned int splice_flags) noexcept {
			return do_call<&io_uring_prep_splice>(fd_in, off_in, fd_out, off_out, nbytes, splice_flags);
		}
		sqe_awaitable provide_buffers(void* addr, int len, int nr, int bgid, int bid) noexcept {
			return do_call<&io_uring_prep_provide_buffers>(addr, len, nr, bgid, bid);
		}
		sqe_awaitable remove_buffers(int nr, int bgid) noexcept { return do_call<&io_uring_prep_remove_buffers>(nr, bgid); }
		sqe_awaitable tee(int fd_in, int fd_out, unsigned int nbytes, unsigned int splice_flags) noexcept {
			return do_call<&io_uring_prep_tee>(fd_in, fd_out, nbytes, splice_flags);
		}
		sqe_awaitable shutdown(int fd, int how) noexcept { return do_call<&io_uring_prep_shutdown>(fd, how); }
		sqe_awaitable renameat(int olddfd, const char* oldpath, int newdfd, const char* newpath, int flags) noexcept {
			return do_call<&io_uring_prep_renameat>(olddfd, oldpath, newdfd, newpath, flags);
		}
		sqe_awaitable unlinkat(int dfd, const char* path, int flags) noexcept { return do_call<&io_uring_prep_unlinkat>(dfd, path, flags); }
		sqe_awaitable mkdirat(int dfd, const char* path, mode_t mode) noexcept { return do_call<&io_uring_prep_mkdirat>(dfd, path, mode); }
		sqe_awaitable symlinkat(const char* target, int newdirfd, const char* linkpath) noexcept {
			return do_call<&io_uring_prep_symlinkat>(target, newdirfd, linkpath);
		}
		sqe_awaitable linkat(int olddfd, const char* oldpath, int newdfd, const char* newpath, int flags) noexcept {
			return do_call<&io_uring_prep_linkat>(olddfd, oldpath, newdfd, newpath, flags);
		}
		sqe_awaitable msg_ring(int fd, unsigned int len, uint64_t data, unsigned int flags) noexcept {
			return do_call<&io_uring_prep_msg_ring>(fd, len, data, flags);
		}
		sqe_awaitable fsetxattr(int fd, const char* name, const char* value, int flags, size_t len) noexcept {
			return do_call<&io_uring_prep_fsetxattr>(fd, name, value, flags, len);
		}
		sqe_awaitable setxattr(const char* name, const char* value, const char* path, int flags, size_t len) noexcept {
			return do_call<&io_uring_prep_setxattr>(name, value, path, flags, len);
		}
		sqe_awaitable fgetxattr(int fd, const char* name, char* value, size_t len) noexcept { return do_call<&io_uring_prep_fgetxattr>(fd, name, value, len); }
		sqe_awaitable getxattr(const char* name, char* value, const char* path, size_t len) noexcept {
			return do_call<&io_uring_prep_getxattr>(name, value, path, len);
		}
		sqe_awaitable socket(int domain, int type, int protocol, unsigned int flags) noexcept {
			return do_call<&io_uring_prep_socket>(domain, type, protocol, flags);
		}
		// TODO: io_uring_prep_uring_cmd

	private:
		std::function<void(const struct io_uring_cqe*)> m_handle_null_cqe;
		int m_dispatched_wake;
		threadsafe_queue<std::function<void()>> m_dispatched;
		async_launch_scope m_async_scope;
		std::atomic<bool> m_want_exit;

		index_set<uint16_t> m_buffer_idx;

		const struct io_uring_cqe* m_current_cqe;

		/**
		 * \brief Internal task used by run() to handle dispatched functions.
		 */
		task<> run_handle_dispatched() noexcept;
	};

	inline task<> io_service::run_handle_dispatched() noexcept {
		// Invoke pushed functions
		while (!m_want_exit) {
			// Wait for events
			eventfd_t value{};
			auto res = co_await this->read(m_dispatched_wake, &value, sizeof(value));

			while (true) {
				auto cb = m_dispatched.pop();
				if (!cb) break;
				(*cb)();
			}
		}
	}

	inline void io_service::run(std::stop_token stop_token) noexcept {
		dispatcher::current(this);
		m_want_exit = false;
		std::stop_callback exit_cb(stop_token, [this]() { this->signal_shutdown(); });
		this->launch(this->run_handle_dispatched());
		while (!m_async_scope.all_done()) {
			unsigned head;
			io_uring_for_each_cqe(raw_handle(), head, m_current_cqe) {
				auto coro = coroutine_handle<>::from_address(io_uring_cqe_get_data(m_current_cqe));
				if (coro == nullptr) {
					if (m_handle_null_cqe) m_handle_null_cqe(m_current_cqe);
					continue;
				}
				coro.resume();
			}
			if (*raw_handle()->cq.khead == head) {
				io_uring_submit_and_wait(raw_handle(), 1);
			} else {
				// This is equivalent to counting the number of cqs above and using io_uring_cq_advance
				// Since head is already counted to the last element we simply write it directly
				io_uring_smp_store_release(raw_handle()->cq.khead, head);
			}
		}
		dispatcher::current(nullptr);
	}

	inline sqe_buffer_awaitable sqe_awaitable::config(buffer_group& group) && noexcept {
		m_sqe->flags |= static_cast<unsigned char>(ioseq_flag::buffer_select);
		m_sqe->buf_group = group.group_index();
		return sqe_buffer_awaitable{m_service, m_sqe, group};
	}

	inline constexpr int sqe_awaitable::await_resume() const noexcept { return m_service.current_cqe()->res; }

	inline std::pair<int, buffer_handle> sqe_buffer_awaitable::await_resume() const noexcept {
		auto cqe = m_service.current_cqe();
		buffer_handle ptr;
		if (cqe->flags & IORING_CQE_F_BUFFER) {
			auto bufidx = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
			assert(cqe->res <= m_group.block_size());
			ptr = buffer_handle(m_group, bufidx);
		}
		return {cqe->res, ptr};
	}

	inline buffer_group::buffer_group(io_service& service, size_t block_size, uint16_t block_count)
		: m_service{service}, m_group_index{m_service.allocate_buffer_group_index()}, m_block_size{block_size}, m_block_count{block_count} {
		m_data = std::make_unique<uint8_t[]>(m_block_size * m_block_count);
		m_refcount = std::make_unique<size_t[]>(m_block_count);
		memset(m_refcount.get(), 0, sizeof(size_t) * m_block_count);
		// TODO: Detect errors
		m_service.provide_buffers(m_data.get(), m_block_size, m_block_count, m_group_index, 0).config(m_service.skip_success_flags);
	}

	inline buffer_group::~buffer_group() noexcept {
		// TODO: Detect errors
		m_service.remove_buffers(m_block_count, m_group_index).config(m_service.skip_success_flags);
		m_service.return_buffer_group_index(m_group_index);
	}

	inline void* buffer_group::ref_buffer(uint16_t buf) noexcept {
		if (buf >= m_block_count) return nullptr;
		m_refcount[buf]++;
		return m_data.get() + (m_block_size * buf);
	}

	inline void buffer_group::unref_buffer(uint16_t buf) noexcept {
		if (buf >= m_block_count) return;
		if (m_refcount[buf] == 0) return;
		if (m_refcount[buf]-- == 1) {
			// TODO: Detect errors
			m_service.provide_buffers(m_data.get() + (m_block_size * buf), m_block_size, 1, m_group_index, buf).config(m_service.skip_success_flags);
		}
	}

	inline buffer_handle::buffer_handle(buffer_group& group, uint16_t idx) noexcept
		: m_group{&group}, m_buffer_index{idx}, m_pointer{m_group->ref_buffer(m_buffer_index)} {}

	inline buffer_handle::buffer_handle(const buffer_handle& other) noexcept : m_group(other.m_group), m_buffer_index{other.m_buffer_index} {
		if (m_group != nullptr) m_pointer = m_group->ref_buffer(m_buffer_index);
	}

	inline buffer_handle::buffer_handle(buffer_handle&& other) noexcept
		: m_group(std::exchange(other.m_group, nullptr)), m_buffer_index(std::exchange(other.m_buffer_index, 0)),
		  m_pointer(std::exchange(other.m_pointer, nullptr)) {}

	inline buffer_handle& buffer_handle::operator=(const buffer_handle& other) noexcept {
		this->reset();
		m_group = other.m_group;
		m_buffer_index = other.m_buffer_index;
		if (m_group != nullptr) m_pointer = m_group->ref_buffer(m_buffer_index);
		return *this;
	}

	inline buffer_handle& buffer_handle::operator=(buffer_handle&& other) noexcept {
		this->reset();
		m_group = std::exchange(other.m_group, nullptr);
		m_buffer_index = std::exchange(other.m_buffer_index, 0);
		m_pointer = std::exchange(other.m_pointer, nullptr);
		return *this;
	}

	inline void* buffer_handle::release() noexcept {
		m_group = nullptr;
		m_buffer_index = 0;
		return std::exchange(m_pointer, nullptr);
	}

	inline void buffer_handle::reset() noexcept {
		if (m_group != nullptr && m_pointer != nullptr) m_group->unref_buffer(m_buffer_index);
		m_group = nullptr;
		m_buffer_index = 0;
		m_pointer = nullptr;
	}

} // namespace asyncpp::uring