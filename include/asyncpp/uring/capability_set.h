#pragma once
#include <bitset>
#include <cstddef>
#include <liburing.h>
#include <liburing/io_uring.h>
#include <memory>
#include <string_view>

namespace asyncpp::uring {
	class capability_set {
		std::bitset<IORING_OP_LAST> m_supported;

	public:
		constexpr static struct {
		} no_parse_tag{};
		capability_set(struct io_uring* ring) : m_supported{} { this->parse(ring); }
		capability_set() : m_supported{} { this->parse(nullptr); }
		constexpr capability_set(decltype(no_parse_tag)) noexcept : m_supported{} {}
		constexpr capability_set(const capability_set& other) noexcept = default;
		capability_set& operator=(const capability_set& other) noexcept = default;

		void parse(struct io_uring* ring) {
			std::unique_ptr<struct io_uring_probe, decltype(&free)> probe{ring ? io_uring_get_probe_ring(ring) : io_uring_get_probe(), &free};
			if (!probe) throw std::bad_alloc{};
			for (size_t i = 0; i < m_supported.size(); i++) {
				m_supported.set(i, io_uring_opcode_supported(probe.get(), i));
			}
		}

		constexpr bool has(size_t index) const noexcept { return index < m_supported.size() && m_supported.test(index); }
		constexpr size_t size() const noexcept { return m_supported.size(); }

		struct iterator_end {};
		struct iterator {
			using value_type = std::tuple<size_t, std::string_view, bool>;

			iterator(const capability_set& p) : m_parent(p) { m_value = value_type{0, capability_set::get_op_name(0), m_parent.has(0)}; }

			size_t index() const noexcept { return std::get<size_t>(m_value); }
			std::string_view name() const noexcept { return std::get<std::string_view>(m_value); }
			bool is_supported() const noexcept { return std::get<bool>(m_value); }

			const value_type& operator*() const noexcept { return m_value; }
			iterator& operator++() noexcept {
				auto next_idx = index() + 1;
				if (next_idx > m_parent.size()) return *this;
				m_value = value_type{next_idx, capability_set::get_op_name(next_idx), m_parent.has(next_idx)};
				return *this;
			}
			iterator operator++(int) noexcept {
				auto tmp = *this;
				++(*this);
				return tmp;
			}

			friend bool operator==(const iterator& lhs, const iterator_end&) noexcept { return lhs.index() == lhs.m_parent.size(); }
			friend bool operator!=(const iterator& lhs, const iterator_end&) noexcept { return lhs.index() != lhs.m_parent.size(); }
			friend bool operator==(const iterator_end&, const iterator& rhs) noexcept { return rhs.index() == rhs.m_parent.size(); }
			friend bool operator!=(const iterator_end&, const iterator& rhs) noexcept { return rhs.index() != rhs.m_parent.size(); }

		private:
			const capability_set& m_parent;
			value_type m_value;
		};

		iterator begin() const noexcept { return iterator{*this}; }
		constexpr iterator_end end() const noexcept { return iterator_end{}; }

		static std::string_view get_op_name(size_t index) noexcept {
			static constexpr std::string_view names[] = {
				"NOP",
				"READV",
				"WRITEV",
				"FSYNC",
				"READ_FIXED",
				"WRITE_FIXED",
				"POLL_ADD",
				"POLL_REMOVE",
				"SYNC_FILE_RANGE",
				"SENDMSG",
				"RECVMSG",
				"TIMEOUT",
				"TIMEOUT_REMOVE",
				"ACCEPT",
				"ASYNC_CANCEL",
				"LINK_TIMEOUT",
				"CONNECT",
				"FALLOCATE",
				"OPENAT",
				"CLOSE",
				"FILES_UPDATE",
				"STATX",
				"READ",
				"WRITE",
				"FADVISE",
				"MADVISE",
				"SEND",
				"RECV",
				"OPENAT2",
				"EPOLL_CTL",
				"SPLICE",
				"PROVIDE_BUFFERS",
				"REMOVE_BUFFERS",
				"TEE",
				"SHUTDOWN",
				"RENAMEAT",
				"UNLINKAT",
				"MKDIRAT",
				"SYMLINKAT",
				"LINKAT",
				"MSG_RING",
				"FSETXATTR",
				"SETXATTR",
				"FGETXATTR",
				"GETXATTR",
				"SOCKET",
				"URING_CMD",
				"SEND_ZC",
				"SENDMSG_ZC",
			};

			if (index >= (sizeof(names) / sizeof(names[0]))) return "";
			return names[index];
		}
		static std::string get_feature_name(size_t index) noexcept {
			static constexpr std::string_view names[] = {
				"SINGLE_MMAP",	   "NODROP",  "SUBMIT_STABLE",	"RW_CUR_POS", "CUR_PERSONALITY", "FAST_POLL",	"POLL_32BITS",
				"SQPOLL_NONFIXED", "EXT_ARG", "NATIVE_WORKERS", "RSRC_TAGS",  "CQE_SKIP",		 "LINKED_FILE",
			};

			std::string res;
			for (size_t i = 0; i < (sizeof(names) / sizeof(names[0])); i++) {
				if (index & (1 << i)) {
					if (!res.empty()) res += " | ";
					res += names[i];
				}
			}
			return res;
		}
	};
} // namespace asyncpp::uring
