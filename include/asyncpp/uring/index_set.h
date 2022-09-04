#pragma once
#include <cassert>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <stdexcept>
#if __has_include(<bit>)
#include <bit>
#endif

namespace asyncpp::uring {
	template<typename T>
	struct always_false : std::false_type {};
#if __cpp_lib_bitops >= 201907L
	using std::countr_zero;
	using std::popcount;
#else
	template<std::unsigned_integral T>
	constexpr int popcount(T x) noexcept {
		if constexpr (sizeof(T) <= sizeof(unsigned int))
			return __builtin_popcount(static_cast<unsigned int>(x));
		else if constexpr (sizeof(T) <= sizeof(unsigned long))
			return __builtin_popcountl(static_cast<unsigned long>(x));
		else if constexpr (sizeof(T) <= sizeof(unsigned long long))
			return __builtin_popcountll(static_cast<unsigned long long>(x));
		else
			static_assert(always_false<T>::value, "unimplemented");
	}
	template<std::unsigned_integral T>
	constexpr int countr_zero(T x) noexcept {
		if (x == 0) return sizeof(T) * 8;
		if constexpr (sizeof(T) <= sizeof(unsigned int))
			return __builtin_ctz(static_cast<unsigned int>(x));
		else if constexpr (sizeof(T) <= sizeof(unsigned long))
			return __builtin_ctzl(static_cast<unsigned long>(x));
		else if constexpr (sizeof(T) <= sizeof(unsigned long long))
			return __builtin_ctzll(static_cast<unsigned long long>(x));
		else
			static_assert(always_false<T>::value, "unimplemented");
	}
#endif
	/**
     * \brief Dynamic index set
     *
     * Maintains a bitfield of in use indizes allowing for fast search and lookup operations.
     * 
     * \tparam T Unsigned integral (e.g. uint16_t, size_t) to represent indices
     */
	template<std::unsigned_integral T, typename Allocator = std::allocator<uint64_t>>
	class index_set {
		class bit_storage {
		public:
			static constexpr size_t num_elements(size_t bits) noexcept { return (bits / bits_per_element) + ((bits % bits_per_element) == 0 ? 0 : 1); }
			using element_type = typename Allocator::value_type;
			static_assert(std::unsigned_integral<element_type>, "Bitstorage needs to use a unsigned int type");
			static constexpr size_t bits_per_element = sizeof(element_type) * 8;

			constexpr bit_storage(const Allocator& alloc = Allocator{}) noexcept : m_allocator{alloc} {
				memset(&m_data, 0, sizeof(m_data));
				m_data.inplace.size = 0x80;
			}
			~bit_storage() noexcept { clear(); }

			bit_storage(const bit_storage& other) : m_allocator{other.m_allocator} {
				resize_bits(other.bit_size());
				memcpy(data(), other.data(), std::min(byte_size(), other.byte_size()));
			}

			bit_storage(bit_storage&& other) : m_allocator{std::move(other.m_allocator)} {
				memcpy(&m_data, &other.m_data, sizeof(other.m_data));
				memset(&other.m_data, 0, sizeof(other.m_data));
			}

			bit_storage& operator=(const bit_storage& other) {
				m_allocator = other.m_allocator;
				auto size = other.bit_size();
				resize_bits(size);
				memcpy(data(), other.data(), std::min(byte_size(), other.byte_size()));
				return *this;
			}

			bit_storage& operator=(bit_storage&& other) {
				this->clear();
				m_allocator = std::move(other.m_allocator);
				memcpy(&m_data, &other.m_data, sizeof(other.m_data));
				memset(&other.m_data, 0, sizeof(other.m_data));
				return *this;
			}

			void resize_bits(size_t bits, bool shrink = false) {
				if (!shrink && bits < bit_size()) return;
				if (bits <= inplace_bits) {
					// If the storage was external we move it inplace, otherwise do nothing
					if (!is_inplace()) {
						// Cache the storage info cause we will overwrite it in the next step
						auto const old_ptr = m_data.storage.ptr;
						auto const old_elem_size = m_data.storage.size;
						// Zero out the data segment
						memset(&m_data.inplace, 0, sizeof(m_data.inplace));
						// Copy the required data in
						memcpy(&m_data.inplace.buffer, old_ptr, std::min(byte_size(), (bits + 7) / 8));
						// Set the inplace flag
						m_data.inplace.size = 0x80;
						// Everything done, delete the pointer
						if (old_ptr != nullptr) m_allocator.deallocate(old_ptr, old_elem_size);
					}
				} else {
					// Data does not fit into inplace storage, allocate external
					auto elem_size = num_elements(bits);
					auto ptr = m_allocator.allocate(elem_size);
					// Zero out the new data
					memset(ptr, 0, elem_size * sizeof(element_type));
					// Copy in the existing data
					memcpy(ptr, data(), std::min(byte_size(), (bits + 7) / 8));
					// Delete old data if external
					if (!is_inplace() && m_data.storage.ptr != nullptr) m_allocator.deallocate(m_data.storage.ptr, m_data.storage.size);
					// Update references
					m_data.storage.ptr = ptr;
					m_data.storage.size = elem_size;
				}
			}

			void clear() {
				if (!is_inplace() && m_data.storage.ptr != nullptr) m_allocator.deallocate(m_data.storage.ptr, m_data.storage.size);
				memset(&m_data.inplace.buffer, 0, sizeof(m_data.inplace.buffer));
				m_data.inplace.size = 0x80;
			}

			size_t bit_size() const noexcept { return (is_inplace()) ? inplace_bits : (m_data.storage.size * bits_per_element); }
			size_t byte_size() const noexcept { return bit_size() / 8; }
			element_type* data() noexcept { return is_inplace() ? reinterpret_cast<element_type*>(&m_data.inplace.buffer) : m_data.storage.ptr; }
			const element_type* data() const noexcept {
				return is_inplace() ? reinterpret_cast<const element_type*>(&m_data.inplace.buffer) : m_data.storage.ptr;
			}

		private:
			// Size in elements
			union {
				struct {
					uint8_t buffer[sizeof(element_type*) + sizeof(size_t) - sizeof(uint8_t)];
					uint8_t size; // Size and flags
				} inplace{};
				struct {
					element_type* ptr;
					size_t size;
				} storage;
			} m_data;
			[[no_unique_address]] Allocator m_allocator{};
			static constexpr size_t inplace_bits = sizeof(m_data.inplace.buffer) * 8;
			bool is_inplace() const noexcept { return (m_data.inplace.size & 0x80) != 0; }
		};

		size_t m_max_size;
		bit_storage m_storage;
		// Element index to the last allocated or freed index
		size_t m_search_hint{0};

		using element_type = typename bit_storage::element_type;
		static constexpr size_t bits_per_element = bit_storage::bits_per_element;

	public:
		constexpr index_set(size_t max_size = std::numeric_limits<T>::max()) noexcept : m_max_size{max_size}, m_storage{} {}
		constexpr bool index_allocated(T idx) const noexcept {
			if (idx >= m_storage.bit_size()) return false;
			const size_t element = idx / bits_per_element;
			const size_t bit = idx % bits_per_element;
			return (m_storage.data()[element] & (element_type{1} << bit)) != 0;
		}
		constexpr size_t count() const noexcept {
			const size_t elements = bit_storage::num_elements(m_storage.bit_size());
			auto* const data = m_storage.data();
			if (data == nullptr) return 0;
			size_t cnt = 0;
			for (size_t i = 0; i < elements; i++) {
				cnt += popcount(data[i]);
			}
			if ((m_storage.bit_size() % bits_per_element) != 0) {
				const element_type last_element_mask = (element_type{1} << (m_storage.bit_size() % bits_per_element)) - 1;
				cnt -= popcount(data[elements - 1] & ~last_element_mask);
			}
			return cnt;
		}
		T allocate_index() {
			const element_type last_element_mask = (element_type{1} << (m_storage.bit_size() % bits_per_element)) - 1;
			auto* data = m_storage.data();
			const auto elements = bit_storage::num_elements(m_storage.bit_size());
			bool found = false;
			T index{};
			for (size_t i = m_search_hint; i < elements; ++i) {
				if (~(data[i]) == 0) continue;
				auto idx = countr_zero(~(data[i]));
				found = true;
				index = idx + i * bits_per_element;
				break;
			}
			if (!found || index >= m_storage.bit_size()) {
				// Out of area
				auto old_size = m_storage.bit_size();
				auto new_size = std::min(m_max_size, std::max<size_t>(old_size * 1.5, bits_per_element));
				if (new_size <= old_size) throw std::runtime_error("out of indices");
				m_storage.resize_bits(new_size);
				data = m_storage.data();
				data[old_size / bits_per_element] |= (element_type(1) << (old_size % bits_per_element));
				m_search_hint = (old_size + 1) / bits_per_element;
				return old_size;
			} else {
				data[index / bits_per_element] |= (element_type(1) << (index % bits_per_element));
				m_search_hint = (index + 1) / bits_per_element;
				return index;
			}
		}
		void return_index(T idx) noexcept {
			if (idx >= m_storage.bit_size()) return;
			auto* const data = m_storage.data();
			const size_t element = idx / bits_per_element;
			const size_t bit = idx % bits_per_element;
			data[element] &= ~(element_type(1) << bit);
			m_search_hint = std::min(m_search_hint, element);
		}
		void return_all() noexcept {
			const auto size = m_storage.bit_size();
			auto* const data = m_storage.data();
			memset(data, 0, size / 8);
			for (auto i = size & ~size_t(7); i < size; i++) {
				const size_t element = i / bits_per_element;
				const size_t bit = i % bits_per_element;
				data[element] &= ~(element_type(1) << bit);
			}
			m_search_hint = 0;
		}
	};
} // namespace asyncpp::uring
