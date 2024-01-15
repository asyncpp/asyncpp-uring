#include <asyncpp/uring/index_set.h>
#include <asyncpp/fire_and_forget.h>
#include <asyncpp/uring/io_service.h>
#include <cstddef>
#include <cstdint>
#include <gtest/gtest.h>
#include <limits>
#include <stdexcept>
#include <sys/types.h>

using namespace asyncpp::uring;
using namespace asyncpp;

TEST(ASYNCPP_URING, IndexSet) {
	srand(time(nullptr));
	index_set<uint16_t> set{};
	ASSERT_EQ(set.count(), 0);
	for (size_t i = 0; i <= std::numeric_limits<uint16_t>::max(); i++) {
		ASSERT_EQ(set.count(), i);
		ASSERT_FALSE(set.index_allocated(i));
		ASSERT_EQ(set.allocate_index(), i);
		ASSERT_TRUE(set.index_allocated(i));
	}
	ASSERT_EQ(set.count(), std::numeric_limits<uint16_t>::max() + 1);
	ASSERT_THROW(set.allocate_index(), std::runtime_error);
	ASSERT_EQ(set.count(), std::numeric_limits<uint16_t>::max() + 1);
	for (size_t i = 0; i <= std::numeric_limits<uint16_t>::max(); i += 2) {
		ASSERT_TRUE(set.index_allocated(i));
		set.return_index(i);
		ASSERT_FALSE(set.index_allocated(i));
	}
	ASSERT_EQ(set.count(), (std::numeric_limits<uint16_t>::max() + 1) / 2);
	for (size_t i = 0; i <= std::numeric_limits<uint16_t>::max(); i += 2) {
		ASSERT_FALSE(set.index_allocated(i));
		ASSERT_EQ(set.allocate_index(), i);
		ASSERT_TRUE(set.index_allocated(i));
	}
	ASSERT_EQ(set.count(), std::numeric_limits<uint16_t>::max() + 1);
	ASSERT_THROW(set.allocate_index(), std::runtime_error);
	ASSERT_EQ(set.count(), std::numeric_limits<uint16_t>::max() + 1);
	std::set<uint16_t> random = {};
	while (random.size() < 100)
		random.insert(rand());
	for (auto i : random) {
		ASSERT_TRUE(set.index_allocated(i));
		set.return_index(i);
		ASSERT_FALSE(set.index_allocated(i));
	}
	ASSERT_EQ(set.count(), std::numeric_limits<uint16_t>::max() + 1 - 100);
	for (auto i : random) {
		ASSERT_FALSE(set.index_allocated(i));
		ASSERT_EQ(set.allocate_index(), i);
		ASSERT_TRUE(set.index_allocated(i));
	}
	ASSERT_EQ(set.count(), std::numeric_limits<uint16_t>::max() + 1);
	ASSERT_THROW(set.allocate_index(), std::runtime_error);
	ASSERT_EQ(set.count(), std::numeric_limits<uint16_t>::max() + 1);

	set.return_all();
	ASSERT_EQ(set.count(), 0);
}

TEST(ASYNCPP_URING, IndexSetCopy) {
	index_set<uint16_t> set{};
	for (size_t i = 0; i <= 10000; i++) {
		ASSERT_EQ(set.count(), i);
		ASSERT_FALSE(set.index_allocated(i));
		ASSERT_EQ(set.allocate_index(), i);
		ASSERT_TRUE(set.index_allocated(i));
	}
	for (size_t i = 0; i <= 10000; i += 3) {
		set.return_index(i);
	}
	// Copy constructor
	index_set<uint16_t> set2{set};
	ASSERT_EQ(set.count(), set2.count());
	for (size_t i = 0; i <= 10000; i++) {
		if (i % 3)
			ASSERT_TRUE(set2.index_allocated(i));
		else
			ASSERT_FALSE(set2.index_allocated(i));
	}
	// Copy assignment
	index_set<uint16_t> set3;
	ASSERT_EQ(set3.count(), 0);
	set3 = set;
	ASSERT_EQ(set.count(), set3.count());
	for (size_t i = 0; i <= 10000; i++) {
		if (i % 3)
			ASSERT_TRUE(set3.index_allocated(i));
		else
			ASSERT_FALSE(set3.index_allocated(i));
	}
	// Move constructor
	index_set<uint16_t> set4{std::move(set)};
	ASSERT_EQ(set.count(), 0);
	ASSERT_EQ(set2.count(), set4.count());
	for (size_t i = 0; i <= 10000; i++) {
		if (i % 3)
			ASSERT_TRUE(set4.index_allocated(i));
		else
			ASSERT_FALSE(set4.index_allocated(i));
	}
	// Move assignment
	index_set<uint16_t> set5;
	ASSERT_EQ(set5.count(), 0);
	for (size_t i = 0; i <= 1000; i++) {
		set5.allocate_index();
	}
	set5 = std::move(set2);
	ASSERT_EQ(set3.count(), set5.count());
	for (size_t i = 0; i <= 10000; i++) {
		if (i % 3)
			ASSERT_TRUE(set5.index_allocated(i));
		else
			ASSERT_FALSE(set5.index_allocated(i));
	}
}

TEST(ASYNCPP_URING, IndexSetSBO) {
	struct fail_allocator {
		using value_type = uint64_t;
		void deallocate([[maybe_unused]] uint64_t* p, [[maybe_unused]] std::size_t n) { throw std::logic_error("attempt to deallocate"); }
		[[nodiscard]] uint64_t* allocate([[maybe_unused]] std::size_t n) { throw std::logic_error("attempt to allocate"); }
	};
	index_set<uint16_t, fail_allocator> set{};
	for (size_t i = 0; i <= 16; i++) {
		ASSERT_EQ(set.count(), i);
		ASSERT_FALSE(set.index_allocated(i));
		ASSERT_EQ(set.allocate_index(), i);
		ASSERT_TRUE(set.index_allocated(i));
	}
	for (size_t i = 0; i <= 16; i += 3) {
		set.return_index(i);
	}
	// Copy constructor
	index_set<uint16_t, fail_allocator> set2{set};
	ASSERT_EQ(set.count(), set2.count());
	for (size_t i = 0; i <= 16; i++) {
		if (i % 3)
			ASSERT_TRUE(set2.index_allocated(i));
		else
			ASSERT_FALSE(set2.index_allocated(i));
	}
	// Copy assignment
	index_set<uint16_t, fail_allocator> set3;
	ASSERT_EQ(set3.count(), 0);
	set3 = set;
	ASSERT_EQ(set.count(), set3.count());
	for (size_t i = 0; i <= 16; i++) {
		if (i % 3)
			ASSERT_TRUE(set3.index_allocated(i));
		else
			ASSERT_FALSE(set3.index_allocated(i));
	}
	// Move constructor
	index_set<uint16_t, fail_allocator> set4{std::move(set)};
	ASSERT_EQ(set.count(), 0);
	ASSERT_EQ(set2.count(), set4.count());
	for (size_t i = 0; i <= 16; i++) {
		if (i % 3)
			ASSERT_TRUE(set4.index_allocated(i));
		else
			ASSERT_FALSE(set4.index_allocated(i));
	}
	// Move assignment
	index_set<uint16_t, fail_allocator> set5;
	ASSERT_EQ(set5.count(), 0);
	for (size_t i = 0; i <= 16; i++) {
		set5.allocate_index();
	}
	set5 = std::move(set2);
	ASSERT_EQ(set3.count(), set5.count());
	for (size_t i = 0; i <= 16; i++) {
		if (i % 3)
			ASSERT_TRUE(set5.index_allocated(i));
		else
			ASSERT_FALSE(set5.index_allocated(i));
	}
}
