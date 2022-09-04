#include <asyncpp/uring/capability_set.h>
#include <gtest/gtest.h>

using namespace asyncpp::uring;

TEST(ASYNCPP_URING, CapabilitySet) {
	capability_set info;
	size_t count = 0;
	for (auto [idx, name, supported] : info) {
		ASSERT_EQ(info.has(idx), supported);
		count++;
	}
	ASSERT_EQ(count, info.size());
	// Nop is always there
	ASSERT_TRUE(info.has(IORING_OP_NOP));
}
