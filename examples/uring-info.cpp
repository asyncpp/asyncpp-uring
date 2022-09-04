#include <asyncpp/uring/capability_set.h>
#include <asyncpp/uring/io_service.h>

using asyncpp::uring::capability_set;
using asyncpp::uring::io_service;

int main() {
	io_service io;

	std::cout << "Supported features:\n";
	for (int i = 0; i < 32; i++) {
		std::string sname{capability_set::get_feature_name(1 << i)};
		if (sname.empty()) break;
		sname += ":";
		sname.resize(20, ' ');
		std::cout << sname << (io.has_feature(1 << i) ? "YES" : "NO") << "\n";
	}

	std::cout << "\nSupported opcodes:\n";
	for (auto [idx, name, supported] : io.caps()) {
		std::string sname{name};
		sname += ":";
		sname.resize(20, ' ');
		std::cout << sname << (supported ? "YES" : "NO") << "\n";
	}
}
