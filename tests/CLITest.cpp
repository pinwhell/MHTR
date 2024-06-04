#include "../src/CLI/main.cpp"
#include <doctest/doctest.h>

TEST_CASE("CLI Test") {
	std::filesystem::current_path(MHR_SAMPLES_DIR);

	const char* argv[] = {
		"", "-j4",
		"--targets", "targets.json"
	};

	CHECK_NOTHROW(MHCLI(sizeof(argv) / sizeof(argv[0]), argv).Run());
}