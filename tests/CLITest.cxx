#include <iostream>
#include <filesystem>
#include <CLI/MH.h>

int main() {
	std::filesystem::current_path(MHR_SAMPLES_DIR);

	const char* argv[] = {
		"", "-j4",
		"--targets", "targets.json"
	};

	try { return MHCLI(sizeof(argv) / sizeof(argv[0]), argv).Run(); } 
	catch (const std::exception& e) { std::cerr << e.what() << std::endl; }

	return -1;
}