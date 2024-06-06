#include <iostream>
#include <filesystem>
#include <CLI/MH.h>

int main() {
	std::filesystem::current_path(MHR_SAMPLES_DIR);

	const char* argv[] = {
		""/*Zeroth for dummy file-path*/,
		"-j4",
		"--targets", "targets.json",
		"--report", "test.report.txt",
		"--rhpp", "test.report.hpp"
	};

	try { return MHCLI(sizeof(argv) / sizeof(argv[0]), argv).Run(); } 
	catch (const std::exception& e) { std::cerr << e.what() << std::endl; }

	return -1;
}