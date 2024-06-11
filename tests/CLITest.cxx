#include <iostream>
#include <filesystem>
#include <MHTR/CLI/MH.h>

using namespace MHTR;

int main(int argc, const char** realArgv) {
	std::filesystem::current_path(MHR_SAMPLES_DIR);

	const char* argv[] = {
		realArgv[0],
		"-j4",
		"--targets", "targets.json",
		"--report", "test.report.txt",
		"--rhpp", "test.report.hpp",
		"--rhpprt", "test.report.rt.hpp"
	};

	try { return MHCLI(sizeof(argv) / sizeof(argv[0]), argv).Run(); } 
	catch (const std::exception& e) { std::cerr << e.what() << std::endl; }

	return -1;
}