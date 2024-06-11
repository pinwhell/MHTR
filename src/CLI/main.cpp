#include <iostream>

#include <MHTR/CLI/MH.h>

int MHunterMain(int argc, const char** argv)
{
    try { return MHCLI(argc, argv).Run(); }
    catch (const std::exception& e)
    { std::cerr << e.what() << std::endl; return -1; }

    return 0; // we should not get here
}

int main(int argc, const char* argv[]) {
    return MHunterMain(argc, argv);
}