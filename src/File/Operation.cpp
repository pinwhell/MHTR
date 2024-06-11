#include <fstream>
#include <MHTR/File/Operation.h>

using namespace MHTR;

void FileWrite(const std::string& path, const std::string& fullContent) {
    std::ofstream outFile(path);

    // Check if the file stream is open
    if (!outFile.is_open()) {
        throw std::runtime_error("Failed to create or open the file at: " + path);
    }

    outFile << fullContent;

    // Close the file stream
    outFile.close();

    // Check if there were any write errors
    if (outFile.fail()) {
        throw std::runtime_error("Failed to write content to the file at: " + path);
    }
}