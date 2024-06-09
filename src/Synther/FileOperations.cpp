#include <Synther/FileOperations.h>
#include <Synther/Utility.h>
#include <fstream>

void FileWrite(const std::string& path, IMultiLineSynthesizer* multiLineSynther) {
    std::ofstream outFile(path);

    // Check if the file stream is open
    if (!outFile.is_open()) {
        throw std::runtime_error("Failed to create or open the file at: " + path);
    }

    outFile << SingleLinefy(multiLineSynther);

    // Close the file stream
    outFile.close();

    // Check if there were any write errors
    if (outFile.fail()) {
        throw std::runtime_error("Failed to write content to the file at: " + path);
    }
}