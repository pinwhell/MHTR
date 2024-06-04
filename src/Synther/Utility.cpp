#include <Synther/Utility.h>
#include <sstream>

std::string SingleLinefy(const IMultiLineSynthesizer* contentProvider, const std::string& delimiter) {
    if (!contentProvider) {
        throw std::runtime_error("Content provider is null.");
    }

    // Retrieve content from the content provider
    std::vector<std::string> content = contentProvider->Synth();

    // Join the content into a single line
    std::ostringstream singleLineStream;
    for (size_t i = 0; i < content.size(); ++i) {
        if (i > 0) {
            singleLineStream << delimiter;
        }
        singleLineStream << content[i];
    }

    return singleLineStream.str();
}