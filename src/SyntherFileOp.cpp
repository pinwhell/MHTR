#include <SyntherFileOp.h>
#include <Synther/Utility.h>
#include <File/Operation.h>

void FileWrite(const std::string& path, IMultiLineSynthesizer* multiLineSynther) {
    FileWrite(path, SingleLinefy(multiLineSynther));
}