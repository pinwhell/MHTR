#pragma once

#include <FileView.h>
#include <BufferView.h>

class FileBufferView : public IRelativeDispProvider {
public:
	inline FileBufferView(const char* filePath)
		: mFileView(filePath)
		, mBufferView(BufferView(mFileView, mFileView.size()))
	{}

	inline uint64_t OffsetFromBase(uint64_t what) const override {
		return mBufferView.OffsetFromBase(what);
	}

private:
	FileView mFileView;
public:
	BufferView mBufferView;	
};