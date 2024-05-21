#pragma once

#include <FileView.h>
#include <BufferView.h>

class FileBufferView : public IRelativeDispProvider, public IRangeProvider {
public:
	inline FileBufferView(const char* filePath)
		: mFileView(filePath)
		, mBufferView(BufferView(mFileView, mFileView.size()))
	{}

	inline uint64_t OffsetFromBase(uint64_t what) const override {
		return mBufferView.OffsetFromBase(what);
	}

	inline BufferView GetRange() override {
		return mBufferView;
	}

private:
	FileView mFileView;
public:
	BufferView mBufferView;	
};