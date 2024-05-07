#pragma once

#include <FileView.h>
#include <BufferView.h>

static BufferView BufferViewFromFileView(const FileView& fileView)
{
	return BufferView(fileView, fileView.size());
}