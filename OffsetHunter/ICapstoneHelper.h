#pragma once

#include <capstone/capstone.h>

class ICapstoneHelper
{
private:
	csh mHandle;

	cs_arch mArch;
	cs_mode mMode;
public:
	ICapstoneHelper();

	virtual bool Init();

	void setArch(cs_arch arch);
	void setMode(cs_mode mode);
};

