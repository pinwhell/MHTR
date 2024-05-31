#pragma once

#include <Binary/IBinary.h>

class IBinaryProvider {
public:
	virtual ~IBinaryProvider() {}
	virtual IBinary* GetBinary() = 0;
};