#pragma once

#include <MHTR/Binary/IBinary.h>

namespace MHTR {

	class IBinaryProvider {
	public:
		virtual ~IBinaryProvider() {}
		virtual IBinary* GetBinary() = 0;
	};

}