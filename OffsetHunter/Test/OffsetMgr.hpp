#pragma once

#include <cstdint>
#include <json/json.h>

struct OffMgr {
#if defined(STATIC_OFFS)
#else

	void Set(Json::Value) {
	}
#endif

} ;
extern OffMgr *gOffMgrOffs;
