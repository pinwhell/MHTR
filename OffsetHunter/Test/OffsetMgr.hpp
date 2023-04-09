#pragma once

#include <cstdint>
#include <json/json.h>

struct OffMgr {
#if defined(STATIC_OFFS)
#else

	void Set(const Json::Value& obj) {
	}
#endif

} ;
extern OffMgr *gOffMgrOffs;
