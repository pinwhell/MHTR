#pragma once

class ILookable {
public:
	virtual void Lookup() = 0;
	virtual ~ILookable() {}
};