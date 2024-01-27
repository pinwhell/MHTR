#pragma once

#include <string>
#include <cstdint>
#include "JsonValueWrapper.h"
#include "ILValueRValueWrapper.h"
#include "INestedLValueRValueWrapper.h"
#include "IChild.h"
#include <OH/IJsonAccesor.h>

#define ERR_INVALID_OFFSET ((uint64_t)~0ull)

class IFutureResult;
struct HeaderFileManager;
class ObfuscationManager;

class IFutureResultInfo : public IChild<IFutureResult>
{ 
private:
	std::string mName;
	std::string mUIdentifier;
	std::string mUIdentifierDynamic;
	std::string mUIdentifierDynamicSalted;
	std::string mUIDHash;
	std::string mComment; // If there is no comment available then this will be empty
	bool mCanPickAnyResult;

protected:
	std::unique_ptr<ILValueRValueWrapper> mStaticResult;
	std::unique_ptr<INestedLValueRValueWrapper> mStructMemberAccessor; // Why nested? well, basicly we need to do, chainig struct
																// objects to be able to modify/acess the desired offset
																// for ex. mA.mB.mC = 0xXYZ;

	uint32_t mObfKey;
	uint32_t mSaltKey;
public:
	IFutureResultInfo();
	virtual ~IFutureResultInfo(){}

	bool Init();

	void setName(const std::string& name);
	void setComment(const std::string& comment);

	const std::string& getName();
	const std::string& getComment();
	std::string getUIDHashStr();
	bool CanPickAnyResult();

	virtual void ReportHppIncludes() {};
	virtual void WriteHppStaticDeclsDefs();
	virtual void WriteHppDynDecls();
	virtual void WriteHppDef();

	virtual void HppRuntimeDecryptionWrite(IJsonAccesor* jsonAccesor);

	HeaderFileManager* getHppWriter();

	bool getNeedShowComment();

	std::string getUidentifier();
	ObfuscationManager* getObfuscationManager();
	virtual void OnParentTargetFinish() {};

	JsonValueWrapper& getMetadata();

	virtual std::string getCppDataType() = 0;
	virtual std::string getCppDefaultRvalue() = 0;




	std::string getUniqueIdentifier();
};
