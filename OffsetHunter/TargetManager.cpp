#include "TargetManager.h"
#include "FileHelper.h"
#include "DumpTargetGroup.h"
#include <iostream>
#include "JsonAccesorClassifier.h"
#include "OffsetHunter.h"

TargetManager::TargetManager()
{
	mObfucationManager = std::make_unique<ObfuscationManager>();
	mHppWriter = std::make_unique<HeaderFileManager>();

	mHppWriter->SetTraits(&std::cout);

	mDynamicJsonObjName = "obj"; // By default
	mDynamicOffsetSetterFuncName = "Set"; // By default
}

bool TargetManager::Init()
{
	if (FileHelper::IsValidFilePath(mDumpTargetsPath, true, true) == false)
		return false;

	if (JsonHelper::File2Json(mDumpTargetsPath, mDumpTargetsRoot) == false)
	{
		printf("Unable to parse DUmp Targets\n");
		return false;
	}

	if (mDumpDynamic)
	{
		if (JsonAccesorClassifier::Classify(mDumpJsonLibName, mJsonAccesor) == false)
		{
			printf("\"%s\" Library mistyped or not supported\n", mDumpJsonLibName.c_str());
			return false;
		}

		mJsonAccesor->setJsonObjectName(mDynamicJsonObjName);
	}

	if (getDumpDynamic())
	{
		mObfucationManager->setPath(mObfuscationBookPath);
		mObfucationManager->setParent(this);
		mObfucationManager->setObfInfoMutationEnabled(mObfuscationBookMutationEnabled);

		if (mObfucationManager->Init() == false)
			return false;
	}

	if (ReadAllTargets() == false)
		return false;

	if (InitAllTargets() == false)
		return false;

	if (mHppOutputPath.empty() == false)
	{
		std::unique_ptr<std::ofstream> mHppOutputFile = std::make_unique<std::ofstream>(mHppOutputPath);

		if (mHppOutputFile->is_open() == false)
		{
			printf("Unable to open/create \"%s\"\n", mHppOutputPath.c_str());
			return false;
		}

		mHppWriter->SetOwnFStream(mHppOutputFile);
	}

	return true;
}

bool TargetManager::InitAllTargets()
{
	for (const auto& kv : mAllTargets)
	{
		if (kv.second->Init() == false)
			return false;
	}

	return true;
}

void TargetManager::ComputeAll()
{
	for (const auto& kv : mAllTargets)
		kv.second->ComputeAll();
}

bool TargetManager::SaveResults()
{
	if (SaveHpp() == false)
		return false;
	
	if (getDumpDynamic())
	{
		if (SaveJson() == false)
			return false;
	}

	mObfucationManager->Export();

	return true;
}

bool TargetManager::SaveJson()
{
	bool bSucess = false;

	for (const auto& kv : mAllTargets)
	{
		bool bCurrentResult = false;

		kv.second->ComputeJsonResult();

		if ((bCurrentResult = kv.second->SaveResultJsonToFile()) == false)
			printf("Unable to save json offsets result for %s\n", kv.second->getMacro().c_str());

		bSucess = bSucess || bCurrentResult;
	}

	return bSucess;
}

bool TargetManager::SaveHpp()
{
	mHppWriter->AppendPragmaOnce();
	mHppWriter->AppendGlobalInclude("cstdint");

	if (mDumpDynamic)
		mHppWriter->AppendGlobalInclude(mJsonAccesor->getGlobalInclude());

	mHppWriter->AppendNextLine();

	mHppWriter->BeginStruct(mMainCategoryName);

	/*Inside the struct*/
	
	mHppWriter->AppendMacroIfDefined("STATIC_OFFS");

	WriteHppStaticDeclsDefs();

	// Generate Declaration-Definition here staticly 

	if (mDumpDynamic)
	{
		mHppWriter->AppendMacroElse();
		/*Generate Declaration-only here*/

		WriteHppDynDecls();

		mHppWriter->BeginFunction("void", mDynamicOffsetSetterFuncName, { "const " + mJsonAccesor->getJsonObjFullType() + "& " + mDynamicJsonObjName });
		/*Generate Definition-only here*/
		
		WriteHppDynDefs();

		mHppWriter->EndFunction();

	}

	mHppWriter->AppendMacroEndIf();
	/*Outside the struct*/
	
	std::vector<StructDeclarationInfo> decls;

	if (mDeclareDumpObject)
		decls.push_back(StructDeclarationInfo(mGlobalDumpObjName, true, true));

	mHppWriter->EndStruct(mMainCategoryName, decls);

	return true;
}

void TargetManager::RemoveTarget(DumpTargetGroup* target)
{
	if (mAllTargets.find(target) == mAllTargets.end())
		return;

	mAllTargets.erase(target);
}

void TargetManager::AddTarget(std::unique_ptr<DumpTargetGroup>& target)
{
	DumpTargetGroup* pDumpTarget = target.get();

	if (mAllTargets.find(pDumpTarget) != mAllTargets.end())
		return;

	mAllTargets[pDumpTarget] = std::move(target);
}

void TargetManager::setDumpTargetPath(const std::string& path)
{
	mDumpTargetsPath = path;
}

void TargetManager::setMainCategoryName(const std::string& mainCategoryName)
{
	mMainCategoryName = mainCategoryName;
}

void TargetManager::setHppOutputPath(const std::string& outputPath)
{
	mHppOutputPath = outputPath;
}

bool TargetManager::ReadAllTargets()
{
	if (mDumpTargetsRoot.isArray() == false)
	{
		printf("Unexpected Format of the \"%s\"\n", mDumpTargetsPath.c_str());
		return false;
	}

	for (size_t i = 0; i < mDumpTargetsRoot.size(); i++) // All Targets
	{
		JsonValueWrapper curr(mDumpTargetsRoot[i]);

		HandleTargetGroupJson(curr);
	}

	return true;
}

bool TargetManager::HandleTargetGroupJson(const JsonValueWrapper& targetGroupRoot)
{

	if (JSON_ASSERT(targetGroupRoot, "targets") == false)
		return false;

	if (JSON_ASSERT_STR_EMPTY(targetGroupRoot, "macro") == false)
	{
		printf("\"macro\" Not present or empty in \"%s\" Targets config\n", mDumpTargetsPath.c_str());
		return false;
	}

	std::unique_ptr<DumpTargetGroup> targetGroup = std::make_unique<DumpTargetGroup>();

	targetGroup->setTargetManager(this);
	targetGroup->setDumpTargetDescJson(targetGroupRoot);
	targetGroup->setParent(this);
	targetGroup->setTargetJsonPath(mDumpTargetsPath);

	AddTarget(targetGroup);

	return true;
}

HeaderFileManager* TargetManager::getHppWriter()
{
	return mHppWriter.get();
}

void TargetManager::setObfuscationBookMutationEnabled(bool b)
{
	mObfuscationBookMutationEnabled = b;
}

void TargetManager::setDumpDynamic(bool b)
{
	mDumpDynamic = b;
}

void TargetManager::setDeclareGlobalDumpObj(bool b)
{
	mDeclareDumpObject = b;
}

void TargetManager::setGlobalDumpObjectName(const std::string& globalObjName)
{
	mGlobalDumpObjName = globalObjName;
}

void TargetManager::setJsonAccesor(std::unique_ptr<IJsonAccesor>&& accesor)
{
	mJsonAccesor = std::move(accesor);
}

IJsonAccesor* TargetManager::getJsonAccesor()
{
	return mJsonAccesor.get();
}

void TargetManager::setDumpJsonLibName(const std::string& dumpJsonLibName)
{
	mDumpJsonLibName = dumpJsonLibName;
}

bool TargetManager::getDumpDynamic()
{
	return mDumpDynamic;
}

void TargetManager::setDynamicOffsetSetterFuncName(const std::string& dynamicOffsetSetterFuncName)
{
	mDynamicOffsetSetterFuncName = dynamicOffsetSetterFuncName;
}

void TargetManager::setObfuscationBookPath(const std::string& obfuscationBookPath)
{
	mObfuscationBookPath = obfuscationBookPath;
}

void TargetManager::WriteHppStaticDeclsDefs()
{
	for (const auto& kv : mAllTargets)
		kv.second->WriteHppStaticDeclsDefs();
}

void TargetManager::WriteHppDynDecls()
{
	for (const auto& kv : mAllTargets)
		kv.second->WriteHppDynDecls();
}

void TargetManager::WriteHppDynDefs()
{
	for (const auto& kv : mAllTargets)
		kv.second->WriteHppDynDefs();
}

CapstoneHelperProvider* TargetManager::getCapstoneHelperProvider()
{
	return mParent->getCapstoneHelperProvider();
}

ObfuscationManager* TargetManager::getObfuscationManager()
{
	return mObfucationManager.get();
}
