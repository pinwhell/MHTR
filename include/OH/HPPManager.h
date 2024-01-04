#pragma once

#include <fstream>
#include <vector>

struct StructDeclarationInfo {
	bool bExtern;
	bool bPointer;
	std::string name;

	StructDeclarationInfo(const std::string& _name, bool bIsPointer = false, bool bIsExtern = false) 
		: bExtern(bIsExtern)
		, bPointer(bIsPointer)
		, name(_name)
	{}
};

struct HeaderFileManager {
	std::ostream* m_Traits;
	uintptr_t	m_TabLevel;
	uintptr_t	m_MacroTabLevel;
	std::unique_ptr<std::ofstream> m_FTraits;

	HeaderFileManager();

	void AppendPragmaOnce();
	void AppendMacroIf();
	void AppendMacroElse();
	void AppendMacroEndIf();
	void AppendMacroDefined(const std::string& macroName);
	void AppendString(const std::string& str);
	void AppendMacroIfDefined(const std::string& macroName, bool bTerminateLine = true);
	void AppendTab();
	void AppendTab(uintptr_t count);
	void AppendConstUintVar(const std::string& name, bool bApplyTabs = false, bool bApplyVal = false, uintptr_t val = 0, bool bJumpNewLine = true);
	void AppendComment(const std::string& comment, bool bJumpNewLine = true);
	void AppendNextLine();
	void AppendGlobalInclude(const std::string& fileName);
	void BeginNameSpace(const std::string& name);
	void BeginStruct(const std::string& name);
	void EndStruct(const std::string& structName, const std::vector<StructDeclarationInfo>& structDecls = std::vector<StructDeclarationInfo>());
	void EndNameSpace(const std::string& name = "");
	void AppendConstExpr(bool bNewLine = false);
	void AppendUintVar(const std::string& varName, bool bApplyTabs = true, bool bApplyVal = false, uintptr_t val = 0, bool bNewLine = true);
	void BeginFunction(const std::string& retType, const std::string& functionName, const std::vector<std::string>& params);
	void EndFunction();
	void AppendLineOfCode(const std::string& loc, bool bApplyTabs = true, bool bNewLine = true);

	void SetTraits(std::ostream* newTrait);
	void Reset();

	void SetOwnFStream(std::unique_ptr<std::ofstream>& fStream);
};