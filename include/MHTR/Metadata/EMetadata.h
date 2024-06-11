#pragma once

namespace MHTR {
	enum class EMetadata {
		NONE = -1,
		METADATA_LOOKUP,
		METADATA_SCAN_RANGE
	};

	enum class EMetadataLookup {
		NONE = -1,
		PATTERN_VALIDATE,
		PATTERN_SINGLE_RESULT,
		INSN_IMMEDIATE,
		FAR_ADDRESS,
		HARDCODED
	};

	enum class EMetadataScanRange {
		DEFAULT,
		PIPELINE,
		REFERENCE
	};

	enum class EMetadataScanRangeStage {
		NONE = -1,
		FUNCTION
	};

	enum class EHardcodedMetadata {
		PATTERN,
		OFFSET
	};

	enum class EMetadataResult {
		OFFSET,
		PATTERN
	};
}