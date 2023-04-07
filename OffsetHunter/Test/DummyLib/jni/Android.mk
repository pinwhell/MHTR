LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_ARM_MODE := arm
LOCAL_LDLIBS := -llog
LOCAL_MODULE := dummy
LOCAL_SRC_FILES := main.c
LOCAL_CFLAGS := -fno-stack-protector -fvisibility=hidden -fno-inline -mno-sse -O0
include $(BUILD_SHARED_LIBRARY)