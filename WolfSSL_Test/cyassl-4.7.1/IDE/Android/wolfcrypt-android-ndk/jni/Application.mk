# The ARMv7 is significanly faster due to the use of the hardware FPU
export APP_ABI :=  armeabi-v7a arm64-v8a #armeabi
export ADDRESS_SANITIZER = true
#ifeq ($(ADDRESS_SANITIZER),true)
NDK_TOOLCHAIN_VERSION=clang
APP_CFLAGS += -O1 -g
APP_CPPFLAGS += -Wall -fexceptions -Wno-narrowing -frtti -O1 -g 
APP_STL := c++_shared
#else
#NDK_TOOLCHAIN_VERSION=4.9
#endif


APP_PLATFORM := android-21
APP_CFLAGS += -Wno-error=format-security 
LOCAL_DISABLE_FORMAT_STRING_CHECKS := true
TARGET_DISABLE_FORMAT_STRING_CFLAGS := -Wno-error=format-security
NDK_PROJECT_PATH := $(call my-dir)/
APP_BUILD_SCRIPT := $(call my-dir)/Android.mk


