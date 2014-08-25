//
//  KeyLogCommon.h
//  KeyLog
//
//  Created by WangYongChun on 1/9/14.
//
//

#ifndef KeyLog_KeyLogCommon_h
#define KeyLog_KeyLogCommon_h

/*
 logKextCommon.h
 logKext
 
 Copyright 2007 Braden Thomas
 
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at
 
 http://www.apache.org/licenses/LICENSE-2.0
 
 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
 */

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
#define KEYMAP_PATH			"/Applications/KeyLogTransferKeymap.plist"
#define LOG_PATH			"/Applications/LogKey.txt"
//#define DEBUG


#endif
