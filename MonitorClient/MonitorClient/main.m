//
//  main.m
//  MonitorClient
//
//  Created by WangYongChun on 12/28/13.
//  Copyright (c) 2013 WangYongChun. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import "LogerMgr.h"

#define MONITOR_DIRECTORY_PATH      @"/var/log/"
#define SERVER_UPLOAD_URL           @"/var/log/"

int main(int argc, const char * argv[])
{
    //return NSApplicationMain(argc, argv);
	@autoreleasepool
    {
        LogerMgr *service = [[LogerMgr alloc] init];
        
        NSRegisterServicesProvider(service, @"LogerMgr");
        [service installService:MONITOR_DIRECTORY_PATH httpUrl:SERVER_UPLOAD_URL];
        
        [[NSRunLoop currentRunLoop] run];
	}
}
