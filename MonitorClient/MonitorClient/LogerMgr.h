//
//  LogerMgr.h
//  MonitorClient
//
//  Created by WangYongChun on 1/7/14.
//  Copyright (c) 2014 WangYongChun. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface LogerMgr : NSObject {
    NSString *mPath;
    NSString *mUrl;
    NSString *mStartTime;
    bool     mbUpdated;
}

-(int)installService:(NSString *)path httpUrl:(NSString *)url;
/*
-(void)updateHandler;
-(int)removesendedFile:(NSString *)path;
*/
@end
