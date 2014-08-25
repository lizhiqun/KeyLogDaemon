//
//  InstallMain.h
//  InstallApp
//
//  Created by WangYongChun on 1/8/14.
//  Copyright (c) 2014 WangYongChun. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface InstallMain : NSWindow {
    
    IBOutlet NSSecureTextField *mPwd;
    IBOutlet NSProgressIndicator    *mProgrs;
}

-(IBAction)install:(id)sender;
- (void)enableLoginItemWithLoginItemsReference:(LSSharedFileListRef )theLoginItemsRefs ForPath:(CFURLRef)thePath;
@end
