//
//  ModeDelegate.h
//  VIntage
//
//  Created by Sean Hess on 11/5/11.
//  Copyright (c) 2011 I.TV. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "HotKeyGroup.h"

@protocol ModeDelegate <NSObject>

-(void)didChangeToGroup:(HotKeyGroup*)group;
-(void)didDeactivate;

@end
