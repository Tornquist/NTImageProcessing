//
//  NTAES.h
//  NTSecurity
//
//  Created by Nathan Tornquist on 3/17/16.
//  Copyright © 2016 Nathan Tornquist. All rights reserved.
//

@import Foundation;

@interface NTAES : NSObject

+ (NSData *)encryptData:(NSData *)data withKey:(NSString*)key;
+ (NSData *)decryptData:(NSData *)data withKey:(NSString*)key;

@end
