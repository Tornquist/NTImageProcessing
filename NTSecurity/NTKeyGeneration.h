//
//  NTKeyGeneration.h
//  NTSecurity
//
//  Created by Nathan Tornquist on 3/17/16.
//  Copyright © 2016 Nathan Tornquist. All rights reserved.
//

@import Security;
@import Foundation;

@interface NTKeyGeneration : NSObject

+ (SecKeyRef)getPublicKeyRefWithName:(NSString *)name;
+ (SecKeyRef)getPrivateKeyRefWithName:(NSString *)name andPassword:(NSString *)password;
+ (NSString *)generateAES256Key;

@end
