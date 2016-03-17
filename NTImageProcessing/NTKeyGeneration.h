//
//  NTKeyGeneration.h
//  NTImageProcessing
//
//  Created by Nathan Tornquist on 3/17/16.
//  Copyright © 2016 Nathan Tornquist. All rights reserved.
//

@import Security;
@import Foundation;

@interface NTKeyGeneration : NSObject

+ (SecKeyRef)getPublicKeyRefAtPath:(NSString *)path;
+ (SecKeyRef)getPrivateKeyRefAtPath:(NSString *)path withPassword:(NSString *)password;

@end
