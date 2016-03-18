//
//  NTKeyGeneration.m
//  NTSecurity
//
//  Created by Nathan Tornquist on 3/17/16.
//  Copyright © 2016 Nathan Tornquist. All rights reserved.
//

#import "NTKeyGeneration.h"

@implementation NTKeyGeneration

+ (SecKeyRef)getPublicKeyRefWithName:(NSString *)name {
    NSString *resourcePath = [[NSBundle mainBundle] pathForResource:name ofType:@"der"];
    NSData *certData = [NSData dataWithContentsOfFile:resourcePath];
    SecCertificateRef cert = SecCertificateCreateWithData(NULL, (CFDataRef)certData);
    SecKeyRef key = NULL;
    SecTrustRef trust = NULL;
    SecPolicyRef policy = NULL;
    
    if (cert != NULL) {
        policy = SecPolicyCreateBasicX509();
        if (policy) {
            if (SecTrustCreateWithCertificates((CFTypeRef)cert, policy, &trust) == noErr) {
                SecTrustResultType result;
                SecTrustEvaluate(trust, &result);

                if (result != kSecTrustResultDeny) {
                    // TODO: Verify certificate manually
                    // Because the certificate is self signed, it would need to be manually added
                    // to the trust.  In this case, all certificates will be accepted unless the user
                    // implicitely denied them.  The actual certificate value really isn't important,
                    // and instead is just a way for the public key to be transmitted to the device.
                    // The key value is what matters.
                    key = SecTrustCopyPublicKey(trust);
                }
            }
        }
    }
    if (policy) CFRelease(policy);
    if (trust) CFRelease(trust);
    if (cert) CFRelease(cert);
    return key;
}

+ (SecKeyRef)getPrivateKeyRefWithName:(NSString *)name andPassword:(NSString *)password {
    NSString *resourcePath = [[NSBundle mainBundle] pathForResource:name ofType:@"p12"];
    NSData *p12Data = [NSData dataWithContentsOfFile:resourcePath];
    
    NSMutableDictionary * options = [[NSMutableDictionary alloc] init];
    
    SecKeyRef privateKeyRef = NULL;
    
    [options setObject:password forKey:(id)kSecImportExportPassphrase];
    
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    
    OSStatus securityError = SecPKCS12Import((CFDataRef) p12Data,
                                             (CFDictionaryRef)options, &items);
    
    if (securityError == noErr && CFArrayGetCount(items) > 0) {
        CFDictionaryRef identityDict = CFArrayGetValueAtIndex(items, 0);
        SecIdentityRef identityApp =
        (SecIdentityRef)CFDictionaryGetValue(identityDict,
                                             kSecImportItemIdentity);
        
        securityError = SecIdentityCopyPrivateKey(identityApp, &privateKeyRef);
        if (securityError != noErr) {
            privateKeyRef = NULL;
        }
    }
    CFRelease(items);
    return privateKeyRef;
}

+ (NSString *)generateAES256Key {
    int charCount = 32;
    int passIndex;
    int charIndex;
    
    char *alphaSec = "abcdefghijklmnopqrstuvwxyzABCEDEFGHIJKLMNOPQRSTUVWXYZ1234567890,./?'\"\\|]}[{=+-_)(*&^%$#@!<>:;";
    
    NSMutableString *tempPass = [NSMutableString new];
    NSMutableString *resString = [NSMutableString new];
    
    srandom((unsigned int)time(0));
    
    [resString appendFormat:@"%d - ", passIndex+1];
    
    for (charIndex = 0; charIndex < charCount; charIndex++)
    {
        char randChar = 0;
        
        long randval = random() % strlen(alphaSec);
        randChar = alphaSec[randval];
        
        [tempPass appendFormat:@"%c", randChar];
    }
    [tempPass appendFormat:@"\n"];
    [resString appendString:tempPass];
    [tempPass setString:@""];
    
    return resString;
}

@end