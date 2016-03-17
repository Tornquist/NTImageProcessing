//
//  NTKeyGeneration.m
//  NTImageProcessing
//
//  Created by Nathan Tornquist on 3/17/16.
//  Copyright © 2016 Nathan Tornquist. All rights reserved.
//

#import "NTKeyGeneration.h"

@implementation NTKeyGeneration

+ (SecKeyRef)getPublicKeyRefAtPath:(NSString *)path {
    NSString *resourcePath = [[NSBundle mainBundle] pathForResource:path ofType:@"der"];
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

                //Check the result of the trust evaluation rather than the result of the API invocation.
                if (result == kSecTrustResultProceed || result == kSecTrustResultUnspecified) {
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

+ (SecKeyRef)getPrivateKeyRefAtPath:(NSString *)path withPassword:(NSString *)password {
    NSString *resourcePath = [[NSBundle mainBundle] pathForResource:path ofType:@"p12"];
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

@end