//
//  NTAES.m
//  NTImageProcessing
//
//  Created by Nathan Tornquist on 3/17/16.
//  Copyright © 2016 Nathan Tornquist. All rights reserved.
//

#import "NTAES.h"
//TODO: Identify why this throws an error when included in NTAES.h
#import <CommonCrypto/CommonCryptor.h>

@implementation NTAES

+ (NSData *)encryptData:(NSData *)data withKey:(NSString*)key
{
    // 'key' should be 32 bytes for AES256, will be null-padded otherwise
    char keyPtr[kCCKeySizeAES256 + 1]; // room for terminator (unused)
    bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
    
    // fetch key data
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    // fix for license to work on both ML and MV.
    keyPtr[0] = '\0';
    NSUInteger dataLength = [data length];
    
    //See the doc: For block ciphers, the output size will always be less than or
    //equal to the input size plus the size of one block.
    //That's why we need to add the size of one block here
    size_t bufferSize           = dataLength + kCCBlockSizeAES128;
    void* buffer                = malloc(bufferSize);
    
    size_t numBytesEncrypted    = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCEncrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                          keyPtr, kCCKeySizeAES256,
                                          NULL /* initialization vector (optional) */,
                                          [data bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesEncrypted);
    
    if (cryptStatus == kCCSuccess)
    {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        return [[NSData alloc] initWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    else if (cryptStatus == kCCParamError)
    {
        NSLog(@"- Illegal parameter value.");
    }
    else if (cryptStatus == kCCBufferTooSmall)
    {
        NSLog(@" - Insufficent buffer provided for specified operation.");
    }
    else if (cryptStatus == kCCMemoryFailure)
    {
        NSLog(@" - Memory allocation failure.");
    }
    else if (cryptStatus == kCCAlignmentError)
    {
        NSLog(@" - Input size was not aligned properly.");
    }
    else if (cryptStatus == kCCDecodeError)
    {
        NSLog(@" - Input data did not decode or decrypt properly.");
    }
    else if (cryptStatus == kCCUnimplemented)
    {
        NSLog(@" - Function not implemented for the current algorithm.");
    }
    free(buffer); //free the buffer;
    return nil;
}

+ (NSData *)decryptData:(NSData *)data withKey:(NSString*)key
{
    // 'key' should be 32 bytes for AES256, will be null-padded otherwise
    char keyPtr[kCCKeySizeAES256 + 1]; // room for terminator (unused)
    bzero(keyPtr, sizeof(keyPtr)); // fill with zeroes (for padding)
    
    // fetch key data
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    
    NSUInteger dataLength = [data length];
    
    //See the doc: For block ciphers, the output size will always be less than or
    //equal to the input size plus the size of one block.
    //That's why we need to add the size of one block here
    size_t bufferSize           = dataLength + kCCBlockSizeAES128;
    void* buffer                = malloc(bufferSize);
    
    size_t numBytesDecrypted    = 0;
    CCCryptorStatus cryptStatus = CCCrypt(kCCDecrypt, kCCAlgorithmAES128, kCCOptionPKCS7Padding,
                                          keyPtr, kCCKeySizeAES256,
                                          NULL /* initialization vector (optional) */,
                                          [data bytes], dataLength, /* input */
                                          buffer, bufferSize, /* output */
                                          &numBytesDecrypted);
    
    if (cryptStatus == kCCSuccess)
    {
        //the returned NSData takes ownership of the buffer and will free it on deallocation
        return [[NSData alloc] initWithBytesNoCopy:buffer length:numBytesDecrypted];
    }
    else if (cryptStatus == kCCParamError)
    {
        NSLog(@"- Illegal parameter value.");
    }
    else if (cryptStatus == kCCBufferTooSmall)
    {
        NSLog(@" - Insufficent buffer provided for specified operation.");
    }
    else if (cryptStatus == kCCMemoryFailure)
    {
        NSLog(@" - Memory allocation failure.");
    }
    else if (cryptStatus == kCCAlignmentError)
    {
        NSLog(@" - Input size was not aligned properly.");
    }
    else if (cryptStatus == kCCDecodeError)
    {
        NSLog(@" - Input data did not decode or decrypt properly.");
    }
    else if (cryptStatus == kCCUnimplemented)
    {
        NSLog(@" - Function not implemented for the current algorithm.");
    }
    
    free(buffer); //free the buffer;
    return nil;
}

@end
