//
//  NTSecurity.swift
//  NTImageProcessing
//
//  Created by Nathan Tornquist on 3/17/16.
//  Copyright © 2016 Nathan Tornquist. All rights reserved.
//

import Foundation

public class NTSecurity: NSObject {
    public class func encryptData(data: NSData, withKey key: SecKeyRef) -> NSData? {
        let blockSize = SecKeyGetBlockSize(key)
        let maxChunkSize = blockSize
        
        var decryptedDataAsArray = [UInt8](count: data.length / sizeof(UInt8), repeatedValue: 0)
        data.getBytes(&decryptedDataAsArray, length: data.length)
        
        var encryptedData = [UInt8](count: 0, repeatedValue: 0)
        var idx = 0
        while (idx < decryptedDataAsArray.count ) {
            var idxEnd = idx + maxChunkSize
            if ( idxEnd > decryptedDataAsArray.count ) {
                idxEnd = decryptedDataAsArray.count
            }
            var chunkData = [UInt8](count: maxChunkSize, repeatedValue: 0)
            for ( var i = idx; i < idxEnd; i++ ) {
                chunkData[i-idx] = decryptedDataAsArray[i]
            }
            
            var encryptedDataBuffer = [UInt8](count: blockSize, repeatedValue: 0)
            var encryptedDataLength = blockSize
            
            let status = SecKeyEncrypt(key, .OAEP, chunkData, idxEnd-idx, &encryptedDataBuffer, &encryptedDataLength)
            if ( status != noErr ) {
                NSLog("Error while encrypting: %i", status)
                return nil
            }
            //let finalData = removePadding(encryptedDataBuffer)
            encryptedData += encryptedDataBuffer
            
            idx += maxChunkSize
        }
        
        return NSData(bytes: encryptedData, length: encryptedData.count)
    }
    
    public class func decryptData(data: NSData, withKey key: SecKeyRef) -> NSData? {
        let blockSize = SecKeyGetBlockSize(key)
        
        var encryptedDataAsArray = [UInt8](count: data.length / sizeof(UInt8), repeatedValue: 0)
        data.getBytes(&encryptedDataAsArray, length: data.length)
        
        var decryptedData = [UInt8](count: 0, repeatedValue: 0)
        var idx = 0
        while (idx < encryptedDataAsArray.count ) {
            var idxEnd = idx + blockSize
            if ( idxEnd > encryptedDataAsArray.count ) {
                idxEnd = encryptedDataAsArray.count
            }
            var chunkData = [UInt8](count: blockSize, repeatedValue: 0)
            for ( var i = idx; i < idxEnd; i++ ) {
                chunkData[i-idx] = encryptedDataAsArray[i]
            }
            
            var decryptedDataBuffer = [UInt8](count: blockSize, repeatedValue: 0)
            var decryptedDataLength = blockSize
            
            let status = SecKeyDecrypt(key, .OAEP, chunkData, idxEnd-idx, &decryptedDataBuffer, &decryptedDataLength)
            if ( status != noErr ) {
                return nil
            }
            //let finalData = removePadding(decryptedDataBuffer)
//            decryptedData += finalData
            decryptedData += decryptedDataBuffer
            
            idx += blockSize
        }
        
        let decryptedNSData = NSData(bytes: decryptedData, length: decryptedData.count)
        return decryptedNSData
    }
    
    //MARK: - Internal Methods
    
    class func removePadding(data: [UInt8]) -> [UInt8] {
        var idxFirstZero = -1
        var idxNextZero = data.count
        for ( var i = 0; i < data.count; i++ ) {
            if ( data[i] == 0 ) {
                if ( idxFirstZero < 0 ) {
                    idxFirstZero = i
                } else {
                    idxNextZero = i
                    break
                }
            }
        }
        var newData = [UInt8](count: idxNextZero-idxFirstZero-1, repeatedValue: 0)
        for ( var i = idxFirstZero+1; i < idxNextZero; i++ ) {
            newData[i-idxFirstZero-1] = data[i]
        }
        return newData
    }
}