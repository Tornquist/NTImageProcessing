//
//  NTImage.swift
//  NTImageProcessing
//
//  Created by Nathan Tornquist on 3/16/16.
//  Copyright © 2016 Nathan Tornquist. All rights reserved.
//

import Foundation

public class NTImage: NSObject {
    var data: NSData?
    var image: UIImage?
    
    init(withImage image: UIImage) {
        self.image = image
    }
    
    /**
     Takes in image and key path and encrypts using RSA
    */
    public class func encrypt(image: UIImage, withKey key: SecKeyRef) -> NSData? {
        let dataToEncrypt = NTImage.dataFromImage(image)
        guard dataToEncrypt != nil else {
            return nil
        }

        let blockSize = SecKeyGetBlockSize(key)
        let maxChunkSize = blockSize - 11
        
        var decryptedDataAsArray = [UInt8](count: dataToEncrypt!.length / sizeof(UInt8), repeatedValue: 0)
        dataToEncrypt!.getBytes(&decryptedDataAsArray, length: dataToEncrypt!.length)
        
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
            
            let status = SecKeyEncrypt(key, .PKCS1, chunkData, idxEnd-idx, &encryptedDataBuffer, &encryptedDataLength)
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

    /**
     Takes in data, key path, and password and decrypts using RSA.
     Converts resulting data to UIImage.
     */
    public class func decrypt(data:NSData, withKey key: SecKeyRef) -> UIImage? {
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
            
            let status = SecKeyDecrypt(key, .PKCS1, chunkData, idxEnd-idx, &decryptedDataBuffer, &decryptedDataLength)
            if ( status != noErr ) {
                return nil
            }
            let finalData = removePadding(decryptedDataBuffer)
            decryptedData += finalData
            
            idx += blockSize
        }
        
        let decryptedNSData = NSData(bytes: decryptedData, length: decryptedData.count)
        
        return UIImage(data: decryptedNSData)
    }
    
    /**
     Encrypts the image stored within the object with RSA using a given
     key path.
     */
    public func encrypt(withKey key: SecKeyRef) -> NSData? {
        guard self.image != nil else {
            return nil
        }
        return NTImage.encrypt(self.image!, withKey: key)
    }
    
    /**
     Decrypts the data stored within the object with RSA using a given
     key path and password for the key. Converts the result to a UIImage.
     */
    public func decrypt(withKey key: SecKeyRef) -> UIImage? {
        guard self.data != nil else {
            return nil
        }
        return NTImage.decrypt(self.data!, withKey: key)
    }
    
    // MARK: - Internal Methods
    
    class func dataFromImage(image: UIImage?) -> NSData? {
        guard image != nil else {
            return nil
        }
        return UIImagePNGRepresentation(image!)
    }
    
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