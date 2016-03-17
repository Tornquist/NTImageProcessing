//
//  NTImage.swift
//  NTImageProcessing
//
//  Created by Nathan Tornquist on 3/16/16.
//  Copyright © 2016 Nathan Tornquist. All rights reserved.
//

import Foundation

public class NTImage {
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
        let cipherText: UnsafeMutablePointer<UInt8> = nil
        let cipherTextLength: UnsafeMutablePointer<Int> = nil
        let res = SecKeyEncrypt(key, .PKCS1, UnsafePointer(dataToEncrypt!.bytes), dataToEncrypt!.length, cipherText, cipherTextLength)
        NSLog("\(res)")
        NSLog("\(cipherText)")
        NSLog("\(cipherTextLength)")
        return NSData()
    }

    /**
     Takes in data, key path, and password and decrypts using RSA.
     Converts resulting data to UIImage.
     */
    public class func decrypt(data:NSData, withKey key: SecKeyRef) -> UIImage {
        return UIImage()
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
}