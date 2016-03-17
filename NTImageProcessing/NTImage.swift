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
    public class func encryptImage(image: UIImage, withKey key: SecKeyRef) -> NSData? {
        let dataToEncrypt = NTImage.dataFromImage(image)
        guard dataToEncrypt != nil else {
            return nil
        }

        return NTSecurity.encryptData(dataToEncrypt!, withKey: key)
    }
    
    /**
     Takes in data, key path, and password and decrypts using RSA.
     Converts resulting data to UIImage.
     */
    public class func decryptData(data:NSData, withKey key: SecKeyRef) -> UIImage? {
        let decryptedData = NTSecurity.decryptData(data, withKey: key)
        guard decryptedData != nil else {
            return nil
        }

        return UIImage(data: decryptedData!)
    }
    
    /**
     Encrypts the image stored within the object with RSA using a given
     key path.
     */
    public func encrypt(withKey key: SecKeyRef) -> NSData? {
        guard self.image != nil else {
            return nil
        }
        return NTImage.encryptImage(self.image!, withKey: key)
    }
    
    /**
     Decrypts the data stored within the object with RSA using a given
     key path and password for the key. Converts the result to a UIImage.
     */
    public func decrypt(withKey key: SecKeyRef) -> UIImage? {
        guard self.data != nil else {
            return nil
        }
        return NTImage.decryptData(self.data!, withKey: key)
    }
    
    // MARK: - Internal Methods
    
    class func dataFromImage(image: UIImage?) -> NSData? {
        guard image != nil else {
            return nil
        }
        return UIImagePNGRepresentation(image!)
    }
}