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
     Takes in image and key and encrypts using RSA
    */
    public class func encrypt(image: UIImage, withKey: String) -> NSData {
        return NSData()
    }

    /**
     Takes in data and key and decrypts using RSA.  Converts resulting
     data to UIImage.
     */
    public class func decrypt(data:NSData, withKey: String) -> UIImage {
        return UIImage()
    }
    
    /**
     Encrypts the image stored within the object with RSA using a given
     key string.
     */
    public func encrypt(withKey key: String) -> NSData? {
        guard self.image != nil else {
            return nil
        }
        return NTImage.encrypt(self.image!, withKey: key)
    }
    
    /**
     Decrypts the data stored within the object with RSA using a given
     key string. Converts the result to a UIImage.
     */
    public func decrypt(withKey key: String) -> UIImage? {
        guard self.data != nil else {
            return nil
        }
        return NTImage.decrypt(self.data!, withKey: key)
    }
}