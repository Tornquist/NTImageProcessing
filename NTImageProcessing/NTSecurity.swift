//
//  NTSecurity.swift
//  NTImageProcessing
//
//  Created by Nathan Tornquist on 3/16/16.
//  Copyright © 2016 Nathan Tornquist. All rights reserved.
//

import Foundation
import Security

class NTSecurity {
    class func secKeyRef(fromBase64Key key: String) -> SecKeyRef? {
        let keyData = NSData(base64EncodedString: key, options: .IgnoreUnknownCharacters)
        guard keyData != nil else {
            return nil
        }
        
        var cert: SecCertificateRef! = nil
        var policy: SecPolicyRef! = nil
        
        cert = SecCertificateCreateWithData(kCFAllocatorDefault, keyData!)
        policy = SecPolicyCreateBasicX509()
        
        var status: OSStatus = OSStatus(noErr)
        var publicKey: SecKeyRef? = nil
        var trust: SecTrustRef? = nil
        let trustType: SecTrustResultType = SecTrustResultType(kSecTrustResultInvalid)
        
        if (cert != nil) {
            // TODO: Verify this should be nil
            status = SecTrustCreateWithCertificates(cert, policy, &trust)
            
            if (status == errSecSuccess){
                status = SecTrustEvaluate(trust!, UnsafeMutablePointer<SecTrustResultType>.alloc(Int(trustType)))
                
                // Evaulate the trust.
                switch Int(Int32(trustType.value)) {
                case kSecTrustResultInvalid:
                    break
// Deprecated
//                case kSecTrustResultConfirm:
//                    break
                case kSecTrustResultDeny:
                    break
                case kSecTrustResultUnspecified:
                    break
                case kSecTrustResultFatalTrustFailure:
                    break
                case kSecTrustResultOtherError:
                    break
                case kSecTrustResultRecoverableTrustFailure:
                    publicKey = SecTrustCopyPublicKey(trust!)
                    break
                case kSecTrustResultProceed:
                    publicKey = SecTrustCopyPublicKey(trust!)
                    break
                }
                
            }
        }
        return publicKey
    }
}