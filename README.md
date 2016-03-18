# NTSecurity

NTSecurity is an Objective-C/Swift framework designed to easily add support for RSA and AES256 encryption.

**This includes:**

* AES256 Key Generation
* AES256 Encryption/Decryption
* SecKeyRef generation from *.dem file for public RSA keys
* SecKeyRef generation from *.p12 file for private RSA keys
* RSA Encryption/Decryption

# Examples

**Situation:** Sending an image encrypted across the network

```objc
// 1. Generate random aes key
NSString* aesKey = [NTKeyGeneration generateAES256Key];
    
// 2. Encrypt UIImage using aes and random key.
NSData *imageAsData = UIImagePNGRepresentation(self.image]);
NSData *encryptedImageData = [NTAES encryptData:imageAsData withKey:aesKey];

// 3. Encrypt aes key with rsa using public server key.
SecKeyRef publicKey = NULL;
publicKey = [NTKeyGeneration getPublicKeyRefWithName: @"<name of dem key>"];
NSData* aesKeyAsData = [aesKey dataUsingEncoding:NSUTF8StringEncoding];
NSData* encryptedAESKey = [NTRSA encryptData:aesKeyAsData withKey:publicKey];
    
// 4. Send encrypted image and key
//    encryptedAESKey and encryptedImageData
```
    
**Situation:** Receiving an encrypted image from the network

```objc
// 1. Receive encrypted image and key
NSData* receivedAESKey = <Network Activity>;
NSData* receivedImage = <Network Activity>;
    
// 2. Decrypt aes key using private rsa key
SecKeyRef privateKey = NULL;
privateKey = [NTKeyGeneration getPrivateKeyRefWithName: @"<name of p12 key>" andPassword: @"<password for file>"];
NSData* decryptedKeyData = [NTRSA decryptData:receivedAESKey withKey:privateKey];
NSString* decryptedAESKey = [[NSString alloc] initWithData:decryptedKeyData encoding:NSUTF8StringEncoding];
    
// 3. Decrypt image with aes key
NSData *decryptedImageData = [NTAES decryptData:receivedImage withKey:decryptedAESKey];
UIImage *decryptedImage = [UIImage imageWithData:decryptedImageData];
```

# Generate Keys for iOS

*.pem files are the standard format used locally on most unix-based machines.  PEM keys
are generated using ssh-keygen by default.  Apple requires signed keys, so the keys must
be passed within certificate files (dem or p12).  

To generate self-signed certificates using existing PEM keys:

```bash
// 1. Create a certificate signing request with the private key
openssl req -new -key <rsaPrivateKey.pem> -out rsa.csr

// 2. Create a self-signed certificate with the private key and signing request
openssl x509 -req -days 3650 -in rsa.csr -signkey <rsaPRivateKey.pem> -out rsa.crt

// 3. Convert the certificate to DER format: the certificate contains the public key
openssl x509 -outform der -in rsa.crt -out <rsaPublic.der>

// 4. Export the private key and certificate to p12 file
openssl pkcs12 -export -out <rsaPrivate.p12> -inkey rsa -in rsa.crt
```

# License

This project is completely open source and under the MIT license. For full details please see [license.md](LICENSE.md)

# Special Thanks

[Arnaud Thiercelin](https://github.com/athiercelin) - For mentoring and assistance

