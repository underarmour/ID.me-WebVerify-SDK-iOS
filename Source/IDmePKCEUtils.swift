//
//  IDmePKCEUtils.swift
//  IDmeWebVerify
//
//  Created by Eric Miller on 9/16/21.
//  Copyright © 2021 ID.me, Inc. All rights reserved.
//

import Foundation
import CommonCrypto

public class IDmePKCEUtils: NSObject {
    
    public func encodeBase64(_ data: Data) -> String {
        let encoded = data.base64EncodedString(options: .lineLength64Characters)
        let encodedDash = encoded.replacingOccurrences(of: "+", with: "-")
        let encodedUnderscore = encodedDash.replacingOccurrences(of: "/", with: "_")
        let encodedEquals = encodedUnderscore.replacingOccurrences(of: "=", with: "")
        return encodedEquals
    }
    
    public func generateCodeVerifier(withSize size: Int) -> String? {
        var data = Data(count: size)
        let result = data.withUnsafeMutableBytes { mutableBytes in
            SecRandomCopyBytes(kSecRandomDefault, size, mutableBytes)
        }
        
        return result == errSecSuccess ? encodeBase64(data) : nil
    }
    
    public func sha256(_ string: String) -> Data {
        let data = string.data(using: .utf8)!
        var hash =  [UInt8](repeating: 0, count: Int(UInt(CC_SHA256_DIGEST_LENGTH)))
        data.withUnsafeBytes { d in
            _ = CC_SHA256(d, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }
}
