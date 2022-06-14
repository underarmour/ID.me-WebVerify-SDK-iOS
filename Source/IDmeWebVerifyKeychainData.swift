//
//  IDmeWebVerifyKeychainData.swift
//  IDmeWebVerify
//
//  Created by Eric Miller on 9/16/21.
//  Copyright © 2021 ID.me, Inc. All rights reserved.
//

import Foundation
import KeychainSwift

let IDME_KEYCHAIN_DATA_ACCOUNT = "IDME_KEYCHAIN_DATA"
let IDME_EXPIRATION_DATE = "IDME_EXPIRATION_DATE"
let IDME_REFRESH_EXPIRATION_DATE = "IDME_REFRESH_EXPIRATION_DATE"
let IDME_REFRESH_TOKEN = "IDME_REFRESH_TOKEN"
let IDME_ACCESS_TOKEN = "IDME_ACCESS_TOKEN"
let IDME_SCOPE = "IDME_SCOPE"

public class IDmeWebVerifyKeychainData: NSObject {
    
    private let keychainData: KeychainSwift
    private let dateFormatter: DateFormatter
    private var latestScope: String?
    private var tokensByScope: [String: [String: String]]
    
    public override init() {
        keychainData = KeychainSwift()
        dateFormatter = DateFormatter()
        dateFormatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ssZZZZZ"
        tokensByScope = [:]
        
        super.init()
        
        loadFromKeychain()
    }
    
    public func getLatestUsedScope() -> String? {
        return latestScope
    }
    
    public func accessToken(forScope scope: String) -> String? {
        return tokensByScope[scope]?[IDME_ACCESS_TOKEN]
    }
    
    public func expirationDate(forScope scope: String) -> Date? {
        guard let dateString = tokensByScope[scope]?[IDME_EXPIRATION_DATE] else { return nil }
        return dateFormatter.date(from: dateString)
    }
    
    public func refreshToken(forScope scope: String) -> String? {
        return tokensByScope[scope]?[IDME_REFRESH_TOKEN];
    }
    
    public func refreshExpirationDate(forScope scope: String) -> Date? {
        guard let dateString = tokensByScope[scope]?[IDME_REFRESH_EXPIRATION_DATE] else { return nil }
        return dateFormatter.date(from: dateString)
    }
    
    // TODO: discuss if refreshToken should be nullable
    public func setToken(_ accessToken: String,
                         expirationDate: Date,
                         refreshToken: String,
                         refreshExpDate: Date,
                         forScope scope: String) {
        tokensByScope[scope] = [
            IDME_EXPIRATION_DATE: dateFormatter.string(from: expirationDate),
            IDME_REFRESH_TOKEN: refreshToken,
            IDME_ACCESS_TOKEN: accessToken,
            IDME_REFRESH_EXPIRATION_DATE: dateFormatter.string(from: refreshExpDate)
        ]
        latestScope = scope
        persist()
    }
    
    public func clean() {
        keychainData.delete(IDME_KEYCHAIN_DATA_ACCOUNT)
    }
    
    public func isClean() -> Bool {
        tokensByScope.count == 0
    }
}

private extension IDmeWebVerifyKeychainData {
    func persist() {
        if let data = try? PropertyListSerialization.data(fromPropertyList: tokensByScope,
                                                          format: PropertyListSerialization.PropertyListFormat.xml,
                                                          options:0) {
            keychainData.set(data, forKey: IDME_KEYCHAIN_DATA_ACCOUNT)
        }
    }
    
    func loadFromKeychain() {
        if let data = keychainData.getData(IDME_KEYCHAIN_DATA_ACCOUNT) {
            if let dictionary: [String: [String: String]] = try? PropertyListSerialization.propertyList(
                from: data,
                options: .mutableContainersAndLeaves,
                format: nil) as? [String: [String: String]] {
                var mostRecentDate = Date(timeIntervalSince1970: 0)
                var scope: String? = nil
                for (key, value) in dictionary {
                    if let expDate = value[IDME_EXPIRATION_DATE],
                       let date = dateFormatter.date(from: expDate) {
                        if date.compare(mostRecentDate) == .orderedDescending {
                            mostRecentDate = date
                            scope = key
                        }
                    }
                }
                tokensByScope = dictionary
                latestScope = scope
            }
        }
    }
}
