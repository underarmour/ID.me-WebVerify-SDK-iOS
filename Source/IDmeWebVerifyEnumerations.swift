//
//  IDmeWebVerifyEnumerations.swift
//  IDmeWebVerify
//
//  Created by Eric Miller on 9/16/21.
//  Copyright © 2021 ID.me, Inc. All rights reserved.
//

import Foundation

/// This typedef differentiates errors that may occur when authentication a user
public enum IDmeWebVerifyErrorCode: Int {
    /**
     * Error occurs if user succesfully verified their group affiliation, but there was a
     * problem with the user's profile being returned.
     * This should never occur, but this error was added to handle a rare situation involving
     * the inability to reach ID.me's server.
     */
    case verificationDidFailToFetchUserProfile = 1001
    
    /// Error occurs if user succesfully verified their group affiliation, but decided
    /// to deny access to your app at the end of the OAuth flow.
    case verificationWasDeniedByUser = 1002
    
    /// Error occurs if user exits modal navigation controller before OAuth flow could complete.
    case verificationWasCanceledByUser = 1003
    
    /// Error occurs if user authentication fails without the user cancelling the process.
    case authenticationFailed = 1004
    
    /// Error occurs if getUserProfileWithScope:result: or getAccessTokenWithScope:forceRefreshing:result:
    /// are called with a scope that has no access token associated.
    case noSuchScope = 1005
    
    /// Error thrown when there is no valid token or when a response status code is 401.
    case notAuthorized = 1006
    
    /// Error thrown when there is an error refreshing the requested access token
    case refreshTokenFailed = 1007
    
    /// Error thrown when the refresh token has expired
    case refreshTokenExpired = 1008
    
    /// Error thrown for not implemented features like token refreshing.
    case notImplemented = 1009
    
    /// Error thrown when an invalid or unknown response type is received.
    case invalidResponseType = 1010
}

/// This enum defines the different connections that a user can connect to.
///  Used to login to the different platforms
public enum IDmeWebVerifyConnection: Int {
    case facebook
    case googlePlus
    case linkedin
    case paypal
    
    func toString() -> String {
        switch self {
        case .facebook: return "facebook"
        case .googlePlus: return "google"
        case .linkedin: return "linkedin"
        case .paypal: return "paypal"
        }
    }
}

/// This enum defines the different IDs that a user can connect to their account.
public enum IDmeWebVerifyAffiliation: Int {
    case government
    case military
    case responder
    case student
    case teacher
    
    func toString() -> String {
        switch self {
        case .government: return "government"
        case .military: return "military"
        case .responder: return "responder"
        case .student: return "student"
        case .teacher: return "teacher"
        }
    }
}

/// This enum defines the desired action, either sign-in or sign-up.
public enum IDmeWebVerifyLoginType: Int {
    case signUp
    case signIn
    
    func toString() -> String {
        switch self {
        case .signUp: return "signup"
        case .signIn: return "signin"
        }
    }
}
