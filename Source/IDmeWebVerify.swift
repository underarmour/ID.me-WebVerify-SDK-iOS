//
//  IDmeWebVerify.swift
//  IDmeWebVerify
//
//  Created by Eric Miller on 9/16/21.
//  Copyright © 2021 ID.me, Inc. All rights reserved.
//

import UIKit
import SafariServices

let IDME_WEB_VERIFY_VERIFICATION_WAS_CANCELED = "The user exited the modal navigationController before being verified."
let IDME_WEB_VERIFY_VERIFICATION_FAILED = "Authorization process failed."
let IDME_WEB_VERIFY_REFRESH_TOKEN_FAILED = "Refreshing the access token failed."
let IDME_WEB_VERIFY_REFRESH_TOKEN_EXPIRED = "The refresh token has expired."
let IDME_WEB_VERIFY_ERROR_DOMAIN = "ID.me Web Verify Error Domain"

public typealias IDmeVerifyWebVerifyProfileResults = (([AnyHashable: Any]?, NSError?) -> Void)
public typealias IDmeVerifyWebVerifyTokenResults = ((String?, NSError?) -> Void)
private typealias RequestCompletion = ((Data?, URLResponse?, Error?) -> Void)

open class IDmeWebVerify: NSObject {
    
    /// The ID.me WebVerify Singleton
    public static let shared = IDmeWebVerify()
    public class func sharedInstance() -> IDmeWebVerify {
        return IDmeWebVerify.shared
    }
    
    open var showCancelButton: Bool
    open var errorPageTitle: String?
    open var errorPageDescription: String?
    open var errorPageRetryAction: String?
    
    private let keychainData: IDmeWebVerifyKeychainData
    private let reachability: IDmeReachability
    private var safariViewController: SFSafariViewController?
    private var webVerificationResults: IDmeVerifyWebVerifyTokenResults?
    private var logoutCallback: (() -> Void)?
    private var pendingRefreshes: [AnyHashable: [IDmeVerifyWebVerifyTokenResults]]
    private let BASE_URL: String
    private var requestScope: String?
    private var clientID: String!
    private var clientSecret: String!
    private var redirectURI: String!
    private var codeVerifier: String?
    private var codeChallenge: String?
    private var codeChallengeMethod: String?
    private let refreshSerialQueue: DispatchQueue
    private let requestSerialQueue: DispatchQueue
    
    private struct Constants {
        /// API (Production)
        static let IDME_WEB_VERIFY_GET_AUTH_URI = "oauth/authorize?client_id=%@&redirect_uri=%@&response_type=code&scope=%@"
        static let IDME_WEB_VERIFY_GET_USER_PROFILE = "api/public/v2/data.json?access_token=%@"
        static let IDME_WEB_VERIFY_REFRESH_CODE_URL = "oauth/token"
        static let IDME_WEB_VERIFY_REGISTER_CONNECTION_URI = "oauth/authorize?client_id=%@&redirect_uri=%@&response_type=code&op=signin&scope=%@&connect=%@"
        static let IDME_WEB_VERIFY_REGISTER_AFFILIATION_URI = "oauth/authorize?client_id=%@&redirect_uri=%@&response_type=code&scope=%@"
        static let IDME_WEB_VERIFY_SIGN_UP_OR_LOGIN = "oauth/authorize?client_id=%@&redirect_uri=%@&response_type=code&scope=%@&op=%@"
        static let IDME_WEB_VERIFY_LOGOUT_PATH = "oauth/logout?client_id=%@&redirect_uri=%@%%3Ftype%%3Dlogout"
        
        /// Data
        static let IDME_WEB_VERIFY_ACCESS_TOKEN_PARAM = "access_token"
        static let IDME_WEB_VERIFY_EXPIRATION_PARAM = "expires_in"
        static let IDME_WEB_VERIFY_REFRESH_EXPIRATION_PARAM = "refresh_expires_in"
        static let IDME_WEB_VERIFY_REFRESH_TOKEN_PARAM = "refresh_token"
        static let IDME_WEB_VERIFY_ACCESS_DENIED_ERROR = "access_denied"
        static let IDME_WEB_VERIFY_ERROR_DESCRIPTION_PARAM = "error_description"
        static let IDME_WEB_VERIFY_ERROR_PARAM = "error"
        
        /// HTTP Methods
        static let POST_METHOD = "POST"
        
        /// Color
        static let kIDmeWebVerifyColorBlue = UIColor(red: 48.0/255.0,
                                                     green: 160.0/255.0,
                                                     blue: 224.0/255.0,
                                                     alpha: 1.0)
        
        /// PKCE
        static let CODE_VERIFIER_SIZE = 64
        static let CODE_CHALLENGE_METHOD = "S256"
    }
    
    public override init() {
        self.keychainData = IDmeWebVerifyKeychainData()
        self.showCancelButton = true
        self.pendingRefreshes = [:]
        self.errorPageTitle = NSLocalizedString("Unavailable",
                                                comment: "IDme WebVerify SDK disconnected page title")
        self.errorPageDescription = NSLocalizedString("ID.me Wallet requires an internet connection.",
                                                      comment: "IDme WebVerify SDK disconnected page description")
        self.errorPageRetryAction = NSLocalizedString("Retry",
                                                      comment: "IDme WebVerify SDK disconnected page retry action")
        self.reachability = try! IDmeReachability()
        
        self.BASE_URL = (Bundle.main.infoDictionary?["IDmeWebVerifyAPIDomainURL"] as? String) ?? "https://api.id.me/"
        
        self.refreshSerialQueue = DispatchQueue(label: "me.id.IDmeWebVerify.refreshQueue")
        self.requestSerialQueue = DispatchQueue(label: "me.id.IDmeWebVerify.requestQueue")
        
        super.init()
    }
    
    /**
     - Parameter clientID: The clientID provided by ID.me when registering the app
     at **http://developer.id.me**
     - Parameter redirectURI: The redirectURI provided to ID.me when registering your app
     at **http://developer.id.me**
     */
    public static func initialize(withClientID clientID: String,
                                  clientSecret: String,
                                  redirectURI: String) {
        assert(IDmeWebVerify.shared.clientID == nil, "You cannot initialize IDmeWebVerify more than once.")
        IDmeWebVerify.shared.clientID = clientID
        IDmeWebVerify.shared.clientSecret = clientSecret
        IDmeWebVerify.shared.redirectURI = redirectURI
    }
    
    /**
     - Parameter externalViewController: The viewController which will present the modal navigationController
     
     - Parameter scope: The type of group verification that should be presented.
     - Parameter webVerificationResults: A block that returns an NSString object representing a valid access token or an NSError object.
     */
    public func verifyUser(in externalViewController: UIViewController,
                           scope: String,
                           callback: @escaping IDmeVerifyWebVerifyTokenResults) {
        assert(clientID != nil, "You should initialize the SDK before making requests. Call IDmeWebVerify.initializeWithClientID:redirectURI")
        assert(isAuthenticationFlowInProgress() == false, "There is an authentication flow in progress. You should not call IDmeWebVerify.verifyUserInViewController:scope:withTokenResult until the previous has finished")
        
        let authUrlString = urlString(with: Constants.IDME_WEB_VERIFY_GET_AUTH_URI)
        let formattedUrlString = String(format: authUrlString, clientID, redirectURI, scope)
        if let urlString = createAndAddPKCEParameters(to: formattedUrlString) {
            let url = URL(string: urlString)
            launchSafari(from: externalViewController, url: url)
            requestScope = scope
            self.webVerificationResults = callback
        }
    }
    
    /**
     This function should be used if it is known if the user wants to sign in or sign up.
     Otherwise works the same as verifyUserInViewController:scope:webVerificationResults
     
     - Parameter externalViewController: The viewController which will present the modal navigationController
     - Parameter scope: The type of group verification that should be presented.
     - Parameter loginType: The type of operation desired (sign in or sign up)
     - Parameter callback: A block that returns an NSString object representing a valid access token or an `NSError` object.
     */
    public func registerOrLogin(in externalViewController: UIViewController,
                                scope: String,
                                loginType: IDmeWebVerifyLoginType,
                                callback: @escaping IDmeVerifyWebVerifyTokenResults) {
        assert(clientID != nil, "You should initialize the SDK before making requests. Call IDmeWebVerify.initializeWithClientID:redirectURI")
        assert(isAuthenticationFlowInProgress() == false, "There is an authentication flow in progress. You should not call IDmeWebVerify.verifyUserInViewController:scope:withTokenResult until the previous has finished")
        
        let loginUrlString = urlString(with: Constants.IDME_WEB_VERIFY_SIGN_UP_OR_LOGIN)
        let formattedUrlString = String(format: loginUrlString, clientID, redirectURI, scope, loginType.toString())
        if let urlString = createAndAddPKCEParameters(to: formattedUrlString) {
            let url = URL(string: urlString)
            launchSafari(from: externalViewController, url: url)
            requestScope = scope
            self.webVerificationResults = callback
        }
    }
    
    /**
     Registers a new connection for the user.
     */
    public func registerConnection(in externalViewController: UIViewController,
                                   scope: String,
                                   type: IDmeWebVerifyConnection,
                                   callback: @escaping IDmeVerifyWebVerifyTokenResults) {
        assert(clientID != nil, "You should initialize the SDK before making requests. Call IDmeWebVerify.initializeWithClientID:redirectURI")
        assert(isAuthenticationFlowInProgress() == false, "There is an authentication flow in progress. You should not call IDmeWebVerify.verifyUserInViewController:scope:withTokenResult until the previous has finished")
        let registerUrlString = urlString(with: Constants.IDME_WEB_VERIFY_REGISTER_CONNECTION_URI)
        let formattedUrlString = String(format: registerUrlString, clientID, redirectURI, scope, type.toString())
        if let urlString = createAndAddPKCEParameters(to: formattedUrlString) {
            let url = URL(string: urlString)
            launchSafari(from: externalViewController, url: url)
            requestScope = scope
            self.webVerificationResults = callback
        }
    }
    
    /**
     Registers a new ID for the user.
     */
    public func registerAffiliation(in externalViewController: UIViewController,
                                    scope: String,
                                    type: IDmeWebVerifyAffiliation,
                                    callback: @escaping IDmeVerifyWebVerifyTokenResults) {
        assert(clientID != nil, "You should initialize the SDK before making requests. Call IDmeWebVerify.initializeWithClientID:redirectURI")
        assert(isAuthenticationFlowInProgress() == false, "There is an authentication flow in progress. You should not call IDmeWebVerify.verifyUserInViewController:scope:withTokenResult until the previous has finished")
        let registerUrlString = urlString(with: Constants.IDME_WEB_VERIFY_REGISTER_AFFILIATION_URI)
        let formattedUrlString = String(format: registerUrlString, clientID, redirectURI, type.toString())
        if let urlString = createAndAddPKCEParameters(to: formattedUrlString) {
            let url = URL(string: urlString)
            launchSafari(from: externalViewController, url: url)
            requestScope = scope
            self.webVerificationResults = callback
        }
    }
    
    /**
     Returns the User profile with the stored access token.
     
     - Parameter scope: The type of token to be used. If nil then the last token will be used
     - Parameter callback: A block that returns an `NSDictionary` object and an `NSError` object. The verified user's profile is stored in an `NSDictionary` object as `JSON` data. If no data was returned, or an error occured, `NSDictionary` is `nil` and `NSError` returns an error code and localized description of the specific error that occured.
     */
    public func getUserProfile(withScope scope: String?,
                               callback: @escaping IDmeVerifyWebVerifyProfileResults) {
        getAccessToken(withScope: scope, forceRefreshing: false) { [weak self] (accessToken, error) in
            guard let self = self else { return }
            guard let accessToken = accessToken else {
                self.callWebVerificationResults(withToken: nil, error: error)
                return
            }
            
            let profileUrlString = self.urlString(with: Constants.IDME_WEB_VERIFY_GET_USER_PROFILE)
            let urlString = String(format: profileUrlString, accessToken)
            guard let encodedUrlString = urlString.addingPercentEncoding(withAllowedCharacters: CharacterSet.urlHostAllowed),
                  let url = URL(string: encodedUrlString) else {
                assertionFailure("Invalid Get Profile URL String: \(urlString)")
                return 
            }
            var request = URLRequest(url: url)
            request.addValue("IDmeWebVerify-SDK-iOS", forHTTPHeaderField: "X-API-ORIGIN")
            
            URLSession.shared.dataTask(with: request) { data, urlResponse, error in
                guard let httpResponse = urlResponse as? HTTPURLResponse else {
                    callback(nil, self.newError(withCode: .invalidResponseType, userInfo: nil))
                    return
                }
                
                let statusCode = httpResponse.statusCode
                if let data = data, data.count > 0, error == nil, statusCode == 200 {
                    if let result: [AnyHashable: Any?] = try? JSONSerialization.jsonObject(with: data, options: [.allowFragments, .mutableContainers]) as? [AnyHashable: Any?] {
                        let userProfile = result.compactMapValues({$0})
                        DispatchQueue.main.async {
                            callback(userProfile, nil)
                        }
                    }
                } else if statusCode == 401 {
                    DispatchQueue.main.async {
                        callback(nil, self.notAuthorizedError(withUserInfo: nil))
                    }
                } else {
                    DispatchQueue.main.async {
                        callback(nil, self.failedFetchingProfileError(withUserInfo: (error as NSError?)?.userInfo))
                    }
                }
                
            }.resume()
        }
    }
    
    /**
     Invalidates and deletes all tokens stored by the SDK.
     
     - Parameter externalViewController: A view controller used to present a web browser which
     will clear the current session
     - Parameter callback: A block that will be called when the session is deleted
     */
    public func logout(in externalViewController: UIViewController, callback: @escaping () -> Void) {
        keychainData.clean()
        logoutCallback = callback
        
        let logoutUrlString = urlString(with: Constants.IDME_WEB_VERIFY_LOGOUT_PATH)
        let urlString = String(format: logoutUrlString, clientID, redirectURI)
        let url = URL(string: urlString)
        launchSafari(from: externalViewController, url: url)
    }
    
    /**
     Returns a valid access token. If the currently saved access token is valid it will be returned.
     If not, then it will be refreshed.
     
     - Parameter scope: The type of token to be used. If nil then the last token will be used
     - Parameter force: Force the SDK to refresh the token and do not use the current one.
     - Parameter callback: A block that returns an `String` object representing a valid access token
     or an `NSError` object.
     */
    public func getAccessToken(withScope scope: String?,
                               forceRefreshing force: Bool,
                               callback: @escaping IDmeVerifyWebVerifyTokenResults) {
        guard let scope = scope ?? keychainData.getLatestUsedScope() else {
            callback(nil, noSuchScopeError(withUserInfo: nil))
            return
        }
        
        guard let refreshToken = keychainData.refreshToken(forScope: scope),
              let accessToken = keychainData.accessToken(forScope: scope),
              let expiresIn = keychainData.expirationDate(forScope: scope),
              let refreshExpiresIn = keychainData.refreshExpirationDate(forScope: scope) else {
            callback(nil, noSuchScopeError(withUserInfo: nil))
            return
        }
        if force {
            refreshAccessToken(forScope: scope, refreshToken: refreshToken, callback: callback)
            return
        }
        
        let now = Date()
        /// Check if token has expired
        if now.compare(expiresIn) != .orderedAscending {
            /// Token has expired
            if now.compare(refreshExpiresIn) != .orderedAscending {
                /// Refresh token has expired
                callback(nil, refreshTokenExpiredError(withUserInfo: [
                    NSLocalizedDescriptionKey: IDME_WEB_VERIFY_REFRESH_TOKEN_EXPIRED
                ]))
            } else {
                refreshAccessToken(forScope: scope, refreshToken: refreshToken, callback: callback)
            }
        } else {
            callback(accessToken, nil)
        }
    }
    
    /**
     Call this method from the [UIApplicationDelegate application:openURL:options:] method
     of the AppDelegate for your app. It should be invoked for the proper processing of responses
     during interaction with the native Facebook app or Safari as part of SSO authorization
     flow or Facebook dialogs.
     
     - Parameter application: The application as passed to [UIApplicationDelegate application:openURL:options:].
     - Parameter url: The URL as passed to [UIApplicationDelegate application:openURL:options:].
     - Parameter options: The options dictionary as passed to [UIApplicationDelegate application:openURL:options:].
     - Returns: YES if the url was intended for the IDmeWebVerify SDK, NO if not.
     */
    @available(iOS 9.3, *)
    public func application(_ app: UIApplication,
                            open url: URL,
                            options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
        return application(app,
                           open: url,
                           sourceApplication: options[.sourceApplication] as? String,
                           annotation: options[.annotation] as Any)
    }
    
    /**
     Call this method from the [UIApplicationDelegate application:openURL:sourceApplication:annotation:]
     method of the AppDelegate for your app. It should be invoked for the proper processing of
     responses during interaction with the native Facebook app or Safari as part of SSO
     authorization flow or Facebook dialogs.
     
     - Parameter application: The application as passed to [UIApplicationDelegate application:openURL:sourceApplication:annotation:].
     - Parameter url: The URL as passed to [UIApplicationDelegate application:openURL:sourceApplication:annotation:].
     - Parameter sourceApplication: The sourceApplication as passed to [UIApplicationDelegate application:openURL:sourceApplication:annotation:].
     - Parameter annotation: The annotation as passed to [UIApplicationDelegate application:openURL:sourceApplication:annotation:].
     - Returns: YES if the url was intended for the IDmeWebVerify SDK, NO if not.
     */
    public func application(_ application: UIApplication,
                            open url: URL,
                            sourceApplication: String?,
                            annotation: Any) -> Bool {
        safariViewController?.presentingViewController?.dismiss(animated: true, completion: nil)
        safariViewController = nil
        
        if url.absoluteString.hasPrefix(redirectURI) && (url.query?.contains("type=logout") ?? false) {
            if logoutCallback == nil {
                return true
            }
            
            let callback = logoutCallback
            self.logoutCallback = nil
            self.webVerificationResults = nil
            DispatchQueue.main.async {
                callback?()
            }
            return true
        }
        
        guard let codeVerifier = self.codeVerifier, let redirectURI = self.redirectURI else {
            return false
        }
        
        if url.absoluteString.hasPrefix(redirectURI) {
            let beforeQueryString = "\(redirectURI)?"
            let queryString = url.absoluteString.replacingOccurrences(of: beforeQueryString, with: "")
            let parameters = parseQueryParameters(fromQuery: queryString)
            if let code = parameters["code"] {
                self.codeVerifier = nil
                self.codeChallenge = nil
                self.codeChallengeMethod = nil
                let format = "client_id=%@&client_secret=%@&redirect_uri=%@&code=%@&grant_type=authorization_code&code_verifier=%@"
                let params = String(format: format, clientID, clientSecret, redirectURI, code, codeVerifier)
                
                let urlString = urlString(with: Constants.IDME_WEB_VERIFY_REFRESH_CODE_URL)
                makePostRequest(with: urlString, parameters: params) { [weak self] (data, urlResponse, error) in
                    guard let self = self else { return }
                    guard let httpResponse = urlResponse as? HTTPURLResponse, let data = data else {
                        self.callWebVerificationResults(withToken: nil,
                                                        error: self.newError(withCode: .invalidResponseType, userInfo: nil))
                        return
                    }
                    if let json = try? JSONSerialization.jsonObject(with: data, options: .mutableContainers) as? [String: Any],
                       let requestScope = self.requestScope {
                        let statusCode = httpResponse.statusCode
                        if error != nil, statusCode < 200, statusCode >= 300 {
                            /// Error from server, we may have a response in the json
                            let callbackError = self.codeAuthenticationError(withUserInfo: json)
                            self.callWebVerificationResults(withToken: nil, error: callbackError)
                            return
                        }
                        self.saveTokenData(fromJSON: json, scope: requestScope)
                        self.callWebVerificationResults(withToken: json[Constants.IDME_WEB_VERIFY_ACCESS_TOKEN_PARAM] as? String,
                                                        error: nil)
                    } else {
                        let authError = self.notAuthorizedError(withUserInfo: [
                            NSLocalizedDescriptionKey: IDME_WEB_VERIFY_VERIFICATION_FAILED
                        ])
                        self.callWebVerificationResults(withToken: nil, error: authError)
                    }
                }
                
            } else if let errorDescription = parameters[Constants.IDME_WEB_VERIFY_ERROR_DESCRIPTION_PARAM],
                      let errorString = parameters[Constants.IDME_WEB_VERIFY_ERROR_PARAM] {
                let details = [NSLocalizedDescriptionKey: errorDescription.replacingOccurrences(of: "+", with: " ")]
                var err: NSError
                if errorString == Constants.IDME_WEB_VERIFY_ACCESS_DENIED_ERROR {
                    err = newError(withCode: .verificationWasDeniedByUser, userInfo: details)
                } else {
                    err = codeAuthenticationError(withUserInfo: details)
                }
                callWebVerificationResults(withToken: nil, error: err)
            }
            return true
        }
        
        return false
    }
}

// MARK: - SFSafariViewControllerDelegate
extension IDmeWebVerify: SFSafariViewControllerDelegate {
    public func safariViewControllerDidFinish(_ controller: SFSafariViewController) {
        safariViewController = nil
        callWebVerificationResults(
            withToken: nil,
            error: newError(withCode: .verificationWasCanceledByUser,
                            userInfo: nil))
    }
}

// MARK: - Web View
private extension IDmeWebVerify {
    func launchSafari(from presenting: UIViewController, url: URL?) {
        guard let url = url else { return }
        let controller = SFSafariViewController(url: url)
        controller.delegate = self
        safariViewController = controller
        presenting.present(controller, animated: true, completion: nil)
    }
}

// MARK: - Helpers
private extension IDmeWebVerify {
    func isLoggedIn() -> Bool {
        return keychainData.isClean() == false
    }
    
    func isAuthenticationFlowInProgress() -> Bool {
        return safariViewController != nil || webVerificationResults != nil
    }
    
    func urlString(with queryString: String) -> String {
        return BASE_URL.appending(queryString)
    }
    
    func callWebVerificationResults(withToken token: String?, error: NSError?) {
        let callback = webVerificationResults
        self.webVerificationResults = nil
        DispatchQueue.main.async {
            callback?(token, error)
        }
    }
    
    func saveTokenData(fromJSON json: [String: Any], scope: String) {
        guard let accessToken = json[Constants.IDME_WEB_VERIFY_ACCESS_TOKEN_PARAM] as? String,
              let refreshToken = json[Constants.IDME_WEB_VERIFY_REFRESH_TOKEN_PARAM] as? String,
              let expiresIn = json[Constants.IDME_WEB_VERIFY_EXPIRATION_PARAM] as? Int,
              let refreshExpiresIn = json[Constants.IDME_WEB_VERIFY_REFRESH_EXPIRATION_PARAM] as? Int else {
            assertionFailure("Invalid or mission required data to save token to keychain.")
            return
        }
        
        let expiresInTimeInterval = TimeInterval(expiresIn)
        let refreshExpiresInTimeInterval = TimeInterval(refreshExpiresIn)
        
        let expiresInDate = Date(timeIntervalSinceNow: expiresInTimeInterval)
        let refreshExpiresInDate = Date(timeIntervalSinceNow: refreshExpiresInTimeInterval)
        
        keychainData.setToken(accessToken,
                              expirationDate: expiresInDate,
                              refreshToken: refreshToken,
                              refreshExpDate: refreshExpiresInDate,
                              forScope: scope)
    }
}

// MARK: - Helpers - Network
private extension IDmeWebVerify {
    func parseQueryParameters(fromQuery query: String) -> [String: String] {
        let components = query.components(separatedBy: "&")
        var queryItems: [String: String] = [:]
        for component in components {
            let parts = component.components(separatedBy: "=")
            guard parts.count >= 2 else { continue }
            if let key = parts[0].removingPercentEncoding,
               let value = parts[1].removingPercentEncoding {
                queryItems[key] = value
            }
        }
        return queryItems
    }
    
    func createAndAddPKCEParameters(to urlString: String) -> String? {
        let utils = IDmePKCEUtils()
        if let codeVerifier = utils.generateCodeVerifier(withSize: Constants.CODE_VERIFIER_SIZE) {
            self.codeVerifier = codeVerifier
            self.codeChallenge = utils.encodeBase64(utils.sha256(codeVerifier))
            self.codeChallengeMethod = Constants.CODE_CHALLENGE_METHOD
            
            if let challenge = codeChallenge, let challengeMethod = codeChallengeMethod {
                let format = "%@&code_challenge=%@&code_challenge_method=%@"
                return String(format: format, urlString, challenge, challengeMethod)
            }
        }
        return nil
    }
    
    func makePostRequest(with urlString: String, parameters: String, completion: @escaping RequestCompletion) {
        let parameterData = parameters.data(using: .utf8)
        guard let url = URL(string: urlString) else {
            assertionFailure("Post Request had invalid URL string: \(urlString)")
            completion(nil, nil, nil)
            return
        }
        
        var request = URLRequest(url: url)
        request.httpMethod = Constants.POST_METHOD
        request.addValue("application/x-www-form-urlencoded; charset=utf-8",
                         forHTTPHeaderField: "Content-Type")
        request.httpBody = parameterData
        
        URLSession.shared.dataTask(with: request, completionHandler: completion).resume()
    }
    
    func refreshAccessToken(forScope scope: String, refreshToken: String, callback: @escaping IDmeVerifyWebVerifyTokenResults) {
        refreshSerialQueue.sync { [weak self] in
            guard let self = self else {
                callback(nil, nil)
                return
            }
            if pendingRefreshes[scope] == nil {
                pendingRefreshes[scope] = []
            }
            
            let scopeCallbacks = pendingRefreshes[scope] ?? []
            if scopeCallbacks.isEmpty {
                /// First one wanting to refresh
                let currentRefreshToken = self.keychainData.refreshToken(forScope: scope)
                if (currentRefreshToken == refreshToken) == false {
                    /// Somebody just updated the refreshToken
                    if let accessToken = self.keychainData.accessToken(forScope: scope) {
                        callback(accessToken, nil)
                    } else {
                        callback(nil, self.notAuthorizedError(withUserInfo: [NSLocalizedDescriptionKey: IDME_WEB_VERIFY_VERIFICATION_FAILED]))
                    }
                    return
                }
                
                let format = "client_id=%@&client_secret=%@&redirect_uri=%@&refresh_token=%@&grant_type=refresh_token"
                let parameters = String(format: format, clientID, clientSecret, redirectURI, refreshToken)
                makePostRequest(with: urlString(with: Constants.IDME_WEB_VERIFY_REFRESH_CODE_URL),
                                parameters: parameters) { data, urlResponse, error in
                    /// If the urlResponse is in the incorrect format, or the data is missing,
                    /// notify the pending callers of the error.
                    guard let httpResponse = urlResponse as? HTTPURLResponse, let data = data else {
                        for cb in scopeCallbacks {
                            cb(nil, self.newError(withCode: .invalidResponseType, userInfo: nil))
                        }
                        self.pendingRefreshes[scope] = []
                        return
                    }
                    self.requestSerialQueue.sync {
                        if let json = try? JSONSerialization.jsonObject(with: data, options: .mutableContainers) as? [String: Any] {
                            if error == nil, [Int](200..<300).contains(httpResponse.statusCode) {
                                self.saveTokenData(fromJSON: json, scope: scope)
                                if let accessToken = json[Constants.IDME_WEB_VERIFY_ACCESS_TOKEN_PARAM] as? String {
                                    for cb in scopeCallbacks {
                                        cb(accessToken, nil)
                                    }
                                    self.pendingRefreshes[scope] = []
                                }
                                return
                            }
                        }
                        
                        for cb in scopeCallbacks {
                            cb(nil, self.refreshTokenFailedError(withUserInfo: [
                                NSLocalizedDescriptionKey: IDME_WEB_VERIFY_REFRESH_TOKEN_FAILED
                            ]))
                        }
                        self.pendingRefreshes[scope] = []
                    }
                }
            }
            pendingRefreshes[scope]?.append(callback)
        }
    }
}

// MARK: - Helpers - Errors
private extension IDmeWebVerify {
    func newError(withCode code: IDmeWebVerifyErrorCode, userInfo: [String: Any]?) -> NSError {
        return NSError(domain: IDME_WEB_VERIFY_ERROR_DOMAIN,
                       code: code.rawValue,
                       userInfo: userInfo)
    }
    
    func failedFetchingProfileError(withUserInfo userInfo: [String: Any]?) -> NSError {
        return newError(withCode: .verificationDidFailToFetchUserProfile, userInfo: userInfo)
    }
    
    func notAuthorizedError(withUserInfo userInfo: [String: Any]?) -> NSError {
        return newError(withCode: .notAuthorized, userInfo: userInfo)
    }
    
    func noSuchScopeError(withUserInfo userInfo: [String: Any]?) -> NSError {
        return newError(withCode: .noSuchScope, userInfo: userInfo)
    }
    
    func notImplementedError(withUserInfo userInfo: [String: Any]?) -> NSError {
        return newError(withCode: .notImplemented, userInfo: userInfo)
    }
    
    func refreshTokenExpiredError(withUserInfo userInfo: [String: Any]?) -> NSError {
        return newError(withCode: .refreshTokenExpired, userInfo: userInfo)
    }
    
    func refreshTokenFailedError(withUserInfo userInfo: [String: Any]?) -> NSError {
        return newError(withCode: .refreshTokenFailed, userInfo: userInfo)
    }
    
    func codeAuthenticationError(withUserInfo userInfo: [String: Any]?) -> NSError {
        return newError(withCode: .authenticationFailed, userInfo: userInfo)
    }
}
