//
//  AppDelegate.swift
//  Example
//
//  Created by Eric Miller on 9/16/21.
//  Copyright © 2021 ID.me, Inc. All rights reserved.
//

import UIKit
import IDmeWebVerify

@UIApplicationMain
class AppDelegate: UIResponder, UIApplicationDelegate {
    
    var window: UIWindow?
    
    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?) -> Bool {
        
        let viewController = ViewController()
        self.window = UIWindow(frame: UIScreen.main.bounds)
        self.window?.rootViewController = viewController
        self.window?.makeKeyAndVisible()
        
        return true
    }
    
    func application(_ app: UIApplication,
                     open url: URL,
                     options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
        IDmeWebVerify.sharedInstance().application(app, open: url, options: options)
    }
    
    func application(_ application: UIApplication,
                     open url: URL,
                     sourceApplication: String?,
                     annotation: Any) -> Bool {
        IDmeWebVerify.sharedInstance().application(application,
                                                   open: url,
                                                   sourceApplication: sourceApplication!,
                                                   annotation: annotation)
    }
}
