//
//  ViewController.swift
//  Example
//
//  Created by Eric Miller on 9/16/21.
//  Copyright © 2021 ID.me, Inc. All rights reserved.
//

import UIKit
import IDmeWebVerify

class ViewController: UIViewController {
    
    private let textView = UITextView()
    private let clientId: String = "<your_client_id>"
    private let clientSecret: String = "<your_client_secret>"
    private let redirectURL: String = "<your_custom_scheme://callback>"
    private let scope: String = "<your_handle>"
    
    override func viewDidLoad() {
        super.viewDidLoad()
        
        IDmeWebVerify.initialize(withClientID: clientId,
                                 clientSecret: clientSecret,
                                 redirectURI: redirectURL)
        
        setupSubviews()
    }
}

// MARK: - View Creation
private extension ViewController {
    func setupSubviews() {
        view.backgroundColor = UIColor.white
        
        textView.translatesAutoresizingMaskIntoConstraints = false
        textView.font = UIFont.systemFont(ofSize: 15.0)
        textView.isEditable = false
        view.addSubview(textView)
        
        let button = UIButton()
        button.translatesAutoresizingMaskIntoConstraints = false
        button.setTitle("Verify Me", for: .normal)
        button.backgroundColor = UIColor.lightGray
        button.addTarget(self, action: #selector(verifyAction(_:)), for: .touchUpInside)
        button.layer.cornerRadius = 5.0
        view.addSubview(button)
        
        let logoutButton = UIButton()
        logoutButton.translatesAutoresizingMaskIntoConstraints = false
        logoutButton.setTitle("Logout", for: .normal)
        logoutButton.backgroundColor = UIColor.lightGray
        logoutButton.addTarget(self, action: #selector(logout(_:)), for: .touchUpInside)
        logoutButton.layer.cornerRadius = 5.0
        view.addSubview(logoutButton)
        
        let loginButton = UIButton()
        loginButton.translatesAutoresizingMaskIntoConstraints = false
        loginButton.setTitle("Add connection", for: .normal)
        loginButton.backgroundColor = UIColor.lightGray
        loginButton.addTarget(self, action: #selector(addConnection(_:)), for: .touchUpInside)
        loginButton.layer.cornerRadius = 5.0
        view.addSubview(loginButton)
        
        let idButton = UIButton()
        idButton.translatesAutoresizingMaskIntoConstraints = false
        idButton.setTitle("Add ID", for: .normal)
        idButton.backgroundColor = UIColor.lightGray
        idButton.addTarget(self, action: #selector(addAddiliation(_:)), for: .touchUpInside)
        idButton.layer.cornerRadius = 5.0
        view.addSubview(idButton)
        
        // Constraints
        let horizontalMargin: CGFloat = 80.0
        let verticalPadding: CGFloat = 10.0
        let buttonHeight: CGFloat = 40.0
        let textViewHeight: CGFloat = 250.0
        let views: [String: Any] = [
            "textView": textView,
            "button": button,
            "logoutButton": logoutButton,
            "loginButton": loginButton,
            "idButton": idButton
        ]
        let metrics: [String: Any] = [
            "horizontalMargin": horizontalMargin,
            "verticalPadding": verticalPadding,
            "buttonHeight": buttonHeight,
            "textViewHeight": textViewHeight
        ]
        
        var allConstraints: [NSLayoutConstraint] = []
        let buttonHorizontalConstraints = NSLayoutConstraint.constraints(
            withVisualFormat: "H:|-horizontalMargin-[button]-horizontalMargin-|",
            options: .alignAllFirstBaseline,
            metrics: metrics,
            views: views)
        allConstraints += buttonHorizontalConstraints
        
        let logoutButtonHorizontalConstraints = NSLayoutConstraint.constraints(
            withVisualFormat: "H:|-horizontalMargin-[logoutButton]-horizontalMargin-|",
            options: .alignAllFirstBaseline,
            metrics: metrics,
            views: views)
        allConstraints += logoutButtonHorizontalConstraints
        
        let loginButtonHorizontalConstraints = NSLayoutConstraint.constraints(
            withVisualFormat: "H:|-horizontalMargin-[loginButton]-horizontalMargin-|",
            options: .alignAllFirstBaseline,
            metrics: metrics,
            views: views)
        allConstraints += loginButtonHorizontalConstraints
        
        let idButtonHorizontalConstraints = NSLayoutConstraint.constraints(
            withVisualFormat: "H:|-horizontalMargin-[idButton]-horizontalMargin-|",
            options: .alignAllFirstBaseline,
            metrics: metrics,
            views: views)
        allConstraints += idButtonHorizontalConstraints
        
        let textViewHorizontalConstraints = NSLayoutConstraint.constraints(
            withVisualFormat: "H:|-[textView]-|",
            options: .alignAllFirstBaseline,
            metrics: metrics,
            views: views)
        allConstraints += textViewHorizontalConstraints
        
        let verticalConstraints = NSLayoutConstraint.constraints(
            withVisualFormat: "V:|-verticalPadding-[textView(textViewHeight)]-verticalPadding-[button(buttonHeight)]-verticalPadding-[loginButton(buttonHeight)]-verticalPadding-[logoutButton(buttonHeight)]-verticalPadding-[idButton(buttonHeight)]",
            options: [],
            metrics: metrics,
            views: views)
        allConstraints += verticalConstraints
        
        NSLayoutConstraint.activate(allConstraints)
    }
}

// MARK: - Actions
private extension ViewController {
    @objc
    func verifyAction(_ sender: UIButton) {
        textView.text = nil
        IDmeWebVerify.sharedInstance().verifyUser(in: self, scope: scope) { token, error in
            IDmeWebVerify.sharedInstance().getUserProfile(withScope: self.scope) { userProfile, error in
                self.results(withUserProfile: userProfile, error: error)
            }
        }
    }
    
    @objc
    func addConnection(_ sender: UIButton) {
        IDmeWebVerify.sharedInstance().registerConnection(in: self, scope: scope, type: .googlePlus) { token, error in
            if let error = error {
                NSLog("Verification Error \((error as NSError).code): \(error.localizedDescription)")
                self.textView.text = String("Error code: \((error as NSError).code)\n\n\(error.localizedDescription)")
            } else {
                self.textView.text = "Successfully added Google connection"
            }
        }
    }
    
    @objc
    func addAddiliation(_ sender: UIButton) {
        IDmeWebVerify.sharedInstance().registerAffiliation(in: self, scope: scope, type: .military) { token, error in
            if let error = error {
                NSLog("Verification Error \((error as NSError).code): \(error.localizedDescription)")
                self.textView.text = String("Error code: \((error as NSError).code)\n\n\(error.localizedDescription)")
            } else {
                self.textView.text = "Successfully added Troop ID"
            }
        }
    }
    
    @objc
    func logout(_ sender: UIButton) {
        IDmeWebVerify.sharedInstance().logout(in: self) {
            self.textView.text = "Successfully logged out"
        }
    }
    
    func results(withUserProfile userProfile: [AnyHashable: Any]?, error: Error?) {
        if let error = error {
            NSLog("Verification Error \((error as NSError).code): \(error.localizedDescription)")
            textView.text = String("Error code: \((error as NSError).code)\n\n\(error.localizedDescription)")
        } else {
            var profile: String = ""
            for (key, value) in userProfile ?? [:] {
                profile.append("\(key): \(value)")
            }
            
            NSLog("\nVerification Results:\n \(profile)");
            textView.text = profile
        }
    }
}
