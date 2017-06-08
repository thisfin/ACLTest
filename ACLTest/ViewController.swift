//
//  ViewController.swift
//  ACLTest
//
//  Created by wenyou on 2017/6/5.
//  Copyright © 2017年 wenyou. All rights reserved.
//

import Cocoa

class ViewController: NSViewController {
    private let aclHelp = ACLHelp.init(url: URL.init(fileURLWithPath: NSOpenStepRootDirectory() + "etc/hosts"))

    override func loadView() {
        view = NSView()
    }

    override func viewDidLoad() {
        super.viewDidLoad()

        view.wantsLayer = true
        view.layer?.backgroundColor = NSColor.white.cgColor
        view.frame = NSRect(origin: .zero, size: AppDelegate.windowSize)
    }

    override func viewDidAppear() {
        super.viewDidAppear()

        view.addSubview({
            let button = NSButton.init(title: "test", target: self, action: #selector(ViewController.buttonClicked(_:)))
            button.frame.origin = .zero
            return button
            }())
    }

    func buttonClicked(_ sender: NSButton) {
        let isWritable = aclHelp.checkACLPermission(userName: NSUserName(), perms: [ACL_READ_DATA, ACL_WRITE_DATA])

        let alert = NSAlert.init()
        alert.messageText = "提示"
        alert.informativeText = "你" + (isWritable ? "有" : "无") + " /etc/hosts 文件的权限"
        alert.alertStyle = .critical
        alert.addButton(withTitle: "cancel")
        alert.addButton(withTitle: isWritable ? "消权" : "加权")
        let response = alert.runModal()
        switch response {
        case NSAlertSecondButtonReturn:
            var error: NSDictionary?
            let ope = isWritable ? "-" : "+"
            var cmd = ""
            cmd += "tell application \"Terminal\"\n"
            cmd += "activate (do script \"sudo /bin/chmod \(ope)a \\\"user:\(NSUserName()):allow read,write\\\" /etc/hosts\")\n"
            cmd += "end tell"
            let appleScript = NSAppleScript.init(source: cmd)
            appleScript?.executeAndReturnError(&error)
            NSLog("\(String(describing: error))")
        default:
            ()
        }
    }
}
