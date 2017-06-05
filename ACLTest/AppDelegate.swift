//
//  AppDelegate.swift
//  ACLTest
//
//  Created by wenyou on 2017/6/5.
//  Copyright © 2017年 wenyou. All rights reserved.
//

import Cocoa

@NSApplicationMain
class AppDelegate: NSObject, NSApplicationDelegate {
    static let windowSize = NSMakeSize(800, 500)
    var window: NSWindow!

    func applicationDidFinishLaunching(_ aNotification: Notification) {
        window = TextWindow(contentRect: NSRect.zero,
                            styleMask: [.closable, .resizable, .miniaturizable, .titled],
                            backing: .buffered,
                            defer: false)
        window.center()
        window.makeKeyAndOrderFront(self)

        let url = URL.init(fileURLWithPath: NSOpenStepRootDirectory() + "etc/hosts1")
        _ = ACLHelp.init(url: url).checkACLPermission(gid: 0, perms: [acl_perm_t]())

    }
}
