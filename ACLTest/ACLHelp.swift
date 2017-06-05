//
//  ACLHelp.swift
//  ACLTest
//
//  Created by wenyou on 2017/6/5.
//  Copyright © 2017年 wenyou. All rights reserved.
//

import Foundation

class ACLHelp {
    static let ACL_PERM_DIR = 1 << 0
    static let ACL_PERM_FILE = 1 << 1

    private let url: URL

    init(url: URL) {
        self.url = url
    }

    // 打印
    func toString() -> String? {
        if let result = acl_get_file(url.path, ACL_TYPE_EXTENDED) {
            var size = acl_size(result)
            return String(utf8String: &acl_to_text(result, &size).pointee)
        }
        return nil
    }

    func checkACLPermission(uid: UInt32, perms: [acl_perm_t]) -> Bool {
        return checkACLPermission(uid: uid, isUser: true, perms: perms)
    }

    func checkACLPermission(gid: UInt32, perms: [acl_perm_t]) -> Bool {
        return checkACLPermission(gid: gid, isUser: false, perms: perms)
    }

    // 检查权限
    // acl https://github.com/jvscode/getfacl/blob/master/getfacl.c
    // mbr https://github.com/practicalswift/osx/blob/master/src/libinfo/membership.subproj/membership.c
    // sizeof https://stackoverflow.com/questions/24662864/swift-how-to-use-sizeof
    private func checkACLPermission(uid: UInt32 = 0, gid: UInt32 = 0, isUser: Bool, perms: [acl_perm_t]) -> Bool {
        guard let result = acl_get_file(url.path, ACL_TYPE_EXTENDED) else {
            return false
        }

        var entryT: acl_entry_t?
        var entry_id = ACL_FIRST_ENTRY

        while acl_get_entry(result, entry_id.rawValue, &entryT) == 0 {
            entry_id = ACL_NEXT_ENTRY

            NSLog("\(String(describing: parseTagType(entry: entryT)))")
            NSLog("\(String(describing: parsePerm(entry: entryT)))")
            NSLog("\(String(describing: parseQualifier(entry: entryT)))")

        }

        return false
    }

    private func parseTagType(entry: acl_entry_t?) -> acl_tag_t? {
        var tagT: acl_tag_t = ACL_UNDEFINED_TAG
        if acl_get_tag_type(entry, &tagT) != 0 {
            return nil
        }

        return tagT
    }

    private func parsePerm(entry: acl_entry_t?) -> [acl_perm_t] {
        var perms = [acl_perm_t]()

        var isDir: ObjCBool = false
        if !FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir) {
            return perms
        }

        var permsetT: acl_permset_t?
        if acl_get_permset(entry, &permsetT) != 0 {
            return perms
        }

        aclPerms.forEach({ (aclPerm) in
            if acl_get_perm_np(permsetT, aclPerm.perm) == 0 {
                return
            }
            if (aclPerm.flags & (isDir.boolValue ? ACLHelp.ACL_PERM_DIR : ACLHelp.ACL_PERM_FILE)) == 0 {
                return
            }
            perms.append(aclPerm.perm)
        })

        return perms
    }

    private func parseFlag(entry: acl_entry_t?) -> [acl_flag_t] {
        var flags = [acl_flag_t]()

        var isDir: ObjCBool = false
        if !FileManager.default.fileExists(atPath: url.path, isDirectory: &isDir) {
            return flags
        }

        var flagsetT: acl_flagset_t?
        if acl_get_flagset_np(UnsafeMutableRawPointer.init(entry), &flagsetT) != 0 {
            return flags
        }

        aclFlags.forEach({ (aclFlag) in
            if acl_get_flag_np(flagsetT, aclFlag.flag) == 0 {
                return
            }
            if (aclFlag.flags & (isDir.boolValue ? ACLHelp.ACL_PERM_DIR : ACLHelp.ACL_PERM_FILE)) == 0 {
                return
            }
            flags.append(aclFlag.flag)
        })

        return flags
    }

    private func parseQualifier(entry: acl_entry_t?) -> (isUser: Bool, id: UInt32)? {
        guard let qualifier = acl_get_qualifier(entry) else {
            return nil
        }

//        let uuid = UUID.init(uuid: qualifier.assumingMemoryBound(to: uuid_t.self).pointee)
        var uuid = qualifier.assumingMemoryBound(to: uuid_t.self).pointee
        var uuidArray = [UInt8].init(repeating: 0, count: 16)
        memcpy(&uuidArray, &uuid, MemoryLayout<uuid_t>.size)

        if let pw = getpwuuid(&uuidArray)?.pointee {
            return (true, pw.pw_uid)
        } else if let gr = getgruuid(&uuidArray)?.pointee {
            return (false, gr.gr_gid)
        }

        return nil
    }

    struct ACLPerm {
        let perm: acl_perm_t
        let name: String
        let flags: Int
    }

    struct ACLFlag {
        let flag: acl_flag_t
        let name: String
        let flags: Int
    }

    let aclPerms = [
        ACLPerm(perm: ACL_READ_DATA, name: "read", flags: ACL_PERM_FILE),
        ACLPerm(perm: ACL_LIST_DIRECTORY, name: "list", flags: ACL_PERM_DIR),
        ACLPerm(perm: ACL_WRITE_DATA, name: "write", flags: ACL_PERM_FILE),
        ACLPerm(perm: ACL_ADD_FILE, name: "add_file", flags: ACL_PERM_DIR),
        ACLPerm(perm: ACL_EXECUTE, name: "execute", flags: ACL_PERM_FILE),
        ACLPerm(perm: ACL_SEARCH, name: "search", flags: ACL_PERM_DIR),
        ACLPerm(perm: ACL_DELETE, name: "delete", flags: ACL_PERM_FILE | ACL_PERM_DIR),
        ACLPerm(perm: ACL_APPEND_DATA, name: "append", flags: ACL_PERM_FILE),
        ACLPerm(perm: ACL_ADD_SUBDIRECTORY, name: "add_subdirectory", flags: ACL_PERM_DIR),
        ACLPerm(perm: ACL_DELETE_CHILD, name: "delete_child", flags: ACL_PERM_DIR),
        ACLPerm(perm: ACL_READ_ATTRIBUTES, name: "readattr", flags: ACL_PERM_FILE | ACL_PERM_DIR),
        ACLPerm(perm: ACL_WRITE_ATTRIBUTES, name: "writeattr", flags: ACL_PERM_FILE | ACL_PERM_DIR),
        ACLPerm(perm: ACL_READ_EXTATTRIBUTES, name: "readextattr", flags: ACL_PERM_FILE | ACL_PERM_DIR),
        ACLPerm(perm: ACL_WRITE_EXTATTRIBUTES, name: "writeextattr", flags: ACL_PERM_FILE | ACL_PERM_DIR),
        ACLPerm(perm: ACL_READ_SECURITY, name: "readsecurity", flags: ACL_PERM_FILE | ACL_PERM_DIR),
        ACLPerm(perm: ACL_WRITE_SECURITY, name: "writesecurity", flags: ACL_PERM_FILE | ACL_PERM_DIR),
        ACLPerm(perm: ACL_CHANGE_OWNER, name: "chown", flags: ACL_PERM_FILE | ACL_PERM_DIR)
    ]

    let aclFlags = [
        ACLFlag(flag: ACL_ENTRY_FILE_INHERIT, name: "file_inherit", flags: ACL_PERM_DIR),
        ACLFlag(flag: ACL_ENTRY_DIRECTORY_INHERIT, name: "directory_inherit", flags: ACL_PERM_DIR),
        ACLFlag(flag: ACL_ENTRY_LIMIT_INHERIT, name: "limit_inherit", flags: ACL_PERM_FILE | ACL_PERM_DIR),
        ACLFlag(flag: ACL_ENTRY_ONLY_INHERIT, name: "only_inherit", flags: ACL_PERM_DIR),
        ACLFlag(flag: ACL_FLAG_NO_INHERIT, name: "??", flags: ACL_PERM_FILE | ACL_PERM_DIR),
        ACLFlag(flag: ACL_ENTRY_INHERITED, name: "??", flags: ACL_PERM_FILE | ACL_PERM_DIR),
        ACLFlag(flag: ACL_FLAG_DEFER_INHERIT, name: "??", flags: ACL_PERM_FILE | ACL_PERM_DIR)
    ]
}



