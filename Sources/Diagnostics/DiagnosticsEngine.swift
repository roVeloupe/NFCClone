//
//  DiagnosticsEngine.swift
//  NFCClone
//
//  完整诊断引擎 — 不需要物理卡，自检后生成可用性报告
//  IOKit 用 dlsym 运行时加载，避免链接 iOS 私有 framework
//

import Foundation
import Darwin
import CoreNFC
import UIKit

// MARK: - IOKit 类型手动 typedef
typealias mach_port_t = UInt32
typealias io_iterator_t = UInt32
typealias io_object_t = UInt32
typealias io_service_t = UInt32
typealias kern_return_t = Int32
let KERN_SUCCESS: kern_return_t = 0

// MARK: - dlsym 桥接（运行时加载 IOKit 私有 framework）
@_silgen_name("dlopen")
func _dlopen(_ path: UnsafePointer<Int8>, _ mode: Int32) -> UnsafeMutableRawPointer?
@_silgen_name("dlsym")
func _dlsym(_ handle: UnsafeMutableRawPointer?, _ sym: UnsafePointer<Int8>) -> UnsafeMutableRawPointer?
@_silgen_name("dlclose")
func _dlclose(_ handle: UnsafeMutableRawPointer?) -> Int32
let RTLD_DEFAULT = UnsafeMutableRawPointer?(nil)

private struct IOKitFuncs {
    // 函数指针类型
    typealias IOMainPortDefaultFn = @convention(c) () -> mach_port_t
    typealias IOServiceMatchingFn = @convention(c) (UnsafePointer<Int8>) -> UnsafeMutableRawPointer?
    typealias IOServiceGetMatchingServicesFn = @convention(c) (mach_port_t, UnsafeMutableRawPointer?, UnsafeMutablePointer<io_iterator_t>) -> kern_return_t
    typealias IOIteratorNextFn = @convention(c) (io_iterator_t) -> io_service_t
    typealias IOObjectReleaseFn = @convention(c) (io_object_t) -> kern_return_t
    typealias IOObjectCopyClassFn = @convention(c) (io_object_t) -> Unmanaged<CFString>?

    let port: mach_port_t
    let matching: IOServiceMatchingFn
    let getMatching: IOServiceGetMatchingServicesFn
    let iterNext: IOIteratorNextFn
    let objRelease: IOObjectReleaseFn
    let objCopyClass: IOObjectCopyClassFn
    let available: Bool

    static let shared = IOKitFuncs()

    private init() {
        // iOS 上 IOKit 在 IOKit.framework 或 libsystem_kernel 里
        // 优先 dlopen IOKit.framework，失败则用 RTLD_DEFAULT (main image)
        let handle = _dlopen("/System/Library/Frameworks/IOKit.framework/IOKit", 2) ??
                     _dlopen("/System/Library/PrivateFrameworks/IOKit.framework/IOKit", 2)
        let sym: (String) -> UnsafeMutableRawPointer? = { name in
            name.withCString { _dlsym(handle, $0) }
        }
        let pmd = sym("IOMainPortDefault") ?? RTLD_DEFAULT.flatMap { _dlsym($0, "IOMainPortDefault") }
        let m = sym("IOServiceMatching")
        let g = sym("IOServiceGetMatchingServices")
        let n = sym("IOIteratorNext")
        let r = sym("IOObjectRelease")
        let c = sym("IOObjectCopyClass")
        guard let pmd, let m, let g, let n, let r, let c else {
            self.port = 0; self.matching = { _ in nil }; self.getMatching = {_,_,_ in 0 }
            self.iterNext = { _ in 0 }; self.objRelease = { _ in 0 }; self.objCopyClass = { _ in nil }
            self.available = false; return
        }
        self.port = unsafeBitCast(pmd, to: IOMainPortDefaultFn.self)()
        self.matching = unsafeBitCast(m, to: IOServiceMatchingFn.self)
        self.getMatching = unsafeBitCast(g, to: IOServiceGetMatchingServicesFn.self)
        self.iterNext = unsafeBitCast(n, to: IOIteratorNextFn.self)
        self.objRelease = unsafeBitCast(r, to: IOObjectReleaseFn.self)
        self.objCopyClass = unsafeBitCast(c, to: IOObjectCopyClassFn.self)
        self.available = true
    }
}

// MARK: - 类型

public enum DiagStatus: String, Codable {
    case pass = "✅ PASS", warn = "⚠️ WARN", fail = "❌ FAIL", skip = "⏭️ SKIP"
}

public struct DiagItem: Identifiable {
    public let id = UUID()
    public let name: String
    public var status: DiagStatus
    public var detail: String
    public var suggestion: String?
}

public struct DiagReport {
    public let timestamp: Date
    public let device: String
    public let osVersion: String
    public var items: [DiagItem]
    public var passCount: Int { items.filter { $0.status == .pass }.count }
    public var warnCount: Int { items.filter { $0.status == .warn }.count }
    public var failCount: Int { items.filter { $0.status == .fail }.count }
    public var overall: DiagStatus {
        if failCount > 0 { return .fail }
        if warnCount > 0 { return .warn }
        return .pass
    }
    public var canEmulate: Bool {
        let s = items.first { $0.name == "Sandbox Escape" }?.status
        let r = items.first { $0.name == "IOKit RFIC 控制器" }?.status
        let e = items.first { $0.name == "NFC Entitlements" }?.status
        return s == .pass && r == .pass && e == .pass
    }
}

// MARK: - Engine

public class DiagnosticsEngine {
    public static let shared = DiagnosticsEngine()
    private init() {}

    public func runFullDiagnostics() -> DiagReport {
        let fm = FileManager.default
        var items: [DiagItem] = []
        items.append(checkDevice())
        items.append(checkBundleID())
        items.append(checkEntitlements(fm))
        items.append(checkSandbox(fm))
        items.append(checkIOKitRFIC())
        items.append(checkNfcdDaemon(fm))
        items.append(checkLegacyDeviceNodes(fm))
        items.append(checkCoreNFC())
        items.append(checkCardSession())
        items.append(checkFileAccess(fm))
        let p = ProcessInfo.processInfo.operatingSystemVersion
        return DiagReport(timestamp: Date(), device: UIDevice.current.model,
                          osVersion: "\(p.majorVersion).\(p.minorVersion)", items: items)
    }

    private func checkDevice() -> DiagItem {
        var u = utsname()
        _ = Darwin.uname(&u)
        let machine = withUnsafeBytes(of: &u.machine) { b in
            String(cString: b.baseAddress!.assumingMemoryBound(to: CChar.self))
        }
        let ok = machine.hasPrefix("iPhone12") || machine.hasPrefix("iPhone13") ||
                 machine.hasPrefix("iPhone14") || machine.hasPrefix("iPhone15") ||
                 machine.hasPrefix("iPhone16") || machine.contains("arm64e")
        let chip = ["iPhone12":"A14","iPhone13":"A15","iPhone14":"A16","iPhone15":"A17","iPhone16":"A18"]
            .first { machine.hasPrefix($0.key) }?.value ?? "Apple Silicon"
        return DiagItem(name: "Device", status: ok ? .pass : .warn,
                        detail: "\(UIDevice.current.model) — \(machine)\nChip: \(chip)",
                        suggestion: ok ? nil : "A14+ 才支持完整 NFC")
    }

    private func checkBundleID() -> DiagItem {
        let bid = Bundle.main.bundleIdentifier ?? "(none)"
        let ok = bid == "com.apple.nfcd"
        return DiagItem(name: "Bundle ID (HouseArrest)", status: ok ? .pass : .warn,
                        detail: "current: \(bid)\nexpected: com.apple.nfcd",
                        suggestion: ok ? nil : "改成 com.apple.nfcd 骗系统权限")
    }

    private func checkEntitlements(_ fm: FileManager) -> DiagItem {
        let hasNFCDesc = Bundle.main.object(forInfoDictionaryKey: "NFCReaderUsageDescription") != nil
        let entPath = Bundle.main.path(forResource: nil, ofType: "entitlements", inDirectory: nil)
        let entInBundle = entPath != nil && fm.fileExists(atPath: entPath!)
        let mpPath = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision")
        let mpExists = mpPath != nil && fm.fileExists(atPath: mpPath!)
        return DiagItem(name: "NFC Entitlements",
                        status: (hasNFCDesc || entInBundle) ? .warn : .fail,
                        detail: "Info.plist NFC desc: \(hasNFCDesc ? "✅" : "❌")\n" +
                                ".entitlements in bundle: \(entInBundle ? "✅" : "❌")\n" +
                                "embedded.mobileprovision: \(mpExists ? "✅" : "❌")",
                        suggestion: "用企业证书 + ldid 注入 Resources/NFCClone.entitlements")
    }

    private func checkSandbox(_ fm: FileManager) -> DiagItem {
        let paths = [
            "/private/var/containers/Bundle/Application/",
            "/private/var/containers/Data/System/",
            "/private/var/Keychains/",
            "/etc/passwd",
        ]
        var accessible: [String] = []
        for p in paths { if fm.fileExists(atPath: p) { accessible.append(p) } }
        let ok = accessible.count >= 2
        return DiagItem(name: "Sandbox Escape", status: ok ? .pass : .fail,
                        detail: ok ? "✅ 沙箱已逃逸 (\(accessible.count)/\(paths.count))" :
                                    "❌ 沙箱未逃逸 (\(accessible.count)/\(paths.count))",
                        suggestion: ok ? nil : "需要 no-sandbox entitlement")
    }

    private func checkIOKitRFIC() -> DiagItem {
        let io = IOKitFuncs.shared
        if !io.available {
            return DiagItem(name: "IOKit RFIC 控制器", status: .skip,
                            detail: "⚠️ dlsym 加载 IOKit 失败\n(可能需要 no-sandbox 或 dyld 权限)",
                            suggestion: "企业证书签后再试")
        }
        let names = ["com.apple.NFC.NFCController", "com.apple.NFC",
                     "IOPCINFCController", "IOAppleNFCController", "AppleNFCController"]
        var found: [String] = []
        for n in names { found.append(contentsOf: iokitServices(io: io, matching: n)) }
        if found.isEmpty {
            let all = iokitServices(io: io, matching: "IOService")
            for s in all {
                let l = s.lowercased()
                if l.contains("nfc") || l.contains("pcic") || l.contains("pn549") { found.append(s) }
            }
        }
        let st: DiagStatus = found.count > 0 ? .pass : .warn
        return DiagItem(name: "IOKit RFIC 控制器", status: st,
                        detail: st == .pass ? "✅ 找到 \(found.count) 个:\n\(found.prefix(6).joined(separator: "\n"))" :
                                              "⚠️ IOKit OK 但没找到 NFC (尝试 \(names.count)+ 名字)",
                        suggestion: st != .pass ? "HouseArrest 逃沙箱后应该能看到" : nil)
    }

    private func iokitServices(io: IOKitFuncs, matching name: String) -> [String] {
        var results: [String] = []
        _ = name.withCString { cname -> kern_return_t in
            guard let match = io.matching(cname) else { return KERN_SUCCESS }
            var iter: io_iterator_t = 0
            let kr = io.getMatching(io.port, match, &iter)
            if kr != KERN_SUCCESS { return kr }
            var svc = io.iterNext(iter)
            while svc != 0 {
                if let clsCF = io.objCopyClass(svc) {
                    results.append(clsCF.takeRetainedValue() as String)
                } else {
                    results.append("io_service_t(\(svc))")
                }
                io.objRelease(svc)
                svc = io.iterNext(iter)
            }
            io.objRelease(iter)
            return KERN_SUCCESS
        }
        return results
    }

    private func checkNfcdDaemon(_ fm: FileManager) -> DiagItem {
        let checks = [
            ("/usr/libexec/nfcd", "nfcd 二进制"),
            ("/System/Library/Frameworks/NFC.framework/", "NFC.framework"),
            ("/System/Library/PrivateFrameworks/NFCFramework.framework/", "NFCFramework (私有)"),
        ]
        var details: [String] = []
        var ok = 0
        for (p, label) in checks {
            let exists = fm.fileExists(atPath: p)
            if exists { ok += 1 }
            details.append("\(label): \(exists ? "✅" : "❌")\n  \(p)")
        }
        let st: DiagStatus = ok == checks.count ? .pass : ok > 0 ? .warn : .fail
        return DiagItem(name: "nfcd Daemon (XPC)", status: st,
                        detail: details.joined(separator: "\n"),
                        suggestion: st == .pass ? nil : "nfcd 缺文件 (\(ok)/\(checks.count))")
    }

    private func checkLegacyDeviceNodes(_ fm: FileManager) -> DiagItem {
        let devs = ["/dev/nfcrx", "/dev/nfctx", "/dev/nfc", "/dev/i2c-0", "/dev/i2c-1"]
        var exist: [String] = []
        for d in devs { if fm.fileExists(atPath: d) { exist.append(d) } }
        let iosVer = ProcessInfo.processInfo.operatingSystemVersion.majorVersion
        if iosVer >= 16 {
            return DiagItem(name: "旧 /dev/nfc* 节点", status: .skip,
                            detail: "iOS \(iosVer)+ 已移除 /dev/nfc*\n走 IOKit + nfcd XPC ✅")
        }
        return DiagItem(name: "旧 /dev/nfc*", status: exist.isEmpty ? .warn : .pass,
                        detail: "存在: \(exist.count) — \(exist.joined(separator: ", "))")
    }

    private func checkCoreNFC() -> DiagItem {
        let ok = NFCReaderSession.readingAvailable
        return DiagItem(name: "CoreNFC", status: ok ? .pass : .fail,
                        detail: ok ? "✅ NFCReaderSession 可用" : "❌ 不可用")
    }

    private func checkCardSession() -> DiagItem {
        if #available(iOS 17.4, *) {
            return DiagItem(name: "CardSession HCE", status: .warn,
                            detail: "iOS 17.4+ API 可用\n需 EEA + HCE entitlement",
                            suggestion: "MobileGestalt patch + 地区伪造")
        }
        return DiagItem(name: "CardSession HCE", status: .skip, detail: "需要 iOS 17.4+")
    }

    private func checkFileAccess(_ fm: FileManager) -> DiagItem {
        let tests = [
            ("/private/var/containers/Data/System/com.apple.MobileGestalt/", "MobileGestalt"),
            ("/private/var/Keychains/", "Keychain"),
            ("/System/Library/PrivateFrameworks/NFCFramework.framework/", "NFCFramework"),
            ("/usr/libexec/nfcd", "nfcd"),
        ]
        var ok: [String] = []
        for (p, l) in tests { if fm.fileExists(atPath: p) { ok.append(l) } }
        let st: DiagStatus = ok.count >= 3 ? .pass : ok.count >= 1 ? .warn : .fail
        return DiagItem(name: "关键路径访问", status: st,
                        detail: "✅: \(ok.joined(separator: ", ")) (\(ok.count)/\(tests.count))")
    }

    // MARK: 无物理卡模拟测试

    public func runDummyEmulationTest() -> (success: Bool, log: [String]) {
        var log: [String] = []
        log.append("🧪 Dummy emulation test (no physical card)")
        let fakeUID: [UInt8] = [0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]
        log.append("📦 Fake UID: \(fakeUID.map { String(format: "%02X", $0) }.joined())")
        let iokitOk = checkIOKitRFIC().status == .pass
        let legacyOk = RFICDriver.shared.connect()
        log.append("🔧 IOKit RFIC: \(iokitOk ? "✅" : "❌")")
        log.append("💾 Legacy /dev/nfc*: \(legacyOk ? "✅" : "❌")")
        if legacyOk {
            let targetOk = RFICDriver.shared.enterTargetMode(fakeUID: fakeUID)
            log.append("🎯 Target Mode: \(targetOk ? "✅ 2s 广播" : "❌ failed")")
            if targetOk { Thread.sleep(forTimeInterval: 2); RFICDriver.shared.exitTargetMode() }
        } else if iokitOk {
            log.append("🎯 IOKit OK — 需 CardSession HCE entitlement 才能模拟")
        } else {
            log.append("❌ 没有可用的 NFC 硬件访问路径")
        }
        return (legacyOk || iokitOk, log)
    }
}
