//
//  DiagnosticsEngine.swift
//  NFCClone
//
//  完整诊断引擎 — 不需要物理卡，自检后生成可用性报告
//  v2: iOS 16+ 无 /dev/nfc*，改用 IOKit + nfcd XPC 检测
//  iOS SDK 默认不暴露 IOKit module — 用 @_silgen_name 手写声明
//

import Foundation
import Darwin
import CoreNFC
import UIKit

// IOKit 基础类型手动 typedef（iOS SDK Darwin module 没导出）
#if arch(arm64)
typealias mach_port_t = UInt32
#else
typealias mach_port_t = UInt32
#endif
typealias io_iterator_t = UInt32
typealias io_object_t = UInt32
typealias io_service_t = UInt32
typealias io_registry_entry_t = UInt32
typealias kern_return_t = Int32
let KERN_SUCCESS: kern_return_t = 0

// MARK: - IOKit C bridge（iOS 私有 framework）
// iOS SDK 没有 Swift module，手动声明

@_silgen_name("IOMainPortDefault")
func _IOMainPortDefault() -> mach_port_t

@_silgen_name("IOServiceMatching")
func _IOServiceMatching(_ name: UnsafePointer<Int8>) -> UnsafeMutableRawPointer?

@_silgen_name("IOServiceGetMatchingServices")
func _IOServiceGetMatchingServices(_ masterPort: mach_port_t, _ matchingDict: UnsafeMutableRawPointer?, _ existing: UnsafeMutablePointer<io_iterator_t>) -> kern_return_t

@_silgen_name("IOIteratorNext")
func _IOIteratorNext(_ iterator: io_iterator_t) -> io_service_t

@_silgen_name("IOObjectRelease")
func _IOObjectRelease(_ object: io_object_t) -> kern_return_t

@_silgen_name("IOObjectCopyClass")
func _IOObjectCopyClass(_ object: io_object_t) -> Unmanaged<CFString>?


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
        var items: [DiagItem] = []
        items.append(checkDevice())
        items.append(checkBundleID())
        items.append(checkEntitlements())
        items.append(checkSandbox())
        items.append(checkIOKitRFIC())
        items.append(checkNfcdDaemonXPC())
        items.append(checkLegacyDeviceNodes())
        items.append(checkCoreNFC())
        items.append(checkCardSession())
        items.append(checkFileAccess())
        return DiagReport(timestamp: Date(), device: UIDevice.current.model,
                          osVersion: UIDevice.current.systemVersion, items: items)
    }

    // MARK: - 单项

    private func checkDevice() -> DiagItem {
        var u = utsname()
        _ = Darwin.uname(&u)
        let machine = withUnsafeBytes(of: &u.machine) { b in
            String(cString: b.baseAddress!.assumingMemoryBound(to: CChar.self))
        }
        let ok = machine.hasPrefix("iPhone12") || machine.hasPrefix("iPhone13") ||
                 machine.hasPrefix("iPhone14") || machine.hasPrefix("iPhone15") ||
                 machine.hasPrefix("iPhone16") || machine.contains("arm64e")
        let chipMap = [
            "iPhone12": "A14",
            "iPhone13": "A15",
            "iPhone14": "A16",
            "iPhone15": "A17",
            "iPhone16": "A18",
        ]
        let chip = chipMap.first { machine.hasPrefix($0.key) }?.value ?? "Apple Silicon"
        return DiagItem(name: "Device", status: ok ? .pass : .warn,
                        detail: "\(UIDevice.current.model) — \(machine)\n\(chip)",
                        suggestion: ok ? nil : "A14+ 才支持完整 NFC")
    }

    private func checkBundleID() -> DiagItem {
        let bid = Bundle.main.bundleIdentifier ?? "(none)"
        let ok = bid == "com.apple.nfcd"
        return DiagItem(name: "Bundle ID (HouseArrest)", status: ok ? .pass : .warn,
                        detail: "current: \(bid)\nexpected: com.apple.nfcd",
                        suggestion: ok ? nil : "改成 com.apple.nfcd 骗系统权限")
    }

    private func checkEntitlements() -> DiagItem {
        let fm = FileManager.default
        let hasNFCDesc = Bundle.main.object(forInfoDictionaryKey: "NFCReaderUsageDescription") != nil
        let entPath = Bundle.main.path(forResource: nil, ofType: "entitlements", inDirectory: nil)
        let fileExists = entPath != nil && fm.fileExists(atPath: entPath!)
        let mpPath = Bundle.main.path(forResource: "embedded", ofType: "mobileprovision")
        let mpExists = mpPath != nil && fm.fileExists(atPath: mpPath!)
        return DiagItem(name: "NFC Entitlements",
                        status: (hasNFCDesc || fileExists) ? .warn : .fail,
                        detail: "Info.plist NFC desc: \(hasNFCDesc ? "✅" : "❌")\n" +
                                ".entitlements in bundle: \(fileExists ? "✅" : "❌")\n" +
                                "embedded.mobileprovision: \(mpExists ? "✅" : "❌")",
                        suggestion: "用企业证书 + ldid 注入 Resources/NFCClone.entitlements")
    }

    private func checkSandbox() -> DiagItem {
        let fm = FileManager.default
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
        let serviceNames = [
            "com.apple.NFC.NFCController",
            "com.apple.NFC",
            "IOPCINFCController",
            "IOAppleNFCController",
            "AppleNFCController",
        ]
        var found: [String] = []
        let port = _IOMainPortDefault()

        for name in serviceNames {
            found.append(contentsOf: findIOServices(matching: name, port: port))
        }

        if found.isEmpty {
            let all = findIOServices(matching: "IOService", port: port)
            for s in all {
                let lower = s.lowercased()
                if lower.contains("nfc") || lower.contains("pcic") || lower.contains("pn549") {
                    found.append(s)
                }
            }
        }

        let st: DiagStatus = found.count > 0 ? .pass : .warn
        return DiagItem(name: "IOKit RFIC 控制器", status: st,
                        detail: st == .pass ? "✅ 找到 \(found.count) 个:\n\(found.prefix(6).joined(separator: "\n"))" :
                                              "⚠️ IOKit 没找到 (尝试了 \(serviceNames.count)+ 个名字)",
                        suggestion: st != .pass ? "HouseArrest 逃沙箱后应该能看到" : nil)
    }

    private func findIOServices(matching name: String, port: mach_port_t) -> [String] {
        var results: [String] = []
        let _ = name.withCString { cname -> kern_return_t in
            guard let match = _IOServiceMatching(cname) else { return KERN_SUCCESS }
            var iter: io_iterator_t = 0
            let kr = _IOServiceGetMatchingServices(port, match, &iter)
            if kr != KERN_SUCCESS { return kr }
            var svc = _IOIteratorNext(iter)
            while svc != 0 {
                if let clsCF = _IOObjectCopyClass(svc) {
                    let cls = clsCF.takeRetainedValue() as String
                    results.append(cls)
                } else {
                    results.append("io_service_t(\(svc))")
                }
                _IOObjectRelease(svc)
                svc = _IOIteratorNext(iter)
            }
            _IOObjectRelease(iter)
            return KERN_SUCCESS
        }
        return results
    }

    private func checkNfcdDaemonXPC() -> DiagItem {
        var details: [String] = []
        let fm = FileManager.default

        let pipe = Pipe()
        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: "/bin/ps")
        proc.arguments = ["-axo", "pid,comm"]
        proc.standardOutput = pipe
        proc.standardError = Pipe()
        var nfcdRunning = false
        do {
            try proc.run()
            proc.waitUntilExit()
            let psOut = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            for line in psOut.components(separatedBy: "\n") {
                if line.contains("nfcd") && !line.contains("grep") {
                    nfcdRunning = true
                    details.append("进程: ✅ \(line.trimmingCharacters(in: .whitespacesAndNewlines))")
                }
            }
        } catch { details.append("ps 失败: \(error.localizedDescription)") }
        if !nfcdRunning { details.append("进程: ❌ nfcd 未运行") }

        let nfcdBin = "/usr/libexec/nfcd"
        let hasBin = fm.fileExists(atPath: nfcdBin)
        details.append("nfcd 二进制: \(hasBin ? "✅" : "❌")")

        let hasPriv = fm.fileExists(atPath: "/System/Library/PrivateFrameworks/NFCFramework.framework/")
        let hasPub = fm.fileExists(atPath: "/System/Library/Frameworks/NFC.framework/")
        details.append("NFC.framework: \(hasPub ? "✅" : "❌")")
        details.append("NFCFramework (私有): \(hasPriv ? "✅" : "❌")")

        let st: DiagStatus = nfcdRunning && hasBin ? .pass : hasBin ? .warn : .fail
        return DiagItem(name: "nfcd Daemon (XPC)", status: st,
                        detail: details.joined(separator: "\n"),
                        suggestion: st == .pass ? nil : "nfcd 缺进程或二进制")
    }

    private func checkLegacyDeviceNodes() -> DiagItem {
        let devs = ["/dev/nfcrx", "/dev/nfctx", "/dev/nfc", "/dev/i2c-0", "/dev/i2c-1"]
        var exist: [String] = []
        for d in devs { if FileManager.default.fileExists(atPath: d) { exist.append(d) } }
        let iosVer = ProcessInfo.processInfo.operatingSystemVersion.majorVersion
        if iosVer >= 16 {
            return DiagItem(name: "旧 /dev/nfc* 节点 (Legacy)", status: .skip,
                            detail: "iOS \(iosVer)+ 已移除\n走 IOKit + nfcd XPC 路径 ✅")
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

    private func checkFileAccess() -> DiagItem {
        let fm = FileManager.default
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

    // MARK: - 无物理卡模拟测试

    public func runDummyEmulationTest() -> (success: Bool, log: [String]) {
        var log: [String] = []
        log.append("🧪 Dummy emulation test (no physical card)")
        let fakeUID: [UInt8] = [0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]
        log.append("📦 Fake UID: \(fakeUID.map { String(format: "%02X", $0) }.joined())")

        let iokitOk = checkIOKitRFIC().status == .pass
        let xpcOk = checkNfcdDaemonXPC().status == .pass
        let legacyOk = RFICDriver.shared.connect()
        log.append("🔧 IOKit RFIC: \(iokitOk ? "✅" : "❌")")
        log.append("📡 nfcd daemon: \(xpcOk ? "✅" : "❌")")
        log.append("💾 Legacy /dev/nfc*: \(legacyOk ? "✅" : "❌")")

        if legacyOk {
            let targetOk = RFICDriver.shared.enterTargetMode(fakeUID: fakeUID)
            log.append("🎯 Target Mode: \(targetOk ? "✅ 2s 广播成功" : "❌ failed")")
            if targetOk { Thread.sleep(forTimeInterval: 2); RFICDriver.shared.exitTargetMode() }
        } else if iokitOk && xpcOk {
            log.append("🎯 nfcd XPC 路径 — 需 CardSession HCE entitlement")
        } else {
            log.append("❌ 所有 NFC 访问路径都不可用")
        }
        return (legacyOk || iokitOk, log)
    }
}
