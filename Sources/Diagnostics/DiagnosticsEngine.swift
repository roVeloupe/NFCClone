//
//  DiagnosticsEngine.swift
//  NFCClone
//
//  完整诊断引擎 — 不需要物理卡，自检后生成可用性报告
//

import Foundation
import Darwin
import CoreNFC

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
        let r = items.first { $0.name == "RFIC Driver Access" }?.status
        let e = items.first { $0.name == "NFC Entitlements" }?.status
        return s == .pass && r == .pass && e == .pass
    }
}

public class DiagnosticsEngine {
    public static let shared = DiagnosticsEngine()
    private init() {}

    public func runFullDiagnostics() -> DiagReport {
        var items: [DiagItem] = []
        items.append(checkDevice())
        items.append(checkBundleID())
        items.append(checkEntitlements())
        items.append(checkSandbox())
        items.append(checkRFICDevices())
        items.append(checkNFCDDaemon())
        items.append(checkCoreNFC())
        items.append(checkCardSession())
        items.append(checkFileAccess())
        return DiagReport(timestamp: Date(), device: UIDevice.current.model,
                          osVersion: UIDevice.current.systemVersion, items: items)
    }

    private func checkDevice() -> DiagItem {
        var u = utsname()
        _ = Darwin.uname(&u)
        let machine = withUnsafeBytes(of: &u.machine) { b in
            String(cString: b.baseAddress!.assumingMemoryBound(to: CChar.self))
        }
        let ok = machine.contains("iPhone12") || machine.contains("arm64e")
        return DiagItem(name: "Device", status: ok ? .pass : .warn,
                        detail: "\(UIDevice.current.model) — machine: \(machine)",
                        suggestion: "Target: iPhone 12 (A14)")
    }

    private func checkBundleID() -> DiagItem {
        let bid = Bundle.main.bundleIdentifier ?? "(none)"
        let ok = bid == "com.apple.nfcd"
        return DiagItem(name: "Bundle ID (HouseArrest)", status: ok ? .pass : .warn,
                        detail: "current: \(bid)\nexpected: com.apple.nfcd",
                        suggestion: ok ? nil : "改成 com.apple.nfcd")
    }

    private func checkEntitlements() -> DiagItem {
        let fm = FileManager.default
        let hasNFCDesc = Bundle.main.object(forInfoDictionaryKey: "NFCReaderUsageDescription") != nil
        // 直接从磁盘读 entitlements 文件（如果被 Xcode 留在 app bundle 里）
        let entPath = Bundle.main.path(forResource: nil, ofType: "entitlements", inDirectory: nil)
        let fileExists = entPath != nil && fm.fileExists(atPath: entPath!)
        return DiagItem(name: "NFC Entitlements",
                        status: (hasNFCDesc || fileExists) ? .warn : .fail,
                        detail: "Info.plist NFC desc: \(hasNFCDesc ? "✅" : "❌")\n.entitlements in bundle: \(fileExists ? "✅" : "❌")",
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
                                    "❌ 沙箱未逃逸 — 只能访问 \(accessible.count)/\(paths.count)",
                        suggestion: ok ? nil : "需要 no-sandbox entitlement")
    }

    private func checkRFICDevices() -> DiagItem {
        let devs = ["/dev/nfcrx", "/dev/nfctx", "/dev/nfc", "/dev/i2c-0", "/dev/i2c-1"]
        var exist: [String] = []
        var writable: [String] = []
        for d in devs {
            if FileManager.default.fileExists(atPath: d) {
                exist.append(d)
                let fd = open(d, O_RDWR)
                if fd >= 0 { writable.append(d); close(fd) }
            }
        }
        let st: DiagStatus = writable.count > 0 ? .pass : exist.count > 0 ? .warn : .fail
        return DiagItem(name: "RFIC Driver Access", status: st,
                        detail: "存在: \(exist.count) — \(exist.joined(separator: ", "))\n可写: \(writable.count) — \(writable.joined(separator: ", "))",
                        suggestion: st != .pass ? "需要 no-sandbox 才能 open /dev/nfc*" : nil)
    }

    private func checkNFCDDaemon() -> DiagItem {
        let fm = FileManager.default
        let paths = [
            "/System/Library/Frameworks/NFC.framework/",
            "/System/Library/PrivateFrameworks/NFCFramework.framework/",
            "/usr/libexec/nfcd",
        ]
        var ok: [String] = []
        for p in paths { if fm.fileExists(atPath: p) { ok.append(p) } }
        return DiagItem(name: "nfcd Daemon", status: ok.count > 0 ? .pass : .warn,
                        detail: "可用路径: \(ok.count)\n\(ok.joined(separator: "\n"))")
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
        ]
        var ok: [String] = []
        for (p, l) in tests { if fm.fileExists(atPath: p) { ok.append(l) } }
        let st: DiagStatus = ok.count >= 2 ? .pass : ok.count >= 1 ? .warn : .fail
        return DiagItem(name: "关键路径访问", status: st,
                        detail: "✅: \(ok.joined(separator: ", ")) (\(ok.count)/\(tests.count))")
    }

    // MARK: - 无需物理卡的模拟测试

    public func runDummyEmulationTest() -> (success: Bool, log: [String]) {
        var log: [String] = []
        log.append("🧪 Dummy emulation test (no physical card needed)")
        let fakeUID: [UInt8] = [0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE]
        log.append("📦 Fake UID: \(fakeUID.map { String(format: "%02X", $0) }.joined())")

        let fdOk = RFICDriver.shared.connect()
        log.append("📡 RFIC connect: \(fdOk ? "✅" : "❌")")

        if fdOk {
            let targetOk = RFICDriver.shared.enterTargetMode(fakeUID: fakeUID)
            log.append("🎯 Target Mode: \(targetOk ? "✅ active (2s)" : "❌ failed")")
            if targetOk {
                Thread.sleep(forTimeInterval: 2)
                RFICDriver.shared.exitTargetMode()
                log.append("⏹️ Target Mode exited")
            }
        }
        return (fdOk, log)
    }
}
