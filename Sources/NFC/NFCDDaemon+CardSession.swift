//
//  NFCDDaemon+CardSession.swift
//  NFCClone
//

import Foundation
import CoreNFC

// MARK: - nfcd 守护进程通信

public class NFCDDaemon {

    public static let shared = NFCDDaemon()
    private var deviceRef: NSObject?
    private init() {}

    public func connect() -> Bool {
        // 在真正的设备上，需要 dlopen /System/Library/PrivateFrameworks/NFCFramework.framework
        // 这里在编译时保持 stub，避免动态链接私有框架的复杂性
        NSLog("[NFCDDaemon] connect() — needs no-sandbox entitlement on real device")
        return false
    }

    public func disconnect() {
        deviceRef = nil
    }

    public func setTargetMode(_ enabled: Bool, fakeUID: Data? = nil) -> Bool {
        NSLog("[NFCDDaemon] setTargetMode(\(enabled)) — stub (needs NFCFramework access)")
        return false
    }
}

// MARK: - CardSession HCE 绕过

public final class CardSessionBypass {

    public static let shared = CardSessionBypass()
    private init() {}

    public func checkEligibility() -> (supported: Bool, eligible: Bool, error: String?) {
        let supported = NFCReaderSession.readingAvailable

        if #available(iOS 17.4, *) {
            // CardSession.isEligible 在新版 iOS 上可能是 async
            // 这里只返回 supported 状态
            return (supported, false, "CardSession needs EEA + enterprise HCE entitlement")
        }
        return (supported, false, "CardSession requires iOS 17.4+")
    }

    public func bypassIsEligible() -> Bool {
        NSLog("[CardSessionBypass] Attempting bypass...")

        // 1. 伪造地区
        UserDefaults.standard.set("FR", forKey: "AppleCountryCode")
        UserDefaults.standard.set(["fr", "en"], forKey: "AppleLanguages")

        // 2. Patch MobileGestalt（需要 no-sandbox）
        FilzaSlopExploit.shared.patchNFCGestalts()

        return false // 是否成功需要运行时检查
    }
}
