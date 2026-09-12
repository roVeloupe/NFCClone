//
//  NFCDDaemon+CardSession.swift
//  NFCClone
//
//  NFC 守护进程通信 + CardSession HCE 绕过
//  这里封装了跟系统 nfcd 交互的两种方式：
//  1. dlopen NFCFramework 用私有类
//  2. CardSession HCE（iOS 17.4+）
//

import Foundation
import CoreNFC

// MARK: - libSystem 私有 API

@_silgen_name("dlopen")
func dlopen(_ path: UnsafePointer<Int8>?, _ mode: Int32) -> UnsafeMutableRawPointer?

@_silgen_name("dlclose")
func dlclose(_ handle: UnsafeMutableRawPointer?) -> Int32

@_silgen_name("dlsym")
func dlsym(_ handle: UnsafeMutableRawPointer?, _ symbol: UnsafePointer<Int8>) -> UnsafeMutableRawPointer?

// MARK: - nfcd Daemon

public class NFCDDaemon {

    public static let shared = NFCDDaemon()

    private var frameworkHandle: UnsafeMutableRawPointer?
    private var proxy: NSObject?

    private init() {}

    public func connect() -> Bool {
        // 加载私有 NFCFramework
        let path = "/System/Library/PrivateFrameworks/NFCFramework.framework/NFCFramework"
        guard let handle = dlopen(path, RTLD_NOW | RTLD_LOCAL) else {
            NSLog("[NFCDDaemon] Cannot open NFCFramework: \(String(cString: dlerror()))")
            return false
        }
        self.frameworkHandle = handle
        NSLog("[NFCDDaemon] NFCFramework loaded")

        // 找 NFCCoreDevice
        guard let clsPtr = dlsym(handle, "NFCCoreDevice") else {
            NSLog("[NFCDDaemon] NFCCoreDevice not found")
            return false
        }

        let cls = unsafeBitCast(clsPtr, to: AnyClass.self)

        // 获取 shared instance
        let sel = NSSelectorFromString("sharedDevice")
        if let instance = cls.perform(sel) as? NSObject {
            NSLog("[NFCDDaemon] Got NFCCoreDevice: \(instance)")
            self.proxy = instance
            instance.perform(NSSelectorFromString("beginSession"))
            return true
        }

        return false
    }

    public func disconnect() {
        if let p = proxy {
            p.perform(NSSelectorFromString("endSession"))
        }
        if let h = frameworkHandle {
            dlclose(h)
        }
        proxy = nil
        frameworkHandle = nil
    }

    public func sendRawCommand(_ command: Data) -> Data? {
        guard let p = proxy else { return nil }

        if let rfCtrl = p.value(forKey: "rfController") as? NSObject {
            let sel = NSSelectorFromString("transmitAPDU:")
            if rfCtrl.responds(to: sel) {
                let resp = rfCtrl.perform(sel, with: command)
                return resp as? Data
            }
        }
        return nil
    }

    public func setTargetMode(_ enabled: Bool, fakeUID: Data? = nil) -> Bool {
        guard let p = proxy else { return false }

        if let sessionMgr = p.value(forKey: "sessionManager") as? NSObject {
            let sel = NSSelectorFromString(enabled ? "enterTargetMode:" : "exitTargetMode")
            if sessionMgr.responds(to: sel) {
                if enabled, let uid = fakeUID {
                    sessionMgr.perform(sel, with: uid)
                } else {
                    sessionMgr.perform(sel)
                }
                return true
            }
        }
        return false
    }
}

// MARK: - CardSession HCE 绕过

/// CardSession 在 iOS 17.4+ 可用，且被限制 EEA 地区 + 企业证书 entitlement
/// 这里封装检查 + 绕过逻辑
public final class CardSessionBypass {

    public static let shared = CardSessionBypass()
    private init() {}

    public func checkEligibility() -> (supported: Bool, eligible: Bool, error: String?) {
        let supported = NFCReaderSession.readingAvailable
        if #available(iOS 17.4, *) {
            // isEligible 在新版可能是 async，这里只检查 supported
            return (supported, false, "CardSession eligibility check needs runtime call")
        }
        return (supported, false, "CardSession requires iOS 17.4+")
    }

    public func bypassIsEligible() -> Bool {
        NSLog("[CardSessionBypass] Attempting isEligible bypass...")

        // 方法 1: 伪造地区
        UserDefaults.standard.set("FR", forKey: "AppleCountryCode")
        UserDefaults.standard.set(["fr", "en"], forKey: "AppleLanguages")

        // 方法 2: 重启 nfcd 让它重新读配置
        FilzaSlopExploit.shared.patchNFCGestalts()

        if #available(iOS 17.4, *) {
            return false  // isEligible 可能是 async，留 stub
        }
        return false
    }

    @available(iOS 17.4, *)
    public func startEmulation(apduHandler: @escaping (Data) -> Data) {
        Task {
            let session = CardSession()

            for await event in session.eventStream {
                switch event {
                case .sessionStarted:
                    NSLog("[CardSession] Session started")
                case .readerDetected:
                    NSLog("[CardSession] Reader detected — starting emulation")
                    try? session.startEmulation()
                case .readerDeselected:
                    NSLog("[CardSession] Reader gone")
                    session.stopEmulation(status: .success)
                case .apdu(let apduRequest):
                    let response = apduHandler(apduRequest.payload)
                    try? apduRequest.respond(response: response)
                @unknown default:
                    break
                }
            }
        }
    }
}
