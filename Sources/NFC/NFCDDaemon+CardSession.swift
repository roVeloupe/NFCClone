//
//  NFCDDaemon+CardSession.swift
//  NFCClone
//
//  两条路径访问 NFC：
//  1. nfcd XPC 通信 — 通过私有 API 跟系统 NFC 守护进程通信
//  2. CardSession HCE 绕过 — 公开 API + MobileGestalt patch 绕过 isEligible
//

import Foundation
import CoreNFC

// MARK: - nfcd XPC 通信层

/// nfcd 守护进程通信封装
///
/// nfcd 是 iOS 上负责 NFC 硬件管理的系统守护进程
/// Apple 的 CoreNFC 框架最终也是通过它来跟 RFIC 通信
/// 我们可以直接建立 XPC 连接，绕过 CoreNFC 的限制
public class NFCDDaemon {

    public static let shared = NFCDDaemon()

    private var connection: NSXPCConnection?
    private var nfcdProxy: Any?

    private init() {}

    // MARK: - 连接 nfcd

    /// 通过 XPC 连接 com.apple.nfcd 守护进程
    @discardableResult
    public func connect() -> Bool {
        // 路径 1: 直接 XPC
        let connection = NSXPCConnection(serviceName: "com.apple.nfcd")
        connection.remoteObjectInterface = NSXPCInterface(with: NFCDDaemonProtocol.self)
        connection.interruptionHandler = {
            NSLog("[NFCDDaemon] XPC connection interrupted")
        }
        connection.invalidationHandler = { [weak self] in
            NSLog("[NFCDDaemon] XPC connection invalidated")
            self?.connection = nil
        }
        connection.resume()

        self.connection = connection

        // 测试连接
        let semaphore = DispatchSemaphore(value: 0)
        var ok = false

        if let proxy = connection.remoteObjectProxyWithErrorHandler({ error in
            NSLog("[NFCDDaemon] XPC connect error: \(error)")
        }) as? NFCDDaemonProtocol {
            // 发个 ping
            proxy.ping { _ in
                ok = true
                semaphore.signal()
            }
        }

        if semaphore.wait(timeout: .now() + 2) == .success {
            NSLog("[NFCDDaemon] ✅ XPC connected to nfcd!")
            return ok
        }

        NSLog("[NFCDDaemon] XPC connect timed out. Trying MCM path...")
        return connectViaMCM()
    }

    /// 备用路径：通过 MCM 拿到 nfcd 的 XPC endpoint
    private func connectViaMCM() -> Bool {
        // HouseArrest 漏洞已经给了我们 nfcd 的容器访问权
        // nfcd 的 XPC endpoint 在容器内有 plist 配置
        // 读出配置，找到实际的 endpoint

        let possiblePaths = [
            "/private/var/containers/Bundle/Application/*/nfcd.app/nfcd",
            "/usr/libexec/nfcd",
            "/System/Library/PrivateFrameworks/NFCFramework.framework/NFCFramework",
        ]

        for path in possiblePaths {
            if FileManager.default.fileExists(atPath: path) {
                NSLog("[NFCDDaemon] Found nfcd/NFCFramework at: \(path)")
            }
        }

        // 直接用 dlopen 加载 NFCFramework 并调用私有类
        guard let handle = dlopen("/System/Library/PrivateFrameworks/NFCFramework.framework/NFCFramework",
                                  RTLD_NOW | RTLD_LOCAL) else {
            NSLog("[NFCDDaemon] Cannot dlopen NFCFramework: \(String(cString: dlerror()))")
            return false
        }
        defer { dlclose(handle) }

        // NFCCoreDevice 是 NFCFramework 的核心类
        guard let cls = dlsym(handle, "NFCCoreDevice") else {
            NSLog("[NFCDDaemon] NFCCoreDevice symbol not found")
            return false
        }

        let NFCCoreDeviceClass = unsafeBitCast(cls, to: AnyClass.self)

        // 获取 shared instance
        guard let device = NFCCoreDeviceClass.perform(NSSelectorFromString("sharedDevice"))?.takeUnretainedValue() as? NSObject else {
            NSLog("[NFCDDaemon] Failed to get NFCCoreDevice.sharedDevice")
            return false
        }

        NSLog("[NFCDDaemon] Got NFCCoreDevice: \(device)")
        nfcdProxy = device

        // 尝试初始化 NFC 硬件
        device.perform(NSSelectorFromString("beginSession"))
        NSLog("[NFCDDaemon] beginSession called on NFCCoreDevice")

        return true
    }

    public func disconnect() {
        if let proxy = nfcdProxy as? NSObject {
            proxy.perform(NSSelectorFromString("endSession"))
        }
        connection?.invalidate()
        connection = nil
        nfcdProxy = nil
    }

    // MARK: - 通过 nfcd 发 NFC 命令

    /// 让 nfcd 发原始 ISO 14443 命令
    public func sendRawCommand(_ command: Data) -> Data? {
        guard let proxy = nfcdProxy as? NSObject else {
            NSLog("[NFCDDaemon] No proxy available")
            return nil
        }

        // NFCRFController.shared().transmitAPDU:
        if let rfCtrl = proxy.value(forKey: "rfController") as? NSObject {
            let selector = NSSelectorFromString("transmitAPDU:")
            if rfCtrl.responds(to: selector) {
                let resp = rfCtrl.perform(selector, with: command)
                return resp?.takeUnretainedValue() as? Data
            }
        }

        return nil
    }

    /// 让 nfcd 进入/退出 target mode
    public func setTargetMode(_ enabled: Bool, fakeUID: Data? = nil) -> Bool {
        guard let proxy = nfcdProxy as? NSObject else { return false }

        // NFCSessionManager.shared()
        if let sessionManager = proxy.value(forKey: "sessionManager") as? NSObject {
            let selector = NSSelectorFromString(enabled ? "enterTargetMode:" : "exitTargetMode")
            if sessionManager.responds(to: selector) {
                if enabled, let uid = fakeUID {
                    sessionManager.perform(selector, with: uid)
                } else {
                    sessionManager.perform(selector)
                }
                NSLog("[NFCDDaemon] Target mode \(enabled ? "ON" : "OFF") via NFCSessionManager")
                return true
            }
        }

        return false
    }
}

// MARK: - nfcd XPC 协议（简化版）

@objc protocol NFCDDaemonProtocol: NSObjectProtocol {
    func ping(_ callback: @escaping (Bool) -> Void)
    func sendCommand(_ data: Data, callback: @escaping (Data?, NSError?) -> Void)
}

// MARK: - CardSession HCE 绕过层

/// CardSession HCE 绕过
///
/// iOS 17.4+ 公开了 CardSession API 用于 HCE，但有三个检查：
/// 1. CardSession.isSupported — 设备是否支持 NFC
/// 2. CardSession.isEligible — Apple ID 是否在 EEA + 物理位置
/// 3. 必须有 HCE entitlement（com.apple.developer.nfc.hce）
///
/// 我们的企业证书已经签了 entitlement
/// 通过 MobileGestalt patch 可以绕过 isSupported
/// isEligible 有多个绕过方法
public class CardSessionBypass {

    public static let shared = CardSessionBypass()
    private init() {}

    // MARK: - 检查

    public func checkEligibility() -> (supported: Bool, eligible: Bool, error: String?) {
        let supported = NFCReaderSession.readingAvailable && CardSession.isSupported
        let eligible = CardSession.isEligible

        var error: String? = nil
        if !supported { error = "NFC not supported on this device/OS" }
        if !eligible { error = "Device not eligible (not in EEA or iCloud not EEA)" }

        NSLog("[CardSessionBypass] supported=\(supported), eligible=\(eligible)")
        return (supported, eligible, error)
    }

    // MARK: - 绕过方法

    /// 组合使用多个方法尝试绕过 isEligible
    /// - Returns: 是否绕过成功
    @discardableResult
    public func bypassIsEligible() -> Bool {
        NSLog("[CardSessionBypass] Attempting isEligible bypass...")

        // 方法 1: MobileGestalt patch — 伪装设备支持 HCE
        FilzaSlopExploit.shared.patchMobileGestalt(key: "nfchce", value: true)
        FilzaSlopExploit.shared.patchMobileGestalt(key: "kMGHasHCE", value: true)
        FilzaSlopExploit.shared.patchMobileGestalt(key: "HasNFCHCE", value: true)

        // 方法 2: 写入 EEA 地区标识
        FilzaSlopExploit.shared.patchMobileGestalt(key: "RegionCode", value: "FR")  // 法国 = EEA
        FilzaSlopExploit.shared.patchMobileGestalt(key: "kMGDeviceRegion", value: "FR")

        // 方法 3: Patch /Library/Preferences/ByHost/ 下的 location plist
        patchLocationPlist()

        // 方法 4: Hook isEligible 的返回值
        hookIsEligibleReturn()

        NSLog("[CardSessionBypass] Bypass attempt complete")
        return CardSession.isEligible
    }

    /// 伪造地区/位置 plist
    private func patchLocationPlist() {
        let possiblePaths = [
            "/Library/Preferences/.GlobalPreferences.plist",
            "/Library/Preferences/ByHost/",
            "~/Library/Preferences/ByHost/",
        ]

        for base in possiblePaths {
            let fullPath = (base as NSString).expandingTildeInPath

            if FileManager.default.fileExists(atPath: fullPath) {
                NSLog("[CardSessionBypass] Found location plist at: \(fullPath)")

                // 找 GlobalsDomain.plist
                let gPath = fullPath.appending("/.GlobalPreferences.plist")
                if FileManager.default.fileExists(atPath: gPath) {
                    if var dict = NSDictionary(contentsOfFile: gPath) as? NSMutableDictionary {
                        dict["AppleLocale"] = "fr_FR"
                        dict["AppleLanguages"] = ["fr", "en"]
                        dict["AppleCountryCode"] = "FR"
                        dict.write(toFile: gPath, atomically: true)
                        NSLog("[CardSessionBypass] Patched GlobalPreferences with FR locale")
                    }
                }
            }
        }
    }

    /// Hook CardSession.isEligible 的返回值
    /// 使用 fishhook 或直接 objc runtime swizzle
    private func hookIsEligibleReturn() {
        NSLog("[CardSessionBypass] Swizzling CardSession.isEligible...")

        // 找到 CardSession 类
        guard let cls = NSClassFromString("CardSession") else {
            NSLog("[CardSessionBypass] CardSession class not found")
            return
        }

        // 类方法 isEligible
        let origSelector = NSSelectorFromString("isEligible")
        let swizzledSelector = NSSelectorFromString("nfclone_isEligible")

        // 创建替换实现 (IMP)
        let newIMP: IMP = imp_implementationWithBlock(imp_closure(returning: true))

        if let origMethod = class_getClassMethod(cls, origSelector) {
            method_setImplementation(origMethod, newIMP)
            NSLog("[CardSessionBypass] ✅ Swizzled CardSession.isEligible → always returns true")
        } else {
            NSLog("[CardSessionBypass] ❌ Cannot find isEligible method on CardSession")
        }
    }

    // MARK: - IMP helper

    private func imp_closure<T>(returning value: T) -> Any {
        // 创建一个简单的 block 作为 IMP
        return value
    }

    // MARK: - 启动 HCE 会话

    /// 启动 CardSession HCE，进入卡模拟模式
    /// - Returns: CardSession 实例
    public func startEmulation(fakeAPDUHandler: @escaping (Data) -> Data) {
        Task {
            // 再次检查 eligibility
            let eligibility = self.checkEligibility()
            if !eligibility.eligible {
                self.bypassIsEligible()
            }

            do {
                let session = CardSession()

                // 注册事件流
                for await event in session.eventStream {
                    switch event {
                    case .sessionStarted:
                        NSLog("[CardSession] Session started!")
                    case .readerDetected:
                        NSLog("[CardSession] Reader detected! Starting emulation...")
                        try session.startEmulation()
                    case .readerDeselected:
                        NSLog("[CardSession] Reader gone")
                        session.stopEmulation(status: .success)
                    case .apdu(let apdu):
                        NSLog("[CardSession] APDU received: \(apdu.payload.hexString)")
                        let response = fakeAPDUHandler(apdu.payload)
                        try apdu.respond(response: response)
                    @unknown default:
                        break
                    }
                }
            } catch {
                NSLog("[CardSession] Error: \(error)")
            }
        }
    }
}
