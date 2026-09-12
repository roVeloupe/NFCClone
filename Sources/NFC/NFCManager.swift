//
//  NFCManager.swift
//  NFCClone
//
//  统一的 NFC 管理器
//  把 RFIC 驱动、nfcd XPC、CardSession 三条路径整合在一起
//  提供简洁的高层 API
//

import Foundation
import CoreNFC

/// NFC 卡片类型
public enum NFCCardType: String, Codable {
    case mifareClassic1K
    case mifareClassic4K
    case mifareUltralight
    case ntag213
    case ntag215
    case ntag216
    case desfire
    case felica
    case unknown

    public var displayName: String {
        switch self {
        case .mifareClassic1K:  return "MIFARE Classic 1K"
        case .mifareClassic4K:  return "MIFARE Classic 4K"
        case .mifareUltralight: return "MIFARE Ultralight"
        case .ntag213:          return "NTAG 213"
        case .ntag215:          return "NTAG 215"
        case .ntag216:          return "NTAG 216"
        case .desfire:          return "MIFARE DESFire"
        case .felica:           return "FeliCa"
        case .unknown:          return "未知类型"
        }
    }
}

/// NFC 卡片完整快照
public struct NFCCardSnapshot: Codable, Identifiable {
    public let id = UUID()
    public var uid: [UInt8]
    public var type: NFCCardType
    public var atqa: [UInt8]
    public var sak: UInt8
    public var blocks: [UInt8: [UInt8]]      // MIFARE Classic: block → data
    public var ndefPayload: [UInt8]?        // NDEF 标签的话存这里
    public var timestamp: Date

    public init(uid: [UInt8], type: NFCCardType, atqa: [UInt8], sak: UInt8,
                blocks: [UInt8: [UInt8]] = [:], ndefPayload: [UInt8]? = nil) {
        self.uid = uid
        self.type = type
        self.atqa = atqa
        self.sak = sak
        self.blocks = blocks
        self.ndefPayload = ndefPayload
        self.timestamp = Date()
    }

    public var uidHex: String { uid.hexString }
    public var blockCount: Int { blocks.count }
}

/// 统一 NFC 管理器
public class NFCManager {

    public static let shared = NFCManager()

    public private(set) var isInitialized = false
    public private(set) var device: String = ""

    private init() {}

    // MARK: - 初始化

    /// 初始化整个 NFC 子系统（漏洞利用 + 驱动连接）
    @discardableResult
    public func initialize() -> Bool {
        NSLog("[NFCManager] === Initializing NFC Clone v1.0 ===")

        // 检查设备
        let sysinfo = utsname()
        var sysinfo = utsname()
        _ = withUnsafeMutableBytes(of: &sysinfo.machine) { ptr in
            device = String(bytes: ptr, encoding: .utf8)?
                .trimmingCharacters(in: CharacterSet(charactersIn: "\0")) ?? "unknown"
        }
        NSLog("[NFCManager] Device: \(device)")

        // 检查沙箱状态
        let escaped = FilzaSlopExploit.shared.isSandboxEscaped()
        NSLog("[NFCManager] Sandbox escaped: \(escaped)")

        // Step 1: 跑漏洞链
        NSLog("[NFCManager] Step 1: Running FilzaSlop exploit chain...")
        FilzaSlopExploit.shared.runFullExploit()

        // Step 2: Patch MobileGestalt NFC capability
        NSLog("[NFCManager] Step 2: Patching MobileGestalt NFC bits...")
        FilzaSlopExploit.shared.patchNFCGestalts()

        // Step 3: 尝试连接 RFIC 驱动
        NSLog("[NFCManager] Step 3: Connecting to RFIC driver...")
        let rficOk = RFICDriver.shared.connect()

        // Step 4: 尝试连接 nfcd
        NSLog("[NFCManager] Step 4: Connecting to nfcd daemon...")
        let nfcdOk = NFCDDaemon.shared.connect()

        // Step 5: 尝试绕过 CardSession
        NSLog("[NFCManager] Step 5: CardSession eligibility check + bypass...")
        let eligibility = CardSessionBypass.shared.checkEligibility()
        NSLog("[NFCManager] CardSession: supported=\(eligibility.supported), eligible=\(eligibility.eligible)")

        if !eligibility.eligible {
            _ = CardSessionBypass.shared.bypassIsEligible()
        }

        isInitialized = rficOk || nfcdOk || escaped
        NSLog("[NFCManager] === NFC Clone initialized: \(isInitialized) (RFIC=\(rficOk), nfcd=\(nfcdOk)) ===")

        return isInitialized
    }

    public func shutdown() {
        RFICDriver.shared.exitTargetMode()
        RFICDriver.shared.disconnect()
        NFCDDaemon.shared.disconnect()
        isInitialized = false
        NSLog("[NFCManager] Shutdown complete")
    }

    // MARK: - 探测卡片类型

    /// 探测当前贴近的卡片类型
    /// - Returns: (uid, atqa, sak, cardType)
    public func probeCard() -> (uid: [UInt8], atqa: [UInt8], sak: UInt8, type: NFCCardType)? {
        guard let fullResult = RFICDriver.shared.fullUID() else {
            NSLog("[NFCManager] No card detected")
            return nil
        }

        let (uid, atqa, sak) = fullResult

        // 根据 ATQA + SAK 推断卡类型
        let type = inferCardType(atqa: atqa, sak: sak)

        NSLog("[NFCManager] Card detected! UID: \(uid.hexString), ATQA: \(atqa.hexString), SAK: \(String(format: "0x%02X", sak)), Type: \(type.displayName)")

        return (uid, atqa, sak, type)
    }

    private func inferCardType(atqa: [UInt8], sak: UInt8) -> NFCCardType {
        // ATQA (2字节) + SAK 组合判断
        // 参考 ISO 14443-3 Type A 标准

        guard atqa.count >= 2 else { return .unknown }

        let atqa1 = atqa[0]
        let atqa2 = atqa[1]

        // MIFARE Classic
        if atqa1 == 0x04 && atqa2 == 0x00 {
            // SAK = 0x08 → MIFARE Classic 1K (S50)
            // SAK = 0x18 → MIFARE Classic 4K (S70)
            if sak == 0x08 { return .mifareClassic1K }
            if sak == 0x18 { return .mifareClassic4K }
            return .mifareClassic1K  // 默认
        }

        // MIFARE Ultralight
        if atqa1 == 0x44 && atqa2 == 0x00 {
            return .mifareUltralight
        }

        // NTAG 系列
        if atqa1 == 0x44 && atqa2 == 0x00 && sak == 0x00 {
            return .ntag213  // 无法精确区分 213/215/216，统一报 213
        }

        // DESFire
        if atqa1 == 0x03 {
            return .desfire
        }

        return .unknown
    }

    // MARK: - 读卡（完整快照）

    /// 完整读取一张卡的所有数据
    public func readFullCard() -> NFCCardSnapshot? {
        // 先探测
        guard let probe = probeCard() else { return nil }

        var snapshot = NFCCardSnapshot(
            uid: probe.uid,
            type: probe.type,
            atqa: probe.atqa,
            sak: probe.sak
        )

        // 根据类型读数据
        switch probe.type {
        case .mifareClassic1K, .mifareClassic4K:
            NSLog("[NFCManager] Reading MIFARE Classic blocks...")
            snapshot.blocks = RFICDriver.shared.dumpAll1K()

        case .mifareUltralight, .ntag213, .ntag215, .ntag216:
            NSLog("[NFCManager] Reading NDEF...")
            snapshot.ndefPayload = RFICDriver.shared.readNDEF()

        default:
            NSLog("[NFCManager] Card type \(probe.type.displayName) has limited read support")
        }

        NSLog("[NFCManager] ✅ Card read complete! Blocks: \(snapshot.blockCount)")
        return snapshot
    }

    // MARK: - 写卡（克隆到新卡）

    /// 把快照写入新卡（空白卡 / 可写卡）
    /// 注意：大多数卡的 UID 是一次性烧录的，无法写入
    ///       只有 gen1a/gen1b CUID 卡、NTAG 空白卡可以写
    public func cloneToBlankCard(_ snapshot: NFCCardSnapshot) -> Bool {
        NSLog("[NFCManager] Attempting to clone UID \(snapshot.uid.hexString) to blank card...")

        // 先让用户把空白卡贴上来
        guard let probe = probeCard() else {
            NSLog("[NFCManager] No blank card detected")
            return false
        }

        NSLog("[NFCManager] Blank card detected: \(probe.uid.hexString) (\(probe.type.displayName))")

        // 尝试写 UID（只有某些卡支持）
        if RFICDriver.shared.writeBlock(0, data: Array(snapshot.uid.prefix(16))) {
            NSLog("[NFCManager] ✅ UID write may have succeeded (check card type!)")
        } else {
            NSLog("[NFCManager] ❌ Cannot write UID on this card type (expected for most cards)")
            NSLog("[NFCManager] 💡 Use CUID card (gen1a/gen1b) or NTAG blank for full clone")
        }

        // 写数据块（MIFARE Classic）
        for (block, data) in snapshot.blocks {
            if block == 0 { continue }  // block 0 = UID，已处理
            if !RFICDriver.shared.writeBlock(block, data: data) {
                NSLog("[NFCManager] Failed to write block \(block)")
            }
        }

        return true
    }

    // MARK: - 卡模拟

    /// 进入卡模拟模式，让 iPhone 在读卡器面前伪装成一张卡
    ///
    /// 两条路径自动选择：
    /// 1. RFIC 直接操作 ioctl（需要漏洞链成功）
    /// 2. CardSession HCE（需要 entitlement + 绕过 isEligible）
    ///
    /// - Parameters:
    ///   - snapshot: 要模拟的卡片快照
    ///   - handler: 处理读卡器发来的 APDU 命令
    public func startEmulation(snapshot: NFCCardSnapshot,
                               handler: ((Data) -> Data?)? = nil) -> Bool {
        NSLog("[NFCManager] 🎯 Starting emulation mode for UID \(snapshot.uid.hexString)")
        NSLog("[NFCManager] Card type: \(snapshot.type.displayName)")

        // 方案 1: RFIC 驱动直接 Target Mode（最快、最像物理卡）
        if RFICDriver.shared.isConnected {
            if RFICDriver.shared.enterTargetMode(fakeUID: snapshot.uid,
                                                 ndefPayload: snapshot.ndefPayload) {
                // 启动命令处理循环
                RFICDriver.shared.processReaderCommands { cmd in
                    if let custom = handler {
                        return custom(Data(cmd))?.bytes
                    }
                    return self.defaultResponse(forCommand: cmd, snapshot: snapshot)
                }
                NSLog("[NFCManager] ✅ Emulation active via RFIC driver!")
                return true
            }
        }

        // 方案 2: nfcd Target Mode
        if NFCDDaemon.shared.connect() {
            if NFCDDaemon.shared.setTargetMode(true, fakeUID: Data(snapshot.uid)) {
                NSLog("[NFCManager] ✅ Emulation active via nfcd!")
                return true
            }
        }

        // 方案 3: CardSession HCE（需要 iOS 17.4+ + entitlement + 绕过）
        let eligibility = CardSessionBypass.shared.checkEligibility()
        if eligibility.supported {
            if !eligibility.eligible {
                _ = CardSessionBypass.shared.bypassIsEligible()
            }
            CardSessionBypass.shared.startEmulation { apdu in
                Data(self.defaultResponse(forCommand: apdu, snapshot: snapshot) ?? [])
            }
            NSLog("[NFCManager] ⚠️ Emulation starting via CardSession (may have latency)")
            return true
        }

        NSLog("[NFCManager] ❌ All emulation paths failed")
        return false
    }

    public func stopEmulation() {
        RFICDriver.shared.exitTargetMode()
        NFCDDaemon.shared.setTargetMode(false)
        NSLog("[NFCManager] Emulation stopped")
    }

    // MARK: - 默认 APDU 响应

    /// 给读卡器返回默认的 APDU 响应
    private func defaultResponse(forCommand cmd: [UInt8], snapshot: NFCCardSnapshot) -> [UInt8]? {
        // ISO 14443-4 / APDU 命令处理
        // 简化实现：对 SELECT 返回正常，对 READ DATA 返回快照中的数据

        switch cmd.first {
        case 0x94:  // SELECT (ISO 7816)
            return [0x90, 0x00]  // SW1=0x90, SW2=0x00 = success

        case 0x30:  // READ (MIFARE block)
            let block = cmd[safe: 1] ?? 0
            if let data = snapshot.blocks[block] {
                return data
            }
            return [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]

        case 0x60, 0x61:  // AUTH A / AUTH B
            return [0x00]  // ACK

        default:
            return [0x00]
        }
    }

    // MARK: - 持久化（卡片库）

    private var libraryPath: String {
        let paths = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)
        return (paths.first ?? "/tmp").appending("/card_library.json")
    }

    public func saveToLibrary(_ snapshot: NFCCardSnapshot, name: String) {
        var dict = loadLibrary()
        dict[name] = snapshot

        if let data = try? JSONEncoder().encode(dict) {
            try? data.write(to: URL(fileURLWithPath: libraryPath))
            NSLog("[NFCManager] Card '\(name)' saved to library")
        }
    }

    public func loadLibrary() -> [String: NFCCardSnapshot] {
        guard let data = try? Data(contentsOf: URL(fileURLWithPath: libraryPath)),
              let dict = try? JSONDecoder().decode([String: NFCCardSnapshot].self, from: data) else {
            return [:]
        }
        return dict
    }

    public func deleteFromLibrary(_ name: String) {
        var dict = loadLibrary()
        dict.removeValue(forKey: name)
        if let data = try? JSONEncoder().encode(dict) {
            try? data.write(to: URL(fileURLWithPath: libraryPath))
        }
    }
}

// MARK: - Array Safe Subscript

extension Array {
    subscript(safe index: Int) -> Element? {
        guard index >= 0 && index < count else { return nil }
        return self[index]
    }
}
