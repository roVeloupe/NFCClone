//
//  NFCManager.swift
//  NFCClone
//

import Foundation
import Darwin

// MARK: - 类型

public enum NFCCardType: String, Codable {
    case mifareClassic1K, mifareClassic4K, mifareUltralight
    case ntag213, ntag215, ntag216, desfire, felica, unknown

    public var displayName: String {
        switch self {
        case .mifareClassic1K: return "MIFARE Classic 1K"
        case .mifareClassic4K: return "MIFARE Classic 4K"
        case .mifareUltralight: return "MIFARE Ultralight"
        case .ntag213: return "NTAG 213"
        case .ntag215: return "NTAG 215"
        case .ntag216: return "NTAG 216"
        case .desfire: return "MIFARE DESFire"
        case .felica: return "FeliCa"
        case .unknown: return "未知类型"
        }
    }
}

public struct NFCCardSnapshot: Codable, Identifiable {
    public let id = UUID()
    public var uid: [UInt8]
    public var type: NFCCardType
    public var atqa: [UInt8]
    public var sak: UInt8
    public var blocks: [UInt8: [UInt8]]
    public var timestamp: Date

    public init(uid: [UInt8], type: NFCCardType, atqa: [UInt8], sak: UInt8, blocks: [UInt8: [UInt8]] = [:]) {
        self.uid = uid
        self.type = type
        self.atqa = atqa
        self.sak = sak
        self.blocks = blocks
        self.timestamp = Date()
    }

    public var uidHex: String { uid.map { String(format: "%02X", $0) }.joined(separator: " ") }
    public var blockCount: Int { blocks.count }
}

// MARK: - 管理器

public class NFCManager {

    public static let shared = NFCManager()

    public private(set) var isInitialized = false

    private init() {}

    public func initialize() -> Bool {
        NSLog("[NFCManager] Initializing...")

        // 设备信息
        var u = utsname()
        _ = Darwin.uname(&u)
        let machine = String(cString: &u.machine)
        NSLog("[NFCManager] Machine: \(machine)")

        let escaped = FilzaSlopExploit.shared.isSandboxEscaped()
        NSLog("[NFCManager] Sandbox escaped: \(escaped)")

        FilzaSlopExploit.shared.runFullExploit()
        FilzaSlopExploit.shared.patchNFCGestalts()

        let rficOk = RFICDriver.shared.connect()
        let nfcdOk = NFCDDaemon.shared.connect()

        isInitialized = rficOk || nfcdOk || escaped
        NSLog("[NFCManager] Init done: RFIC=\(rficOk), nfcd=\(nfcdOk)")
        return isInitialized
    }

    public func shutdown() {
        RFICDriver.shared.exitTargetMode()
        RFICDriver.shared.disconnect()
        NFCDDaemon.shared.disconnect()
        isInitialized = false
    }

    // MARK: - 操作

    public func probeCard() -> (uid: [UInt8], atqa: [UInt8], sak: UInt8, type: NFCCardType)? {
        guard let full = RFICDriver.shared.getFullUID() else { return nil }

        let type: NFCCardType = {
            guard full.atqa.count >= 2 else { return .unknown }
            switch (full.atqa[0], full.atqa[1], full.sak) {
            case (0x04, 0x00, 0x08): return .mifareClassic1K
            case (0x04, 0x00, 0x18): return .mifareClassic4K
            case (0x44, 0x00, _): return .ntag213
            case (0x03, _, _): return .desfire
            default: return .unknown
            }
        }()

        return (full.uid, full.atqa, full.sak, type)
    }

    public func readFullCard() -> NFCCardSnapshot? {
        guard let p = probeCard() else { return nil }
        let snapshot = NFCCardSnapshot(uid: p.uid, type: p.type, atqa: p.atqa, sak: p.sak)
        NSLog("[NFCManager] Read card: \(p.type.displayName), UID: \(p.uid.map { String(format: "%02X", $0) }.joined())")
        return snapshot
    }

    public func cloneToBlankCard(_ snapshot: NFCCardSnapshot) -> Bool {
        NSLog("[NFCManager] Clone requested — needs CUID/blank card hardware support")
        return false
    }

    public func startEmulation(snapshot: NFCCardSnapshot, handler: (([UInt8]) -> [UInt8]?)? = nil) -> Bool {
        NSLog("[NFCManager] Start emulation, UID: \(snapshot.uid.map { String(format: "%02X", $0) }.joined())")

        if RFICDriver.shared.isConnected {
            if RFICDriver.shared.enterTargetMode(fakeUID: snapshot.uid) {
                return true
            }
        }

        if NFCDDaemon.shared.setTargetMode(true, fakeUID: Data(snapshot.uid)) {
            return true
        }

        NSLog("[NFCManager] All emulation paths failed — requires no-sandbox entitlements")
        return false
    }

    public func stopEmulation() {
        RFICDriver.shared.exitTargetMode()
        NFCDDaemon.shared.setTargetMode(false)
    }

    // MARK: - 持久化

    private var libraryPath: String {
        let paths = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)
        return (paths.first ?? "/tmp").appending("/card_library.json")
    }

    public func saveToLibrary(_ snapshot: NFCCardSnapshot, name: String) {
        var dict = loadLibrary()
        dict[name] = snapshot
        if let data = try? JSONEncoder().encode(dict) {
            try? data.write(to: URL(fileURLWithPath: libraryPath))
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
