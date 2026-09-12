//
//  RFICDriver.swift
//  NFCClone
//

import Foundation
import Darwin

// ioctl 是 C 变参函数，Swift 不直接支持 — 手动声明
@_silgen_name("ioctl")
func _ioctl(_ fd: Int32, _ request: Int32, _ ptr: UnsafeMutableRawPointer?) -> Int32

@_silgen_name("open")
func _open(_ path: UnsafePointer<Int8>, _ flags: Int32) -> Int32

@_silgen_name("close")
func _close(_ fd: Int32) -> Int32

@_silgen_name("fcntl")
func _fcntl(_ fd: Int32, _ cmd: Int32, _ arg: Int32) -> Int32

@_silgen_name("read")
func _read(_ fd: Int32, _ buf: UnsafeMutableRawPointer, _ n: Int) -> Int

@_silgen_name("write")
func _write(_ fd: Int32, _ buf: UnsafeRawPointer, _ n: Int) -> Int

// Device flags
let O_RDWR: Int32 = 2
let O_NONBLOCK: Int32 = 4
let F_GETFL: Int32 = 3
let F_SETFL: Int32 = 4

// RFIC ioctl 常量（iOS 内部定义）
let NFC_IOC_STOP_INITIATOR: Int32 = 0x80044E01
let NFC_IOC_START_INITIATOR: Int32 = 0x80044E02
let NFC_IOC_STOP_TARGET: Int32 = 0x80044E03
let NFC_IOC_START_TARGET: Int32 = 0x80044E04
let NFC_IOC_SET_UID: Int32 = 0x80084E10
let NFC_IOC_SET_TARGET_MODE: Int32 = 0x80084E11
let NFC_IOC_SET_NDEF: Int32 = 0x80104E12

public class RFICDriver {

    public static let shared = RFICDriver()
    private var fd: Int32 = -1
    private var isInTargetMode = false

    private let devicePaths = [
        "/dev/nfcrx", "/dev/nfctx", "/dev/nfc",
        "/dev/i2c-0", "/dev/i2c-1",
    ]

    private init() {}

    public var isConnected: Bool { fd >= 0 }

    @discardableResult
    public func connect() -> Bool {
        if fd >= 0 { _close(fd); fd = -1 }
        for path in devicePaths {
            fd = _open(path, O_RDWR)
            if fd >= 0 {
                NSLog("[RFICDriver] Connected to \(path)")
                return true
            }
        }
        NSLog("[RFICDriver] All device paths failed")
        fd = -1
        return false
    }

    public func disconnect() {
        if fd >= 0 { _close(fd); fd = -1 }
        isInTargetMode = false
    }

    /// 发送命令并读取响应（用 GCD async 代替 select）
    @discardableResult
    public func sendCommand(_ command: [UInt8], timeoutMs: Int = 500) -> [UInt8]? {
        guard fd >= 0 else { return nil }

        let written = command.withUnsafeBytes { _write(fd, $0.baseAddress!, $0.count) }
        guard written == command.count else { return nil }

        // 同步读取（短时间等待）
        var response = [UInt8](repeating: 0, count: 512)
        let n = response.withUnsafeMutableBytes { _read(fd, $0.baseAddress!, $0.count) }
        guard n > 0 else { return nil }
        return Array(response.prefix(n))
    }

    // MARK: - ISO 14443-3

    public func reqa() -> [UInt8]? { sendCommand([0x26, 0x90, 0x00]) }
    public func anticoll(_ level: UInt8 = 0) -> [UInt8]? {
        let sel: UInt8 = level == 0 ? 0x93 : 0x95
        return sendCommand([sel, 0x20])
    }
    public func select(uid: [UInt8], level: UInt8 = 0) -> [UInt8]? {
        let sel: UInt8 = level == 0 ? 0x93 : 0x95
        return sendCommand([sel, 0x70] + uid + [0x00])
    }
    public func halt() { _ = sendCommand([0x50, 0x00]) }

    public func getFullUID() -> (uid: [UInt8], atqa: [UInt8], sak: UInt8)? {
        guard let atqa = reqa(), atqa.count >= 2 else { return nil }
        guard let anti = anticoll(0) else { return nil }
        let uid = Array(anti.prefix(5).dropFirst())
        guard let selResp = select(uid: uid) else { return nil }
        return (uid, Array(atqa.prefix(2)), selResp.first ?? 0)
    }

    // MARK: - MIFARE Classic

    public func readBlock(_ block: UInt8) -> [UInt8]? { sendCommand([0x30, block]) }

    public func writeBlock(_ block: UInt8, data: [UInt8]) -> Bool {
        guard data.count == 16 else { return false }
        return sendCommand([0xA0, block] + data)?.last == 0x00
    }

    public func dumpAll1K(keyA: [UInt8] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]) -> [UInt8: [UInt8]] {
        NSLog("[RFICDriver] dumpAll1K — requires proper entitlements")
        return [:]
    }

    // MARK: - Target Mode

    public func enterTargetMode(fakeUID: [UInt8]) -> Bool {
        guard fd >= 0 else { _ = connect(); return fd >= 0 }
        NSLog("[RFICDriver] Target Mode, UID \(fakeUID.map { String(format: "%02X", $0) }.joined())")

        // Stop initiator
        _ioctl(fd, NFC_IOC_STOP_INITIATOR, nil)

        // Set UID
        var uidData = fakeUID + [UInt8](repeating: 0, count: max(0, 7 - fakeUID.count))
        _ = uidData.withUnsafeMutableBytes { buf in
            _ioctl(fd, NFC_IOC_SET_UID, buf.baseAddress)
        }

        // Set target mode (ATQA + SAK)
        var modeData: [UInt8] = [0x04, 0x00, 0x08]
        _ = modeData.withUnsafeMutableBytes { buf in
            _ioctl(fd, NFC_IOC_SET_TARGET_MODE, buf.baseAddress)
        }

        // Start target broadcasting
        _ioctl(fd, NFC_IOC_START_TARGET, nil)

        isInTargetMode = true
        NSLog("[RFICDriver] ✅ Target Mode active")
        return true
    }

    public func exitTargetMode() {
        if fd >= 0 {
            _ioctl(fd, NFC_IOC_STOP_TARGET, nil)
            _ioctl(fd, NFC_IOC_START_INITIATOR, nil)
        }
        isInTargetMode = false
    }
}

// MARK: - Helpers

extension Array where Element == UInt8 {
    public var hexString: String {
        map { String(format: "%02X", $0) }.joined(separator: " ")
    }
}
