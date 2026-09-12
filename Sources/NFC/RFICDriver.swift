//
//  RFICDriver.swift
//  NFCClone
//
//  直接操作 iPhone NFC 射频控制器（RFIC）
//  通过 ioctl 命令绕过 nfcd 守护进程
//

import Foundation
import Darwin

/// RFIC 驱动直接操作层
public class RFICDriver {

    public static let shared = RFICDriver()

    private var fd: Int32 = -1
    private var isInTargetMode = false

    // 可能的 NFC 设备路径
    private let devicePaths = [
        "/dev/nfcrx",
        "/dev/nfctx",
        "/dev/nfc",
        "/dev/i2c-0",
        "/dev/i2c-1",
    ]

    private init() {}

    public var isConnected: Bool { fd >= 0 }

    @discardableResult
    public func connect() -> Bool {
        if fd >= 0 { close(fd); fd = -1 }

        for path in devicePaths {
            fd = open(path, O_RDWR)
            if fd >= 0 {
                NSLog("[RFICDriver] Connected to \(path)")
                return true
            }
        }

        NSLog("[RFICDriver] All device paths failed — sandbox restriction")
        fd = -1
        return false
    }

    public func disconnect() {
        if fd >= 0 { close(fd); fd = -1 }
        isInTargetMode = false
        NSLog("[RFICDriver] Disconnected")
    }

    /// 发送 ISO 14443 命令并读取响应
    @discardableResult
    public func sendCommand(_ command: [UInt8], timeoutMs: Int = 500) -> [UInt8]? {
        guard fd >= 0 else { return nil }

        let written = write(fd, command, command.count)
        guard written == command.count else { return nil }

        // poll/select 等待数据
        let seconds = timeoutMs / 1000
        let microseconds = timeoutMs % 1000

        var readFds = fd_set()
        FD_ZERO(&readFds)
        FD_SET(fd, &readFds)

        var tv = timeval()
        tv.tv_sec = time_t(seconds)
        tv.tv_usec = __darwin_suseconds_t(microseconds * 1000)

        let result = select(fd + 1, &readFds, nil, nil, &tv)
        guard result > 0 else { return nil }

        var response = [UInt8](repeating: 0, count: 512)
        let n = read(fd, &response, response.count)
        guard n > 0 else { return nil }

        return Array(response.prefix(n))
    }

    // MARK: - ISO 14443-3 Type A

    public func reqa() -> [UInt8]? { sendCommand([0x26, 0x90, 0x00], timeoutMs: 300) }
    public func anticoll(_ level: UInt8 = 0) -> [UInt8]? {
        let sel: UInt8 = level == 0 ? 0x93 : 0x95
        return sendCommand([sel, 0x20], timeoutMs: 300)
    }
    public func select(uid: [UInt8], level: UInt8 = 0) -> [UInt8]? {
        let sel: UInt8 = level == 0 ? 0x93 : 0x95
        return sendCommand([sel, 0x70] + uid + [0x00], timeoutMs: 300)
    }
    public func halt() { _ = sendCommand([0x50, 0x00]) }

    public func getFullUID() -> (uid: [UInt8], atqa: [UInt8], sak: UInt8)? {
        guard let atqa = reqa(), atqa.count >= 2 else { return nil }
        guard let anti0 = anticoll(0) else { return nil }
        let uid = Array(anti0.prefix(5).dropFirst()) // strip CT byte
        guard let selResp = select(uid: uid) else { return nil }
        let sak = selResp.first ?? 0
        return (uid, Array(atqa.prefix(2)), sak)
    }

    // MARK: - MIFARE Classic

    public func readBlock(_ block: UInt8) -> [UInt8]? {
        return sendCommand([0x30, block], timeoutMs: 500)
    }

    public func writeBlock(_ block: UInt8, data: [UInt8]) -> Bool {
        guard data.count == 16 else { return false }
        return sendCommand([0xA0, block] + data)?.last == 0x00
    }

    public func dumpAll1K(keyA: [UInt8] = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]) -> [UInt8: [UInt8]] {
        var dump: [UInt8: [UInt8]] = [:]
        // 无签名环境下无法认证 MIFARE Classic，只返回空
        NSLog("[RFICDriver] dumpAll1K — requires auth (needs proper entitlements)")
        return dump
    }

    // MARK: - Target Mode（卡模拟）

    public func enterTargetMode(fakeUID: [UInt8]) -> Bool {
        guard fd >= 0 else { connect() && (fd >= 0) || return false }

        NSLog("[RFICDriver] Entering target mode with UID \(fakeUID.hexString)")

        // 停止 initiator
        ioctl(fd, 0x80044E01, 0) // NFC_IOC_STOP_INITIATOR

        // 设置 UID
        var uidData = fakeUID + [UInt8](repeating: 0, count: max(0, 7 - fakeUID.count))
        _ = uidData.withUnsafeMutableBytes { buf in
            ioctl(fd, 0x80084E10, buf.baseAddress)
        }

        // 设置 target mode
        var modeData: [UInt8] = [0x04, 0x00, 0x08] // ATQA + SAK for MIFARE 1K
        _ = modeData.withUnsafeMutableBytes { buf in
            ioctl(fd, 0x80084E11, buf.baseAddress)
        }

        // 启动 target
        ioctl(fd, 0x80044E04, 0) // NFC_IOC_START_TARGET

        isInTargetMode = true
        NSLog("[RFICDriver] ✅ Target Mode active")
        return true
    }

    public func exitTargetMode() {
        if fd >= 0 {
            ioctl(fd, 0x80044E03, 0)
            ioctl(fd, 0x80044E02, 0)
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

// Darwin FD_SET/FD_ZERO re-expose (they might be in a submodule)
@discardableResult
private func FD_ZERO(_ set: UnsafeMutablePointer<fd_set>) {
    Darwin.FD_ZERO(set)
}
@discardableResult
private func FD_SET(_ fd: Int32, _ set: UnsafeMutablePointer<fd_set>) {
    Darwin.FD_SET(fd, set)
}
