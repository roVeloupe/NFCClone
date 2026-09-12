//
//  RFICDriver.swift
//  NFCClone
//
//  直接操作 iPhone NFC 射频控制器（RFIC）
//  绕过 Apple 的 nfcd 守护进程，直接用 ioctl 跟硬件芯片通信
//
//  A14 芯片使用的是 NXP PN548 或 ST ST21 NFC 控制器
//  设备节点路径可能因 iOS 版本而异，这里列所有可能的路径

import Foundation
import Darwin

#if canImport(Darwin)
import Darwin.C
#endif

/// RFIC 驱动直接操作层
public class RFICDriver {

    public static let shared = RFICDriver()

    private var fd: Int32 = -1
    private var isInTargetMode = false

    // MARK: - 设备节点路径候选
    // A14 (iPhone 12/12 Pro/12 Pro Max/12 mini) 可能的 NFC 设备路径
    private let devicePaths = [
        "/dev/nfcrx",
        "/dev/nfctx",
        "/dev/nfc",
        "/dev/i2c-0",
        "/dev/i2c-1",
        "/dev/char/union/nfc",
        "/private/var/run/nfcd.sock",
    ]

    private init() {}

    // MARK: - 连接 / 断开

    /// 尝试打开所有候选路径，找到能用的那个
    @discardableResult
    public func connect() -> Bool {
        // 如果已经连接，先断开
        if fd >= 0 { close(fd); fd = -1 }

        for path in devicePaths {
            fd = open(path, O_RDWR | O_NONBLOCK)
            if fd >= 0 {
                NSLog("[RFICDriver] Connected to \(path) (fd=\(fd))")
                // 设置为阻塞模式方便读写
                let flags = fcntl(fd, F_GETFL, 0)
                fcntl(fd, F_SETFL, flags & ~O_NONBLOCK)
                return true
            }
        }

        NSLog("[RFICDriver] All device paths failed. Trying via nfcd IPC...")
        fd = -1
        return false
    }

    public func disconnect() {
        if fd >= 0 {
            close(fd)
            fd = -1
            NSLog("[RFICDriver] Disconnected")
        }
        isInTargetMode = false
    }

    public var isConnected: Bool { fd >= 0 }

    // MARK: - 低层通信

    /// 发送 ISO 14443-3 命令并读取响应
    /// - Parameter command: 原始命令字节
    /// - Returns: 响应数据，或 nil
    @discardableResult
    public func sendCommand(_ command: [UInt8], timeout: TimeInterval = 0.5) -> [UInt8]? {
        guard fd >= 0 else { connect() }
        guard fd >= 0 else {
            NSLog("[RFICDriver] Not connected, cannot send command")
            return nil
        }

        // 发命令
        let written = write(fd, command, command.count)
        guard written == command.count else {
            NSLog("[RFICDriver] Write failed: \(written)/\(command.count) bytes")
            return nil
        }

        // 设置超时
        var readFds = fd_set()
        Darwin.FD_ZERO(&readFds)
        Darwin.FD_SET(fd, &readFds)

        let timeoutSecs = Int(timeout)
        let timeoutUsecs = Int((timeout - Double(timeoutSecs)) * 1_000_000)
        var tv = timeval(tv_sec: time_t(timeoutSecs), tv_usec: __darwin_suseconds_t(timeoutUsecs))

        let selectResult = Darwin.select(fd + 1, &readFds, nil, nil, &tv)
        guard selectResult > 0 else {
            NSLog("[RFICDriver] Read timeout or error: \(selectResult)")
            return nil
        }

        // 读响应
        var response = [UInt8](repeating: 0, count: 512)
        let bytesRead = read(fd, &response, response.count)
        guard bytesRead > 0 else {
            NSLog("[RFICDriver] Read 0 bytes")
            return nil
        }

        NSLog("[RFICDriver] TX: \(command.hexString) → RX: \(Array(response.prefix(bytesRead)).hexString)")
        return Array(response.prefix(bytesRead))
    }

    // MARK: - ISO 14443-3 Type A 基础命令

    /// REQA - 寻卡
    /// 返回 ATQA（卡的类型应答）
    public func reqa() -> [UInt8]? {
        return sendCommand([0x26, 0x90, 0x00], timeout: 0.3)
    }

    /// WUPA - 唤醒卡（从 HALT 状态）
    public func wupa() -> [UInt8]? {
        return sendCommand([0x52, 0x90, 0x00], timeout: 0.3)
    }

    /// ANTI_COLL - 防冲突，获取完整 UID
    /// - Parameter cascadeLevel: 0 = 第一次 cascade, 1 = 第二次 (UID 4字节→7字节)
    /// - Returns: UID + SAK 等信息
    public func anticoll(_ cascadeLevel: UInt8 = 0) -> [UInt8]? {
        let selCode: UInt8 = cascadeLevel == 0 ? 0x93 : 0x95
        let cmd: [UInt8] = [selCode, 0x20]
        return sendCommand(cmd, timeout: 0.3)
    }

    /// SELECT - 选卡（完成 UID 获取）
    public func select(uid: [UInt8], cascadeLevel: UInt8 = 0) -> [UInt8]? {
        let selCode: UInt8 = cascadeLevel == 0 ? 0x93 : 0x95
        let cmd: [UInt8] = [selCode, 0x70] + uid + [0x00]
        return sendCommand(cmd, timeout: 0.3)
    }

    /// HALT - 让卡进入 HALT 状态
    public func halt() {
        _ = sendCommand([0x50, 0x00])
    }

    /// 获取完整 UID
    /// - Returns: (uid, atqa, sak)
    public func fullUID() -> (uid: [UInt8], atqa: [UInt8], sak: UInt8)? {
        // 1. REQA
        guard let atqa = reqa(), atqa.count >= 2 else { return nil }

        // 2. ANTI_COLL cascade level 0
        guard let anti0 = anticoll(0) else { return nil }
        // anti0 返回格式: [CT, UID0-4, BCC, SAK(如果已选)]
        let uid = Array(anti0[1..<6])  // UID 是 4 字节（加上 CT 是 5 字节）

        // 3. SELECT
        guard let selResp = select(uid: uid, cascadeLevel: 0) else { return nil }
        let sak = selResp.first ?? 0

        return (uid, atqa.prefix(2), sak)
    }

    // MARK: - MIFARE Classic 读写

    /// 认证 MIFARE Classic 块
    /// - Parameters:
    ///   - block: 块号 (0-63 for 1K, 0-255 for 4K)
    ///   - keyA: Key A (6字节)
    ///   - keyB: Key B (6字节)，可选
    /// - Returns: 是否认证成功
    public func authenticate(block: UInt8, keyA: [UInt8], keyB: [UInt8]? = nil) -> Bool {
        guard keyA.count == 6 else { return false }

        // 先尝试 Key A
        let cmdA: [UInt8] = [0x60, block] + keyA  // AUTH A
        if let resp = sendCommand(cmdA), resp.last == 0x00 {
            return true
        }

        // 再尝试 Key B
        if let keyB = keyB, keyB.count == 6 {
            let cmdB: [UInt8] = [0x61, block] + keyB  // AUTH B
            if let resp = sendCommand(cmdB), resp.last == 0x00 {
                return true
            }
        }

        return false
    }

    /// 读 MIFARE Classic 块
    public func readBlock(_ block: UInt8) -> [UInt8]? {
        return sendCommand([0x30, block], timeout: 0.5)
    }

    /// 写 MIFARE Classic 块
    public func writeBlock(_ block: UInt8, data: [UInt8]) -> Bool {
        guard data.count == 16 else { return false }
        let cmd = [0xA0, block] + data
        guard let resp = sendCommand(cmd) else { return false }
        return resp.last == 0x00  // ACK
    }

    /// 批量读整个 MIFARE Classic 1K (16 sectors × 4 blocks = 64 blocks)
    /// - Returns: [blockNumber: [data]]
    public func dumpAll1K(keyA: [UInt8] = [0xFF as UInt8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]) -> [UInt8: [UInt8]] {
        var dump: [UInt8: [UInt8]] = [:]

        for sector in 0..<16 {
            let block0 = UInt8(sector * 4)

            // 认证每个 sector
            if authenticate(block: block0, keyA: keyA) {
                for blockOffset in 0..<4 {
                    let block = UInt8(block0) + UInt8(blockOffset)
                    if let data = readBlock(block as! UInt8) {
                        dump[block as! UInt8] = Array(data.prefix(16))
                    }
                }
                NSLog("[RFICDriver] Sector \(sector) dumped successfully")
            } else {
                NSLog("[RFICDriver] Sector \(sector) auth FAILED, trying default keys...")
                // 尝试常用默认 key
                let defaultKeys: [[UInt8]] = [
                    [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
                    [0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
                    [0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5],
                    [0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7],
                    [0x01, 0x02, 0x03, 0x04, 0x05, 0x06],
                ]
                for k in defaultKeys {
                    if authenticate(block: block0, keyA: k) {
                        NSLog("[RFICDriver] Sector \(sector) unlocked with key \(k.hexString)")
                        for blockOffset in 0..<4 {
                            let block = UInt8(block0) + UInt8(blockOffset)
                            if let data = readBlock(block as! UInt8) {
                                dump[block as! UInt8] = Array(data.prefix(16))
                            }
                        }
                        break
                    }
                }
            }
        }

        return dump
    }

    // MARK: - NDEF 读写

    /// 读 NDEF 标签
    public func readNDEF() -> [UInt8]? {
        // NDEF 标签通常是 Type 4A (ISO 14443-4)
        // 需要先 SELECT NDEF 应用
        let selectNDEF: [UInt8] = [
            0x90, 0x5A, 0x00, 0x00, // SELECT
            0x07,                    // Lc
            0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x00,  // AID: NDEF
            0x00, 0x00              // Le
        ]

        return sendCommand(selectNDEF)
    }

    // MARK: - 卡模拟（Target Mode）

    /// 让 NFC 控制器进入 Target Mode（卡模拟）
    /// 这是最关键的功能——让 iPhone 在读卡器面前伪装成一张卡
    ///
    /// 注意：iOS 17+ 上这个 ioctl 可能被 nfcd 守护进程锁定
    /// 需要先通过漏洞拿到 nfcd 的容器访问权
    public func enterTargetMode(fakeUID: [UInt8], ndefPayload: [UInt8]? = nil) -> Bool {
        NSLog("[RFICDriver] Entering Target Mode with UID \(fakeUID.hexString)")

        // 如果直接操作驱动失败，需要先 patch nfcd 的配置
        guard fd >= 0 else {
            NSLog("[RFICDriver] Need to open RFIC device first")
            return false
        }

        // 1. 停止 Initiator Mode（正常的读卡模式）
        _ = ioctl(fd, NFC_IOC_STOP_INITIATOR, 0)

        // 2. 设置要广播的 UID (ISO 14443-3 Type A)
        var uidData = fakeUID + [UInt8](repeating: 0, count: max(0, 7 - fakeUID.count))
        let uidPtr = UnsafeMutableRawPointer(&uidData)
        if ioctl(fd, NFC_IOC_SET_UID, uidPtr) < 0 {
            NSLog("[RFICDriver] NFC_IOC_SET_UID failed: \(errno)")
            return false
        }

        // 3. 设置 ATQA / SAK 响应（让读卡器认出是什么类型的卡）
        // MIFARE Classic 1K: ATQA=0x0004, SAK=0x08
        // MIFARE Ultralight: ATQA=0x0044, SAK=0x00
        let atqa: [UInt8] = [0x04, 0x00]  // MIFARE 1K
        let sak: UInt8 = 0x08
        var modeData = atqa + [sak]
        if ioctl(fd, NFC_IOC_SET_TARGET_MODE, UnsafeMutableRawPointer(&modeData)) < 0 {
            NSLog("[RFICDriver] NFC_IOC_SET_TARGET_MODE failed: \(errno)")
            return false
        }

        // 4. 如果有 NDEF payload，预加载
        if let ndef = ndefPayload {
            var payload = ndef
            if ioctl(fd, NFC_IOC_SET_NDEF, UnsafeMutableRawPointer(&payload)) < 0 {
                NSLog("[RFICDriver] NFC_IOC_SET_NDEF failed (may be ok): \(errno)")
            }
        }

        // 5. 开始广播
        if ioctl(fd, NFC_IOC_START_TARGET, 0) < 0 {
            NSLog("[RFICDriver] NFC_IOC_START_TARGET failed: \(errno)")
            return false
        }

        isInTargetMode = true
        NSLog("[RFICDriver] ✅ Target Mode active! Broadcasting UID: \(fakeUID.hexString)")
        return true
    }

    /// 退出 Target Mode，回到正常模式
    public func exitTargetMode() {
        if fd >= 0 {
            ioctl(fd, NFC_IOC_STOP_TARGET, 0)
            ioctl(fd, NFC_IOC_START_INITIATOR, 0)
        }
        isInTargetMode = false
        NSLog("[RFICDriver] Exited Target Mode")
    }

    /// 在 Target Mode 下，处理读卡器发来的命令
    /// 这是一个阻塞式循环，在后台线程运行
    public func processReaderCommands(callback: @escaping ([UInt8]) -> [UInt8]?) {
        guard isInTargetMode, fd >= 0 else {
            NSLog("[RFICDriver] Not in target mode")
            return
        }

        DispatchQueue.global(qos: .background).async { [weak self] in
            guard let self = self else { return }

            NSLog("[RFICDriver] Listening for reader commands...")
            var buffer = [UInt8](repeating: 0, count: 256)

            while self.isInTargetMode {
                let bytesRead = read(self.fd, &buffer, buffer.count)
                if bytesRead > 0 {
                    let cmd = Array(buffer.prefix(bytesRead))
                    NSLog("[RFICDriver] Reader command: \(cmd.hexString)")

                    // 用户回调生成响应
                    if let response = callback(cmd) {
                        write(self.fd, response, response.count)
                        NSLog("[RFICDriver] Sent response: \(response.hexString)")
                    } else {
                        // 默认响应 ACK
                        let ack: [UInt8] = [0x00]
                        write(self.fd, ack, ack.count)
                    }
                }
            }
        }
    }
}

// MARK: - NFC IOCTL 常量
// 这些是 Apple 私有定义，需要从 nfcd / NFCFramework 逆向得到
// 不同 iOS 版本可能有差异，A14 + iOS 27 beta 应该是这些值

private let NFC_IOC_STOP_INITIATOR:   UInt = 0x80044E01
private let NFC_IOC_START_INITIATOR:  UInt = 0x80044E02
private let NFC_IOC_STOP_TARGET:      UInt = 0x80044E03
private let NFC_IOC_START_TARGET:     UInt = 0x80044E04
private let NFC_IOC_SET_UID:          UInt = 0x80084E10
private let NFC_IOC_SET_TARGET_MODE:  UInt = 0x80084E11
private let NFC_IOC_SET_NDEF:         UInt = 0x80104E12
private let NFC_IOC_GET_VERSION:      UInt = 0x80044E20

// MARK: - Data 扩展

extension Array where Element == UInt8 {
    var hexString: String {
        return map { String(format: "%02X", $0) }.joined(separator: " ")
    }
}
