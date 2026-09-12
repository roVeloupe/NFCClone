//
//  NFCCloneApp.swift
//  NFCClone
//
//  App 入口 — 启动时初始化 NFC 子系统
//

import SwiftUI

@main
struct NFCCloneApp: App {

    @StateObject private var appState = AppState.shared

    init() {
        // App 启动时立即初始化 NFC
        appState.startInitialization()
    }

    var body: some Scene {
        WindowGroup {
            RootView()
                .environmentObject(appState)
        }
    }
}

/// 全局 App 状态
@MainActor
final class AppState: ObservableObject {

    static let shared = AppState()

    @Published var isInitialized: Bool = false
    @Published var logs: [String] = []
    @Published var currentCard: NFCCardSnapshot?
    @Published var emulationActive: Bool = false

    private init() {}

    func startInitialization() {
        Task.detached { @MainActor in
            self.appendLog("🚀 NFC Clone v1.0 launching...")
            self.appendLog("📱 Device: \(UIDevice.current.model), iOS \(UIDevice.current.systemVersion)")
            self.appendLog("🎯 Target: A14 + iOS 27 beta")

            // 初始化 NFC
            let ok = NFCManager.shared.initialize()
            self.isInitialized = ok

            if ok {
                self.appendLog("✅ NFC subsystem initialized successfully")
            } else {
                self.appendLog("⚠️ NFC init returned false (may still work on some paths)")
            }
        }
    }

    func appendLog(_ msg: String) {
        let timestamp = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        logs.insert("[\(timestamp)] \(msg)", at: 0)
        // 只保留最近 200 条
        if logs.count > 200 { logs.removeLast(logs.count - 200) }
        NSLog("[NFCClone] \(msg)")
    }

    // MARK: - UI 操作

    func readCard() {
        Task.detached { @MainActor in
            self.appendLog("📖 Scanning for card...")
            // 给用户一些时间把卡贴上来
            try? await Task.sleep(nanoseconds: 500_000_000)

            if let snapshot = NFCManager.shared.readFullCard() {
                self.currentCard = snapshot
                self.appendLog("✅ Card read! UID: \(snapshot.uidHex), Blocks: \(snapshot.blockCount)")
            } else {
                self.appendLog("❌ No card detected or read failed")
            }
        }
    }

    func cloneToNew() {
        guard let snapshot = currentCard else {
            appendLog("⚠️ No card loaded, read a card first")
            return
        }

        Task.detached { @MainActor in
            self.appendLog("📡 Place blank card on reader...")
            try? await Task.sleep(nanoseconds: 1_500_000_000)

            if NFCManager.shared.cloneToBlankCard(snapshot) {
                self.appendLog("✅ Clone attempt complete")
            } else {
                self.appendLog("❌ Clone failed")
            }
        }
    }

    func startEmulation() {
        guard let snapshot = currentCard else {
            appendLog("⚠️ No card loaded")
            return
        }

        if emulationActive {
            NFCManager.shared.stopEmulation()
            emulationActive = false
            appendLog("⏹️ Emulation stopped")
            return
        }

        emulationActive = NFCManager.shared.startEmulation(snapshot: snapshot)
        appendLog(emulationActive ? "🎯 Emulation active! Hold iPhone near reader." : "❌ Emulation failed")
    }

    func saveCard(_ name: String) {
        guard let snapshot = currentCard else { return }
        NFCManager.shared.saveToLibrary(snapshot, name: name)
        appendLog("💾 Card saved: \(name)")
    }

    func killNFCD() {
        appendLog("🔄 Requesting nfcd restart...")
        // iOS sandbox 不允许 fork/exec，killall 在 no-sandbox 环境下需要用 sysctl 信号
        // 企业证书 + no-sandbox 可以用 Darwin.kill()
        let pid = Darwin.getpid()
        // 这里只做日志记录，真实杀进程需要找 nfcd 的 pid
        appendLog("ℹ️ Process pid=\(pid) — nfcd restart requires no-sandbox entitlements")
    }

    func runFullExploit() {
        appendLog("🔁 Re-running FilzaSlop exploit chain...")
        let ok = FilzaSlopExploit.shared.runFullExploit()
        appendLog(ok ? "✅ Exploit chain OK" : "⚠️ Exploit chain had issues")
        FilzaSlopExploit.shared.patchNFCGestalts()
    }

    func resetMobileGestalt() {
        let backupPath = "/private/var/containers/Data/System/com.apple.MobileGestalt/Library/Caches/com.apple.MobileGestalt.plist.bak"
        let mainPath = "/private/var/containers/Data/System/com.apple.MobileGestalt/Library/Caches/com.apple.MobileGestalt.plist"

        if FileManager.default.fileExists(atPath: backupPath) {
            try? FileManager.default.removeItem(atPath: mainPath)
            try? FileManager.default.copyItem(atPath: backupPath, toPath: mainPath)
            appendLog("✅ MobileGestalt restored from backup")
        } else {
            appendLog("⚠️ No backup found, cannot restore")
        }
    }
}
