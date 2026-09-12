//
//  NFCCloneApp.swift
//  NFCClone
//

import SwiftUI

@main
struct NFCCloneApp: App {
    @StateObject private var appState = AppState.shared

    init() {
        appState.startInitialization()
    }

    var body: some Scene {
        WindowGroup {
            RootView().environmentObject(appState)
        }
    }
}

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
            self.appendLog("🚀 NFCClone v1.0 launching...")
            self.appendLog("📱 iOS \(UIDevice.current.systemVersion)")

            let ok = NFCManager.shared.initialize()
            self.isInitialized = ok

            if ok {
                self.appendLog("✅ NFC subsystem ready")
            } else {
                self.appendLog("⚠️ 沙箱限制 — 需要企业证书 + no-sandbox entitlements")
            }
        }
    }

    func appendLog(_ msg: String) {
        let ts = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
        logs.insert("[\(ts)] \(msg)", at: 0)
        if logs.count > 200 { logs.removeLast(logs.count - 200) }
        NSLog("[NFCClone] \(msg)")
    }

    // MARK: - UI Actions

    func readCard() {
        Task.detached { @MainActor in
            self.appendLog("📖 Scanning...")
            try? await Task.sleep(nanoseconds: 500_000_000)
            if let snap = NFCManager.shared.readFullCard() {
                self.currentCard = snap
                self.appendLog("✅ UID: \(snap.uidHex)")
            } else {
                self.appendLog("❌ No card detected")
            }
        }
    }

    func startEmulation() {
        guard let snap = currentCard else {
            appendLog("⚠️ 先读一张卡")
            return
        }

        if emulationActive {
            NFCManager.shared.stopEmulation()
            emulationActive = false
            appendLog("⏹️ Emulation stopped")
            return
        }

        emulationActive = NFCManager.shared.startEmulation(snapshot: snap)
        appendLog(emulationActive ? "🎯 Emulation active!" : "❌ Failed")
    }

    func saveCard(_ name: String) {
        guard let snap = currentCard else { return }
        NFCManager.shared.saveToLibrary(snap, name: name)
        appendLog("💾 Saved: \(name)")
    }

    func runExploit() {
        appendLog("🔁 Re-running FilzaSlop...")
        let ok = FilzaSlopExploit.shared.runFullExploit()
        appendLog(ok ? "✅ OK" : "⚠️ Issues")
    }
}
