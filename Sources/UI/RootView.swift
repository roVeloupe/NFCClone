//
//  RootView.swift
//  NFCClone
//
//  主 UI — 标签页：设备状态 / 读卡 / 模拟 / 卡片库 / 日志
//

import SwiftUI

struct RootView: View {

    @EnvironmentObject var state: AppState
    @State private var selectedTab = 0
    @State private var saveName = ""

    var body: some View {
        TabView(selection: $selectedTab) {
            // MARK: Tab 1: 状态仪表板
            DashboardView()
                .tabItem {
                    Image(systemName: "gearshape.fill")
                    Text("状态")
                }
                .tag(0)

            // MARK: Tab 2: 读卡 / 克隆
            ReadWriteView()
                .tabItem {
                    Image(systemName: "wave.3.right.circle.fill")
                    Text("读/写")
                }
                .tag(1)

            // MARK: Tab 3: 卡模拟
            EmulateView()
                .tabItem {
                    Image(systemName: "antenna.radiowaves.left.and.right")
                    Text("模拟")
                }
                .tag(2)

            // MARK: Tab 4: 卡片库
            LibraryView()
                .tabItem {
                    Image(systemName: "tray.fill")
                    Text("卡片库")
                }
                .tag(3)

            // MARK: Tab 5: 日志
            LogView()
                .tabItem {
                    Image(systemName: "terminal.fill")
                    Text("日志")
                }
                .tag(4)
        }
        .tint(.green)
    }
}

// MARK: - Dashboard

struct DashboardView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 16) {
                    // 初始化状态卡片
                    StatusCard(
                        title: "NFC 子系统",
                        status: state.isInitialized ? .ok : .waiting,
                        detail: state.isInitialized ? "RFIC + nfcd 已连接" : "等待初始化..."
                    )

                    // 漏洞链状态
                    Button {
                        state.runFullExploit()
                    } label: {
                        StatusCard(
                            title: "FilzaSlop 漏洞链",
                            status: state.isInitialized ? .ok : .warning,
                            detail: "点击重新运行 exploit chain"
                        )
                    }
                    .buttonStyle(.plain)

                    // MobileGestalt patch
                    Button {
                        NFCManager.shared.shutdown()
                        state.startInitialization()
                    } label: {
                        StatusCard(
                            title: "MobileGestalt NFC patch",
                            status: .info,
                            detail: "重启 NFC 子系统"
                        )
                    }
                    .buttonStyle(.plain)

                    Divider()

                    // 工具按钮
                    HStack(spacing: 12) {
                        ActionButton(title: "重启 nfcd", icon: "arrow.clockwise", color: .orange) {
                            state.killNFCD()
                        }
                        ActionButton(title: "重置 MG", icon: "arrow.counterclockwise", color: .red) {
                            state.resetMobileGestalt()
                        }
                    }

                    Divider()

                    // 设备信息
                    VStack(alignment: .leading, spacing: 8) {
                        Text("设备信息")
                            .font(.headline)
                        Text("📱 \(UIDevice.current.model)")
                        Text("🔧 iOS \(UIDevice.current.systemVersion)")
                        Text("🔋 \(UIDevice.current.batteryLevel >= 0 ? "\(Int(UIDevice.current.batteryLevel * 100))%" : "N/A")")
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
                    .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 12))
                }
                .padding()
            }
            .navigationTitle("NFC Clone")
        }
    }
}

// MARK: - Read/Write

struct ReadWriteView: View {
    @EnvironmentObject var state: AppState
    @State private var saveName = ""

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                // 读卡片按钮
                BigButton(title: "🔍 扫描并读卡", color: .green) {
                    state.readCard()
                }

                if let card = state.currentCard {
                    CardDetailView(card: card)

                    HStack {
                        TextField("给卡片起个名字", text: $saveName)
                            .textFieldStyle(.roundedBorder)
                            .disabled(saveName.isEmpty)
                        Button("保存") {
                            guard !saveName.isEmpty else { return }
                            state.saveCard(saveName)
                            saveName = ""
                        }
                        .buttonStyle(.borderedProminent)
                        .disabled(saveName.isEmpty)
                    }

                    BigButton(title: "📝 克隆到空白卡", color: .blue) {
                        state.cloneToNew()
                    }
                } else {
                    ContentUnavailableView(
                        "还没读到卡",
                        systemImage: "creditcard",
                        description: Text("点上面的按钮开始扫描")
                    )
                }
            }
            .padding()
            .navigationTitle("读 / 写")
        }
    }
}

// MARK: - Emulate

struct EmulateView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                if let card = state.currentCard {
                    CardDetailView(card: card)

                    BigButton(
                        title: state.emulationActive ? "⏹️ 停止模拟" : "🎯 开始模拟",
                        color: state.emulationActive ? .red : .purple
                    ) {
                        state.startEmulation()
                    }

                    if state.emulationActive {
                        VStack {
                            ProgressView()
                                .controlSize(.large)
                            Text("iPhone 正在广播...")
                                .foregroundStyle(.secondary)
                            Text("⚠️ iOS 可能会重启 nfcd 守护进程")
                                .font(.footnote)
                                .foregroundStyle(.orange)
                        }
                        .padding()
                    }
                } else {
                    ContentUnavailableView(
                        "先去读一张卡",
                        systemImage: "antenna.radiowaves.left.and.right",
                        description: Text("模拟功能需要一张已读取的卡片")
                    )
                }
            }
            .padding()
            .navigationTitle("卡模拟")
        }
    }
}

// MARK: - Library

struct LibraryView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        NavigationStack {
            let library = NFCManager.shared.loadLibrary()

            List {
                if library.isEmpty {
                    ContentUnavailableView(
                        "卡片库是空的",
                        systemImage: "tray",
                        description: Text("读一张卡然后保存它")
                    )
                    .frame(maxWidth: .infinity)
                } else {
                    ForEach(Array(library.keys), id: \.self) { name in
                        let card = library[name]!
                        HStack {
                            VStack(alignment: .leading) {
                                Text(name).font(.headline)
                                Text("UID: \(card.uidHex)")
                                    .font(.caption)
                                    .foregroundStyle(.secondary)
                                Text(card.type.displayName)
                                    .font(.caption2)
                                    .foregroundStyle(.tertiary)
                            }
                            Spacer()
                            Button {
                                state.currentCard = card
                                state.appendLog("Loaded card '\(name)'")
                            } label: {
                                Image(systemName: "arrow.counterclockwise")
                            }
                            Button(role: .destructive) {
                                NFCManager.shared.deleteFromLibrary(name)
                                state.appendLog("Deleted '\(name)'")
                            } label: {
                                Image(systemName: "trash")
                            }
                        }
                    }
                }
            }
            .navigationTitle("卡片库")
            .refreshable { }
        }
    }
}

// MARK: - Log

struct LogView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        NavigationStack {
            List(state.logs, id: \.self) { log in
                Text(log)
                    .font(.system(.caption, design: .monospaced))
            }
            .navigationTitle("日志")
        }
    }
}

// MARK: - Card Detail

struct CardDetailView: View {
    let card: NFCCardSnapshot

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            LabeledContent("类型", value: card.type.displayName)
            LabeledContent("UID", value: card.uidHex)
            LabeledContent("ATQA", value: card.atqa.hexString)
            LabeledContent("SAK", value: String(format: "0x%02X", card.sak))
            LabeledContent("数据块", value: "\(card.blockCount) blocks")
            LabeledContent("时间", value: card.timestamp.formatted())
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 12))
    }
}

// MARK: - 辅助组件

struct StatusCard: View {
    let title: String
    let status: Status
    let detail: String

    enum Status { case ok, waiting, warning, info }

    var body: some View {
        HStack {
            Circle()
                .fill(color)
                .frame(width: 12, height: 12)
            VStack(alignment: .leading) {
                Text(title).font(.headline)
                Text(detail).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding()
        .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 12))
    }

    var color: Color {
        switch status {
        case .ok: return .green
        case .waiting: return .orange
        case .warning: return .orange
        case .info: return .blue
        }
    }
}

struct BigButton: View {
    let title: String
    let color: Color
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            Text(title)
                .font(.title3.bold())
                .frame(maxWidth: .infinity)
                .padding()
                .background(color, in: RoundedRectangle(cornerRadius: 16))
                .foregroundStyle(.white)
        }
        .buttonStyle(.plain)
    }
}

struct ActionButton: View {
    let title: String
    let icon: String
    let color: Color
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(spacing: 8) {
                Image(systemName: icon).font(.title2)
                Text(title).font(.footnote)
            }
            .frame(maxWidth: .infinity)
            .padding()
            .background(color.opacity(0.2), in: RoundedRectangle(cornerRadius: 12))
            .foregroundStyle(color)
        }
        .buttonStyle(.plain)
    }
}
