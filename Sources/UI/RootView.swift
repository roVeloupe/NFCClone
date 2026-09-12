//
//  RootView.swift
//  NFCClone
//

import SwiftUI

struct RootView: View {
    @EnvironmentObject var state: AppState
    @State private var selectedTab = 0
    @State private var saveName = ""

    var body: some View {
        TabView(selection: $selectedTab) {
            DashboardView().tabItem { Label("状态", systemImage: "gearshape") }.tag(0)
            ReadView().tabItem { Label("读卡", systemImage: "wave.3.right") }.tag(1)
            EmulateView().tabItem { Label("模拟", systemImage: "antenna.radiowaves.left.and.right") }.tag(2)
            LogView().tabItem { Label("日志", systemImage: "terminal") }.tag(3)
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
                    HStack {
                        Circle().fill(state.isInitialized ? .green : .orange).frame(width: 12, height: 12)
                        VStack(alignment: .leading) {
                            Text("NFC 子系统").font(.headline)
                            Text(state.isInitialized ? "已连接" : "等待初始化").font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                    }.padding().background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 12))

                    Button { state.runExploit() } label: {
                        HStack {
                            Image(systemName: "arrow.clockwise").foregroundStyle(.orange)
                            VStack(alignment: .leading) {
                                Text("重新跑 FilzaSlop").font(.headline)
                                Text("重新执行 exploit chain").font(.caption).foregroundStyle(.secondary)
                            }
                            Spacer()
                        }.padding().background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 12))
                    }.buttonStyle(.plain)

                    Text("⚠️ 需要 iOS 27 beta 1-4 + 企业证书").font(.footnote).foregroundStyle(.orange)
                    Text("beta 5 已补漏洞").font(.footnote).foregroundStyle(.red)

                    Button("🔄 重启 nfcd (no-op in sandbox)") {
                        state.appendLog("需要 no-sandbox entitlement")
                    }
                    .buttonStyle(.bordered).foregroundStyle(.orange)
                }
                .padding()
            }
            .navigationTitle("NFCClone")
        }
    }
}

// MARK: - Read

struct ReadView: View {
    @EnvironmentObject var state: AppState
    @State private var saveName = ""

    var body: some View {
        NavigationStack {
            VStack(spacing: 20) {
                Button("🔍 扫描并读卡") {
                    state.readCard()
                }
                .font(.title3.bold()).frame(maxWidth: .infinity).padding()
                .background(Color.green, in: RoundedRectangle(cornerRadius: 16))
                .foregroundStyle(.white)

                if let card = state.currentCard {
                    VStack(alignment: .leading, spacing: 8) {
                        LabeledContent("类型", value: card.type.displayName)
                        LabeledContent("UID", value: card.uidHex)
                        LabeledContent("ATQA", value: card.atqa.map { String(format: "%02X", $0) }.joined(separator: " "))
                    }
                    .frame(maxWidth: .infinity, alignment: .leading).padding()
                    .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 12))

                    HStack {
                        TextField("起个名字", text: $saveName).textFieldStyle(.roundedBorder)
                        Button("保存") {
                            guard !saveName.isEmpty else { return }
                            state.saveCard(saveName); saveName = ""
                        }.buttonStyle(.borderedProminent)
                    }
                } else {
                    ContentUnavailableView("还没读到卡", systemImage: "creditcard", description: Text("贴卡到 iPhone 背面"))
                }
            }
            .padding().navigationTitle("读卡")
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
                    VStack(alignment: .leading, spacing: 8) {
                        LabeledContent("类型", value: card.type.displayName)
                        LabeledContent("UID", value: card.uidHex)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading).padding()
                    .background(Color(.secondarySystemBackground), in: RoundedRectangle(cornerRadius: 12))

                    Button(state.emulationActive ? "⏹️ 停止模拟" : "🎯 开始模拟") {
                        state.startEmulation()
                    }
                    .font(.title3.bold()).frame(maxWidth: .infinity).padding()
                    .background(state.emulationActive ? Color.red : Color.purple, in: RoundedRectangle(cornerRadius: 16))
                    .foregroundStyle(.white)

                    if state.emulationActive {
                        ProgressView().controlSize(.large)
                        Text("iPhone 正在广播...").foregroundStyle(.secondary)
                    }
                } else {
                    ContentUnavailableView("先去读一张卡", systemImage: "antenna.radiowaves.left.and.right")
                }
            }
            .padding().navigationTitle("卡模拟")
        }
    }
}

// MARK: - Log

struct LogView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        NavigationStack {
            List(state.logs, id: \.self) { Text($0).font(.system(.caption, design: .monospaced)) }
            .navigationTitle("日志")
        }
    }
}
