import SwiftUI
#if canImport(FreeFlowCore)
import FreeFlowCore
#endif

@main
struct FreeFlowApp: App {
    @StateObject private var appState = AppState()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(appState)
        }
    }
}

struct ContentView: View {
    @EnvironmentObject var state: AppState

    var body: some View {
        TabView {
            ChatsTab()
                .tabItem { Label("Chats", systemImage: "bubble.left.and.bubble.right") }
                .badge(state.unreadCounts.values.reduce(0, +))

            ContactsTab()
                .tabItem { Label("Contacts", systemImage: "person.2") }

            BulletinsTab()
                .tabItem { Label("Bulletins", systemImage: "megaphone") }

            ConnectionTab()
                .tabItem { Label("Connection", systemImage: "antenna.radiowaves.left.and.right") }

            SettingsTab()
                .tabItem { Label("Settings", systemImage: "gearshape") }
        }
        .onAppear {
            if !state.hasIdentity {
                // Will show identity creation in Settings
            }
        }
    }
}
