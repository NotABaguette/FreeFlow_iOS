import SwiftUI

struct ChatsTab: View {
    @EnvironmentObject var state: AppState
    @State private var selectedContact: Contact?

    var body: some View {
        NavigationStack {
            List(state.contacts, selection: $selectedContact) { contact in
                NavigationLink(value: contact) {
                    HStack(spacing: 12) {
                        ZStack {
                            Circle().fill(.blue.gradient).frame(width: 44, height: 44)
                            Text(String(contact.displayName.prefix(1)).uppercased())
                                .font(.system(.body, design: .monospaced)).foregroundStyle(.white).bold()
                        }
                        VStack(alignment: .leading, spacing: 2) {
                            Text(contact.displayName)
                                .font(.system(.body, design: .monospaced)).fontWeight(.medium)
                            if let last = state.conversations[contact.fingerprintHex]?.last {
                                Text(last.text).font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.secondary).lineLimit(1)
                            } else {
                                Text("No messages").font(.system(.caption, design: .monospaced))
                                    .foregroundStyle(.tertiary)
                            }
                        }
                        Spacer()
                        if let n = state.unreadCounts[contact.fingerprintHex], n > 0 {
                            Text("\(n)").font(.caption2).bold().foregroundStyle(.white)
                                .padding(.horizontal, 6).padding(.vertical, 2)
                                .background(.blue).clipShape(Capsule())
                        }
                    }
                }
            }
            .navigationDestination(for: Contact.self) { contact in
                ChatView(contact: contact)
            }
            .navigationTitle("Messages")
            .toolbar {
                ToolbarItem(placement: .topBarLeading) {
                    HStack(spacing: 4) {
                        Circle().fill(state.connectionState.color).frame(width: 8, height: 8)
                        Text(state.connectionState.rawValue)
                            .font(.system(.caption2, design: .monospaced)).foregroundStyle(.secondary)
                    }
                }
                ToolbarItem(placement: .topBarTrailing) {
                    Button { state.syncInbox() } label: {
                        Image(systemName: "arrow.clockwise")
                    }.disabled(!state.sessionActive)
                }
            }
            .overlay {
                if state.contacts.isEmpty {
                    ContentUnavailableView("No Conversations",
                        systemImage: "bubble.left.and.bubble.right",
                        description: Text("Add contacts to start messaging"))
                }
            }
        }
    }
}

struct ChatView: View {
    @EnvironmentObject var state: AppState
    let contact: Contact
    @State private var messageText = ""

    private var messages: [ChatMessage] {
        state.conversations[contact.fingerprintHex] ?? []
    }

    var body: some View {
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(spacing: 6) {
                        HStack {
                            Image(systemName: "lock.fill")
                            Text("End-to-end encrypted")
                        }
                        .font(.system(.caption2, design: .monospaced))
                        .foregroundStyle(.secondary).padding(.vertical, 12)

                        ForEach(messages) { msg in
                            MessageBubble(message: msg).id(msg.id)
                        }
                    }.padding(.horizontal, 12).padding(.bottom, 8)
                }
                .onChange(of: messages.count) { _, _ in
                    if let last = messages.last {
                        withAnimation { proxy.scrollTo(last.id, anchor: .bottom) }
                    }
                }
            }

            Divider()

            HStack(spacing: 8) {
                TextField("Message...", text: $messageText, axis: .vertical)
                    .textFieldStyle(.plain)
                    .font(.system(.body, design: .monospaced))
                    .lineLimit(1...4)
                    .padding(10)
                    .background(Color(.systemGray6))
                    .cornerRadius(20)

                Button {
                    let text = messageText.trimmingCharacters(in: .whitespacesAndNewlines)
                    guard !text.isEmpty else { return }
                    state.sendMessage(text, to: contact)
                    messageText = ""
                } label: {
                    Image(systemName: "arrow.up.circle.fill")
                        .font(.system(size: 32))
                        .foregroundColor(messageText.isEmpty ? .gray : .blue)
                }
                .disabled(messageText.isEmpty)
            }
            .padding(.horizontal, 12).padding(.vertical, 8)
        }
        .navigationTitle(contact.displayName)
        .navigationBarTitleDisplayMode(.inline)
        .onAppear { state.markRead(contact.fingerprintHex) }
    }
}

struct MessageBubble: View {
    let message: ChatMessage
    private var isSent: Bool { message.direction == .sent }

    var body: some View {
        HStack {
            if isSent { Spacer(minLength: 60) }
            VStack(alignment: isSent ? .trailing : .leading, spacing: 2) {
                Text(message.text)
                    .font(.system(.body, design: .monospaced))
                    .padding(.horizontal, 14).padding(.vertical, 8)
                    .background(isSent ? Color.blue : Color(.systemGray5))
                    .foregroundStyle(isSent ? .white : .primary)
                    .cornerRadius(18)
                HStack(spacing: 4) {
                    Text(message.timestamp, style: .time)
                    if isSent {
                        Image(systemName: message.status == .sent ? "checkmark" :
                              message.status == .sending ? "clock" :
                              message.status == .delivered ? "checkmark.circle" : "exclamationmark.circle")
                    }
                }
                .font(.system(.caption2, design: .monospaced)).foregroundStyle(.tertiary)
            }
            if !isSent { Spacer(minLength: 60) }
        }
    }
}
