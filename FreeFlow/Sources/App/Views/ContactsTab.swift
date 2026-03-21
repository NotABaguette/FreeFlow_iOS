import SwiftUI

struct ContactsTab: View {
    @EnvironmentObject var state: AppState
    @State private var showAddSheet = false

    var body: some View {
        NavigationStack {
            List {
                ForEach(state.contacts) { contact in
                    NavigationLink {
                        ContactDetail(contact: contact)
                    } label: {
                        HStack(spacing: 12) {
                            ZStack {
                                Circle().fill(.blue.gradient).frame(width: 40, height: 40)
                                Text(String(contact.displayName.prefix(1)).uppercased())
                                    .font(.system(.caption, design: .monospaced)).foregroundStyle(.white).bold()
                            }
                            VStack(alignment: .leading) {
                                Text(contact.displayName).font(.system(.body, design: .monospaced))
                                Text(contact.fingerprintHex)
                                    .font(.system(.caption2, design: .monospaced)).foregroundStyle(.secondary)
                            }
                        }
                    }
                    .swipeActions(edge: .trailing) {
                        Button(role: .destructive) { state.removeContact(contact) } label: {
                            Label("Delete", systemImage: "trash")
                        }
                    }
                }
            }
            .navigationTitle("Contacts")
            .toolbar {
                Button { showAddSheet = true } label: { Image(systemName: "plus") }
            }
            .sheet(isPresented: $showAddSheet) { AddContactSheet() }
            .overlay {
                if state.contacts.isEmpty {
                    ContentUnavailableView("No Contacts", systemImage: "person.2",
                        description: Text("Tap + to add a contact"))
                }
            }
        }
    }
}

struct ContactDetail: View {
    @EnvironmentObject var state: AppState
    let contact: Contact
    @State private var copied = false

    var body: some View {
        List {
            Section("Identity") {
                LabeledContent("Name") { Text(contact.displayName).font(.system(.body, design: .monospaced)) }
                LabeledContent("Fingerprint") {
                    Text(contact.fingerprintHex).font(.system(.caption, design: .monospaced)).textSelection(.enabled)
                }
            }
            Section("Public Key") {
                Text(contact.publicKey.map { String(format: "%02x", $0) }.joined())
                    .font(.system(.caption2, design: .monospaced)).textSelection(.enabled)
            }
            Section("Stats") {
                let msgs = state.conversations[contact.fingerprintHex] ?? []
                LabeledContent("Messages") { Text("\(msgs.count)") }
                LabeledContent("Sent") { Text("\(msgs.filter { $0.direction == .sent }.count)") }
                LabeledContent("Received") { Text("\(msgs.filter { $0.direction == .received }.count)") }
            }
            Section {
                Button {
                    UIPasteboard.general.string = contact.publicKey.map { String(format: "%02x", $0) }.joined()
                    copied = true
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2) { copied = false }
                } label: {
                    Label(copied ? "Copied!" : "Copy Public Key", systemImage: copied ? "checkmark" : "doc.on.doc")
                }
            }
            Section {
                Button(role: .destructive) { state.removeContact(contact) } label: {
                    Label("Remove Contact", systemImage: "trash")
                }
            }
        }
        .navigationTitle(contact.displayName)
    }
}

struct AddContactSheet: View {
    @EnvironmentObject var state: AppState
    @Environment(\.dismiss) var dismiss
    @State private var name = ""
    @State private var publicKeyHex = ""
    @State private var error = ""

    var body: some View {
        NavigationStack {
            Form {
                TextField("Name", text: $name)
                    .font(.system(.body, design: .monospaced))
                Section("Public Key (hex)") {
                    TextEditor(text: $publicKeyHex)
                        .font(.system(.caption, design: .monospaced))
                        .frame(minHeight: 60)
                }
                if !error.isEmpty {
                    Text(error).foregroundStyle(.red).font(.caption)
                }
            }
            .navigationTitle("Add Contact")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add") {
                        do {
                            try state.addContact(name: name, publicKeyHex: publicKeyHex.trimmingCharacters(in: .whitespacesAndNewlines))
                            dismiss()
                        } catch { self.error = "Invalid key. Must be 64 hex characters." }
                    }.disabled(name.isEmpty || publicKeyHex.count < 64)
                }
            }
        }
    }
}
