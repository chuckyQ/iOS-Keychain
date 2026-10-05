//
//  This keychain is used for storing secrets locally
//
//  Created by Charles Quinn on 10/4/26.
//

import Foundation
import Security

protocol KeychainStoring {
    func save(_ value: String, forKey key: String) throws
    func read(forKey key: String) throws -> String?
    func delete(forKey key: String) throws
}

final class KeychainService: KeychainStoring {

    func save(_ value: String, forKey key: String) throws {
        let data = Data(value.utf8)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecValueData as String: data
        ]

        let status = SecItemAdd(query as CFDictionary, nil)

        if status == errSecDuplicateItem {
            let updateQuery: [String: Any] = [
                kSecClass as String: kSecClassGenericPassword,
                kSecAttrAccount as String: key
            ]

            let attributes: [String: Any] = [
                kSecValueData as String: data
            ]

            let updateStatus = SecItemUpdate(
                updateQuery as CFDictionary,
                attributes as CFDictionary
            )

            guard updateStatus == errSecSuccess else {
                throw KeychainError.unhandledError(updateStatus)
            }

            return
        }

        guard status == errSecSuccess else {
            throw KeychainError.unhandledError(status)
        }
    }

    func read(forKey key: String) throws -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(
            query as CFDictionary,
            &result
        )

        if status == errSecItemNotFound {
            return nil
        }

        guard status == errSecSuccess else {
            throw KeychainError.unhandledError(status)
        }

        guard let data = result as? Data else {
            throw KeychainError.invalidData
        }

        return String(data: data, encoding: .utf8)
    }

    func delete(forKey key: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: key
        ]

        let status = SecItemDelete(query as CFDictionary)

        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.unhandledError(status)
        }
    }
}

enum KeychainError: Error {
    case invalidData
    case unhandledError(OSStatus)
}
