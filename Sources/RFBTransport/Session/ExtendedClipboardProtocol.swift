import Foundation
import RFBProtocol

/// The Extended Clipboard pseudo-encoding (0xC0A1E5CE) of TigerVNC 1.10+ and
/// other conventional servers. Legacy ServerCutText / ClientCutText carry
/// ISO 8859-1, so text outside Latin-1 (Chinese, emoji) arrives garbled; this
/// extension carries UTF-8.
///
/// An extended message is a cut-text message whose S32 length is negative;
/// its magnitude is the payload size. The payload starts with a U32 whose
/// low 16 bits name formats and whose high byte holds one action. Text is
/// UTF-8 with CRLF line endings and a terminating NUL, and a `provide`
/// body is zlib-compressed.
enum ExtendedClipboardProtocol {
    static let textFormat: UInt32 = 1 << 0
    static let capsAction: UInt32 = 1 << 24
    static let requestAction: UInt32 = 1 << 25
    static let peekAction: UInt32 = 1 << 26
    static let notifyAction: UInt32 = 1 << 27
    static let provideAction: UInt32 = 1 << 28
    static let formatMask: UInt32 = 0xFFFF

    /// Largest text accepted or sent, NUL included. Matches the transport's
    /// cap on auxiliary payloads.
    static let maximumTextSize = 16 * 1024 * 1024

    static let clientCutTextType: UInt8 = 6
    static let serverCutTextType: UInt8 = 3

    enum Message: Equatable {
        /// The peer's supported actions and formats. `textLimit` is the
        /// largest text it takes without requesting it (TigerVNC: 0), nil
        /// when it does not handle text.
        case caps(flags: UInt32, textLimit: Int?)
        case request(formats: UInt32)
        case peek
        case notify(formats: UInt32)
        /// nil when the provided formats carry no text.
        case provide(text: String?)
    }

    /// Parses the payload following the S32 length, flags included.
    static func parse(_ payload: Data) throws -> Message {
        guard let flags = uint32BE(payload, at: payload.startIndex) else {
            throw violation("Extended clipboard message has no flags")
        }
        let formats = flags & formatMask
        let body = payload.dropFirst(4)
        // TigerVNC's precedence when a peer sets several action bits.
        if flags & capsAction != 0 {
            // One U32 size per format bit, lowest bit first; text is bit 0.
            let textLimit = formats & textFormat != 0
                ? uint32BE(body, at: body.startIndex).map(Int.init)
                : nil
            return .caps(flags: flags, textLimit: textLimit)
        }
        if flags & requestAction != 0 { return .request(formats: formats) }
        if flags & peekAction != 0 { return .peek }
        if flags & notifyAction != 0 { return .notify(formats: formats) }
        if flags & provideAction != 0 {
            guard formats & textFormat != 0 else { return .provide(text: nil) }
            return .provide(text: try providedText(Data(body)))
        }
        throw violation("Extended clipboard message has no action")
    }

    /// The client's capabilities: text up to `maximumTextSize`, every action.
    static func capsMessage() -> Data {
        var body = Data()
        appendUInt32BE(UInt32(maximumTextSize), to: &body)
        return clientMessage(
            flags: capsAction | textFormat | requestAction | peekAction
                | notifyAction | provideAction,
            body: body)
    }

    static func notifyMessage(hasText: Bool) -> Data {
        clientMessage(flags: notifyAction | (hasText ? textFormat : 0),
                      body: Data())
    }

    static func requestMessage() -> Data {
        clientMessage(flags: requestAction | textFormat, body: Data())
    }

    /// Throws when the encoded text, NUL included, exceeds `limit`.
    static func provideMessage(_ text: String, limit: Int) throws -> Data {
        var bytes = Data(crlf(text).utf8)
        bytes.append(0)
        guard bytes.count <= min(limit, maximumTextSize) else {
            throw violation(
                "Clipboard text of \(bytes.count) bytes exceeds the limit "
                    + "of \(limit)")
        }
        var stream = Data()
        appendUInt32BE(UInt32(bytes.count), to: &stream)
        stream.append(bytes)
        return clientMessage(flags: provideAction | textFormat,
                             body: try AppleClipboardProtocol.compress(stream))
    }

    /// A complete ClientCutText (`type` 6) or ServerCutText (`type` 3)
    /// carrying `flags` and `body` as an extended message.
    static func message(type: UInt8, flags: UInt32, body: Data) -> Data {
        var data = Data([type, 0, 0, 0])
        appendUInt32BE(UInt32(bitPattern: -Int32(4 + body.count)), to: &data)
        appendUInt32BE(flags, to: &data)
        data.append(body)
        return data
    }

    private static func clientMessage(flags: UInt32, body: Data) -> Data {
        message(type: clientCutTextType, flags: flags, body: body)
    }

    private static func providedText(_ compressed: Data) throws -> String {
        guard !compressed.isEmpty else {
            throw violation("Extended clipboard provide has no data")
        }
        // Each message is its own zlib stream. Text is the lowest format, so
        // it comes first; anything after it is ignored.
        let stream = try RFBZlibStreamInflater().decompress(
            compressed, maxOutputSize: 4 + maximumTextSize)
        guard let length = uint32BE(stream, at: stream.startIndex).map(Int.init),
              length <= stream.count - 4 else {
            throw violation("Truncated extended clipboard text")
        }
        var bytes = stream.dropFirst(4).prefix(length)
        if let nul = bytes.firstIndex(of: 0) { bytes = bytes[..<nul] }
        guard let text = String(data: Data(bytes), encoding: .utf8) else {
            throw violation("Extended clipboard text is not UTF-8")
        }
        return lf(text)
    }

    /// CRLF and lone CR become LF.
    static func lf(_ text: String) -> String {
        text.replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
    }

    /// Every line ending becomes CRLF, as the extension requires.
    static func crlf(_ text: String) -> String {
        lf(text).replacingOccurrences(of: "\n", with: "\r\n")
    }

    private static func uint32BE(_ data: Data, at index: Int) -> UInt32? {
        AppleClipboardProtocol.uint32BE(data, at: index)
    }

    private static func appendUInt32BE(_ value: UInt32, to data: inout Data) {
        data.append(UInt8((value >> 24) & 0xFF))
        data.append(UInt8((value >> 16) & 0xFF))
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }

    private static func violation(_ message: String) -> VNCProtocolError {
        .protocolViolation(message)
    }
}
