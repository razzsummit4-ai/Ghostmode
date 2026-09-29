/// Wire models shared by the HTTP client and the local chat store.
///
/// Every message from the server is ciphertext-only: `ciphertext`, `iv` and
/// `header`. There is deliberately no `text` field anywhere in these models.
class ChatUser {
  ChatUser({
    required this.id,
    required this.phone,
    required this.displayName,
    this.publicIdentityKey,
    this.registrationId,
    this.avatarColor = 0,
    this.hasKeys = false,
  });

  final String id;
  final String phone;
  final String displayName;
  String? publicIdentityKey;
  int? registrationId;
  int avatarColor;
  bool hasKeys;

  factory ChatUser.fromJson(Map<String, dynamic> j) => ChatUser(
        id: '${j['id']}',
        phone: '${j['phone'] ?? ''}',
        displayName: '${j['displayName'] ?? 'Unknown'}',
        publicIdentityKey: j['publicIdentityKey'] as String?,
        registrationId: (j['registrationId'] as num?)?.toInt(),
        avatarColor: (j['avatarColor'] as num?)?.toInt() ?? 0,
        hasKeys: j['hasKeys'] as bool? ?? false,
      );
}

/// A stored or in-flight message: ciphertext plus routing metadata.
class ChatMessage {
  ChatMessage({
    required this.id,
    required this.clientMessageId,
    required this.chatId,
    required this.senderId,
    this.receiverId,
    this.groupId,
    required this.ciphertext,
    required this.iv,
    this.mac = '',
    required this.header,
    this.envelope = const {'type': 'text'},
    this.status = 'sent',
    this.createdAt,
    this.cleartext,
    this.mediaKind,
    this.mediaLocalPath,
  });

  final String id;
  final String clientMessageId;
  final String chatId;
  final String senderId;
  final String? receiverId;
  final String? groupId;
  final String ciphertext;
  final String iv;
  final String mac;
  final Map<String, dynamic> header;
  final Map<String, dynamic> envelope;
  String status;
  final DateTime? createdAt;

  /// Decrypted body. In-memory only - never persisted.
  String? cleartext;
  String? mediaKind;
  String? mediaLocalPath;

  bool get isGroup => groupId != null && groupId!.isNotEmpty;
  String get messageType => '${envelope['type'] ?? 'text'}';

  factory ChatMessage.fromJson(Map<String, dynamic> j) => ChatMessage(
        id: '${j['id']}',
        clientMessageId: '${j['clientMessageId'] ?? ''}',
        chatId: '${j['chatId'] ?? ''}',
        senderId: '${j['senderId'] ?? ''}',
        receiverId: j['receiverId'] as String?,
        groupId: j['groupId'] as String?,
        ciphertext: '${j['ciphertext'] ?? ''}',
        iv: '${j['iv'] ?? ''}',
        mac: '${j['mac'] ?? ''}',
        header: Map<String, dynamic>.from(j['header'] as Map? ?? const {}),
        envelope:
            Map<String, dynamic>.from(j['envelope'] as Map? ?? const {'type': 'text'}),
        status: '${j['status'] ?? 'sent'}',
        createdAt:
            j['createdAt'] == null ? null : DateTime.tryParse('${j['createdAt']}'),
      );

  Map<String, dynamic> toJson() => {
        'id': id,
        'clientMessageId': clientMessageId,
        'chatId': chatId,
        'senderId': senderId,
        'receiverId': receiverId,
        'groupId': groupId,
        'ciphertext': ciphertext,
        'iv': iv,
        'mac': mac,
        'header': header,
        'envelope': envelope,
        'status': status,
        'createdAt': createdAt?.toIso8601String(),
      };
}

class ChatThread {
  ChatThread({
    required this.chatId,
    required this.type,
    required this.title,
    this.peerId,
    this.groupId,
    this.phone,
    this.avatarColor = 0,
    this.memberIds = const [],
    this.disappearingMessagesSeconds = 0,
    this.lastMessage,
  });

  final String chatId;
  final String type;
  final String title;
  final String? peerId;
  final String? groupId;
  final String? phone;
  final int avatarColor;
  final List<String> memberIds;
  final int disappearingMessagesSeconds;
  final ChatMessage? lastMessage;

  bool get isGroup => type == 'group';

  factory ChatThread.fromJson(Map<String, dynamic> j) {
    final m = j['lastMessage'];
    return ChatThread(
      chatId: '${j['chatId']}',
      type: '${j['type'] ?? 'direct'}',
      title: '${j['title'] ?? 'Unknown'}',
      peerId: j['peerId'] as String?,
      groupId: j['groupId'] as String?,
      phone: j['phone'] as String?,
      avatarColor: (j['avatarColor'] as num?)?.toInt() ?? 0,
      memberIds:
          ((j['memberIds'] as List?) ?? const []).map((e) => '$e').toList(),
      disappearingMessagesSeconds:
          (j['disappearingMessagesSeconds'] as num?)?.toInt() ?? 0,
      lastMessage: m == null
          ? null
          : ChatMessage.fromJson(Map<String, dynamic>.from(m as Map)),
    );
  }
}
