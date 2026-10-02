import 'dart:convert';
import 'dart:typed_data';

import 'package:http/http.dart' as http;

import '../core/config.dart';

/// A failure returned by the server, or a transport failure talking to it.
///
/// [code] mirrors the server's machine-readable error code so the UI can react
/// to specific cases (e.g. `keys_not_published`, `zero_knowledge_violation`)
/// instead of matching on prose.
class ApiException implements Exception {
  ApiException(this.status, this.code, [this.message]);

  final int status;
  final String code;
  final String? message;

  /// True when the request never reached the server, so retrying may help.
  bool get isNetwork => status == 0;

  @override
  String toString() =>
      'ApiException($status $code${message == null ? '' : ': $message'}';
}

/// REST client for the SecureChat server.
///
/// This layer is deliberately ignorant of content: it moves opaque ciphertext
/// envelopes and public key material, and never sees plaintext. It performs no
/// cryptography of its own.
class SecureApi {
  SecureApi({http.Client? httpClient, Future<String?> Function()? tokenProvider})
      : _http = httpClient ?? http.Client(),
        _tokenProvider = tokenProvider;

  final http.Client _http;
  final Future<String?> Function()? _tokenProvider;

  /// Bearer token, read fresh on every request so a re-login takes effect
  /// without rebuilding the client.
  Future<String?> token() async => _tokenProvider?.call();

  Future<Map<String, String>> _headers({bool json = true, bool auth = true}) async {
    final h = <String, String>{};
    if (json) h['content-type'] = 'application/json';
    if (auth) {
      final t = await token();
      if (t != null) h['authorization'] = 'Bearer $t';
    }
    return h;
  }

  Uri _uri(String path, [Map<String, String>? query]) =>
      Uri.parse('${AppConfig.apiBaseUrl}$path').replace(queryParameters: query);

  Map<String, dynamic> _decode(http.Response r) {
    Map<String, dynamic> body;
    try {
      final decoded = jsonDecode(r.body);
      body = decoded is Map<String, dynamic> ? decoded : {'raw': r.body};
    } catch (_) {
      body = {'raw': r.body};
    }
    if (r.statusCode >= 400) {
      throw ApiException(
        r.statusCode,
        '${body['code'] ?? body['error'] ?? 'request_failed'}',
        '${body['message'] ?? ''}',
      );
    }
    return body;
  }

  Future<Map<String, dynamic>> _get(String path,
      [Map<String, String>? query, bool auth = true]) async {
    final res = await _http
        .get(_uri(path, query), headers: await _headers(auth: auth))
        .timeout(AppConfig.requestTimeout);
    return _decode(res);
  }

  Future<Map<String, dynamic>> _post(String path, Map<String, dynamic> body,
      {bool auth = true}) async {
    final res = await _http
        .post(_uri(path), headers: await _headers(auth: auth), body: jsonEncode(body))
        .timeout(AppConfig.requestTimeout);
    return _decode(res);
  }

  Future<Map<String, dynamic>> _patch(String path, Map<String, dynamic> body) async {
    final res = await _http
        .patch(_uri(path), headers: await _headers(), body: jsonEncode(body))
        .timeout(AppConfig.requestTimeout);
    return _decode(res);
  }

  Future<Map<String, dynamic>> _delete(String path) async {
    final res = await _http
        .delete(_uri(path), headers: await _headers())
        .timeout(AppConfig.requestTimeout);
    return _decode(res);
  }

  // --- Auth ------------------------------------------------------------------
  //
  // A phone number is registered once and then only ever used to sign in.
  // `register` refuses a number that already exists rather than replacing it,
  // so it cannot be used to take over an account.

  /// Create an account. 409 if the number is already registered.
  Future<Map<String, dynamic>> register({
    required String phone,
    required String password,
    String? displayName,
    String? deviceName,
    String? deviceId,
    Map<String, dynamic>? publicKeyBundle,
  }) =>
      _post('/api/auth/register', {
        'phone': phone,
        'password': password,
        if (publicKeyBundle != null) ...{
          'publicIdentityKey': publicKeyBundle['identityKey'],
          'signedPreKey': publicKeyBundle['signedPreKey'],
          'oneTimePreKeys': publicKeyBundle['oneTimePreKeys'],
        },
        if (displayName != null) 'displayName': displayName,
        if (deviceName != null) 'deviceName': deviceName,
        if (deviceId != null) 'deviceId': deviceId,
      });

  /// Sign in to an existing account.
  Future<Map<String, dynamic>> login({
    required String phone,
    required String password,
    String? displayName,
    String? deviceName,
    String? deviceId,
    Map<String, dynamic>? publicKeyBundle,
  }) =>
      _post('/api/auth/login', {
        'phone': phone,
        'password': password,
        if (publicKeyBundle != null) ...{
          'publicIdentityKey': publicKeyBundle['identityKey'],
          'signedPreKey': publicKeyBundle['signedPreKey'],
          'oneTimePreKeys': publicKeyBundle['oneTimePreKeys'],
        },
        if (displayName != null) 'displayName': displayName,
        if (deviceName != null) 'deviceName': deviceName,
        if (deviceId != null) 'deviceId': deviceId,
      });

  /// Whether a number already has an account. Used to guide the sign-up UI.
  Future<bool> isRegistered(String phone) async {
    final body = await _get('/api/auth/check/${Uri.encodeComponent(phone)}');
    return body['registered'] == true;
  }

  /// Server-side password policy, so the client can match it exactly.
  Future<Map<String, dynamic>> passwordPolicy() => _get('/api/auth/policy');

  /// Change the password. Requires the current one.
  Future<Map<String, dynamic>> changePassword({
    required String currentPassword,
    required String newPassword,
  }) =>
      _post('/api/auth/change-password', {
        'currentPassword': currentPassword,
        'newPassword': newPassword,
      });

  /// Unauthenticated reachability probe, used by the server picker.
  Future<Map<String, dynamic>> health() => _get('/health', null, false);

  /// Current identity plus pre-key pool health.
  Future<Map<String, dynamic>> me() => _get('/api/auth/me');

  Future<Map<String, dynamic>> updateProfile(Map<String, dynamic> patch) =>
      _patch('/api/auth/me', patch);


  // --- Keys ------------------------------------------------------------------

  /// Publish this device's public key bundle.
  Future<Map<String, dynamic>> publishKeys(Map<String, dynamic> bundle) =>
      _post('/api/keys', {
        'identityKey': bundle['identityKey'],
        'signedPreKey': bundle['signedPreKey'],
        'oneTimePreKeys': bundle['oneTimePreKeys'],
      });

  /// Top up the one-time pre-key pool as peers consume keys.
  Future<Map<String, dynamic>> topUpPreKeys(
          List<Map<String, dynamic>> oneTimePreKeys) =>
      _post('/api/keys/prekeys', {'oneTimePreKeys': oneTimePreKeys});

  /// Fetch a peer's published keys.
  ///
  /// With [consume] the server atomically burns one one-time pre-key, which is
  /// what makes an X3DH handshake non-replayable.
  Future<Map<String, dynamic>> fetchKeys(String userId, {bool consume = false}) =>
      _get('/api/keys/$userId', consume ? {'consume': 'true'} : null);

  // --- Users & chats ---------------------------------------------------------

  Future<List<Map<String, dynamic>>> searchUsers(String query) async {
    final body = await _get('/api/users/search', {'q': query});
    return (body['users'] as List? ?? const []).cast<Map<String, dynamic>>();
  }

  Future<Map<String, dynamic>> userProfile(String userId) =>
      _get('/api/users/$userId');

  /// Both public identity keys, for computing the safety number locally.
  Future<Map<String, dynamic>> safetyNumber(String userId) =>
      _get('/api/users/$userId/safety-number');

  /// Chat list. Every `lastMessage` here is ciphertext.
  Future<List<Map<String, dynamic>>> chats() async {
    final body = await _get('/api/chats');
    return (body['chats'] as List? ?? const []).cast<Map<String, dynamic>>();
  }

  Future<Map<String, dynamic>> chatWith(String peerId) =>
      _get('/api/chats/with/$peerId');

  // --- Profile -----------------------------------------------------------------

  /// Withdraw this account's access to [userId].
  Future<void> revokeVerification(String userId) async {
    await _delete('/api/verification/$userId');
  }

  // --- Messages --------------------------------------------------------------

  /// Persist one encrypted message.
  ///
  /// There is deliberately no plaintext parameter: adding one would make the
  /// server reject the request, which is the point of the zero-knowledge guard.
  Future<Map<String, dynamic>> sendMessage({
    required String clientMessageId,
    String? receiverId,
    String? groupId,
    required String ciphertext,
    required String iv,
    String mac = '',
    required Map<String, dynamic> header,
    required Map<String, dynamic> envelope,
    String? replyToClientMessageId,
  }) =>
      _post('/api/messages', {
        'clientMessageId': clientMessageId,
        if (receiverId != null) 'receiverId': receiverId,
        if (groupId != null) 'groupId': groupId,
        'ciphertext': ciphertext,
        'iv': iv,
        'mac': mac,
        'header': header,
        'envelope': envelope,
        if (replyToClientMessageId != null)
          'replyToClientMessageId': replyToClientMessageId,
      });

  /// A page of a thread, ciphertext only.
  Future<List<Map<String, dynamic>>> messages(
    String chatId, {
    int limit = 50,
    String? before,
  }) async {
    final body = await _get('/api/messages/$chatId', {
      'limit': '$limit',
      if (before != null) 'before': before,
    });
    return (body['messages'] as List? ?? const []).cast<Map<String, dynamic>>();
  }

  /// Mark incoming messages delivered or read.
  Future<Map<String, dynamic>> markStatus(List<String> messageIds, String status) =>
      _post('/api/messages/receipts', {
        'messageIds': messageIds,
        'status': status,
      });


  // --- Groups ----------------------------------------------------------------

  Future<Map<String, dynamic>> createGroup(String name, List<String> memberIds,
          {int disappearingMessagesSeconds = 0}) =>
      _post('/api/groups', {
        'name': name,
        'memberIds': memberIds,
        'disappearingMessagesSeconds': disappearingMessagesSeconds,
      });

  Future<List<Map<String, dynamic>>> groups() async {
    final body = await _get('/api/groups');
    return (body['groups'] as List? ?? const []).cast<Map<String, dynamic>>();
  }

  Future<Map<String, dynamic>> group(String groupId) => _get('/api/groups/$groupId');

  /// Update a group's settings, including the disappearing-message policy.
  Future<Map<String, dynamic>> updateGroup(
    String groupId, {
    String? name,
    int? disappearingMessagesSeconds,
  }) =>
      _patch('/api/groups/$groupId', {
        if (name != null) 'name': name,
        if (disappearingMessagesSeconds != null)
          'disappearingMessagesSeconds': disappearingMessagesSeconds,
      });

  Future<Map<String, dynamic>> addGroupMembers(
          String groupId, List<String> memberIds) =>
      _post('/api/groups/$groupId/members', {'memberIds': memberIds});

  Future<Map<String, dynamic>> removeGroupMember(String groupId, String userId) =>
      _delete('/api/groups/$groupId/members/$userId');

  // --- Media -----------------------------------------------------------------

  /// Get a short-lived upload target for an ALREADY encrypted blob.
  Future<Map<String, dynamic>> presignUpload({
    required int size,
    String contentType = 'application/octet-stream',
    String kind = 'file',
  }) =>
      _post('/api/media/presign', {
        'size': size,
        'contentType': contentType,
        'kind': kind,
      });

  /// Upload encrypted bytes to a presigned target (S3) or the local driver.
  Future<void> putBlob(String url, Uint8List bytes, String contentType) async {
    final res = await _http
        .put(_resolveBlobUrl(url),
            headers: {'content-type': contentType}, body: bytes)
        .timeout(const Duration(minutes: 5));
    if (res.statusCode >= 400) {
      throw ApiException(res.statusCode, 'upload_failed');
    }
  }

  /// Download an encrypted blob.
  Future<Uint8List> getBlob(String url) async {
    final res = await _http
        .get(_resolveBlobUrl(url))
        .timeout(const Duration(minutes: 5));
    if (res.statusCode >= 400) {
      throw ApiException(res.statusCode, 'download_failed');
    }
    return res.bodyBytes;
  }

  /// The local storage driver returns a relative URL; retarget it at the API
  /// base. Real S3 presigned URLs are absolute and pass through untouched.
  Uri _resolveBlobUrl(String url) {
    final parsed = Uri.parse(url);
    if (parsed.hasScheme) return parsed;
    return Uri.parse('${AppConfig.apiBaseUrl}${parsed.path}');
  }

  /// Remove a message you sent, for everyone.
  Future<void> deleteMessage(String messageId) =>
      _delete('/api/messages/$messageId');
}

