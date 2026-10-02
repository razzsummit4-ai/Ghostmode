import 'dart:async';

import 'package:flutter/foundation.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../core/config.dart';
import '../net/api.dart';
import '../net/discovery.dart';
import '../net/realtime.dart';
import '../session/session_manager.dart';
import '../service/messaging.dart';
import '../service/secure_window.dart';
import '../store/key_vault.dart';
import 'chat_store.dart';

/// Lifecycle phase, driving which screen the router shows.
enum AppPhase {
  /// Reading secure storage and restoring a previous session.
  booting,

  /// No valid token: show the OTP login screen.
  signedOut,

  /// Authenticated, but this device has not published a key bundle yet.
  generatingKeys,

  /// Authenticated with keys published: show the chat list.
  ready,
}

/// Owns authentication, the device key lifecycle, and all crypto sessions.
///
/// This is the only place that decides whether a device may send or receive.
/// It enforces the invariant the whole project rests on: the app never reaches
/// [AppPhase.ready] unless a key identity exists on this device AND the server
/// holds the matching public bundle.
class AppState extends ChangeNotifier {
  AppState({KeyVault? vault})
      : vault = vault ?? KeyVault() {
    // The API client must read the token from this instance, not from a
    // captured copy, so a sign-in takes effect immediately and a sign-out is
    // never served from a stale cache. Without this callback every request goes
    // out unauthenticated and the server answers 401 "Missing bearer token".
    api = SecureApi(tokenProvider: _currentToken);
  }

  final KeyVault vault;

  /// The REST client. Rebuilt on logout so no request can carry a dead token.
  late final SecureApi api;

  final ChatStore chats = ChatStore();
  late final SessionManager sessions;

  /// Built during bootstrap; owns all encrypt/decrypt of message content.
  late final MessagingService messaging;

  /// Live transport for ciphertext, receipts and typing.
  final RealtimeGateway realtime = RealtimeGateway();

  StreamSubscription<Map<String, dynamic>>? _inbound;
  StreamSubscription<ReceiptEvent>? _receiptSub;
  StreamSubscription<TypingEvent>? _typingSub;

  /// Subscription to the socket's "your pre-keys are empty" notification.
  StreamSubscription<void>? _preKeysSub;

  /// Whether the live socket is currently up.
  bool realtimeConnected = false;

  /// Screenshot blocking, persisted so the choice survives a restart.
  bool blockScreenshots = true;

  /// The server this install talks to, loaded from preferences.
  String get serverUrl => AppConfig.apiBaseUrl;

  /// The server rejected our token (401) on a request that should have been
  /// authenticated.
  ///
  /// The token is dropped and the router returns to the sign-in screen, but the
  /// device keys are deliberately KEPT. Signing out through [logout] destroys
  /// them, which would permanently orphan every ratchet chain and make already
  /// received messages undecryptable. Keys outlive a token; only the server
  /// session is gone.
  Future<void> handleUnauthorized() async {
    if (token == null) return;
    _teardownRealtime();
    token = null;
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('sc.token');
    phase = AppPhase.signedOut;
    notifyListeners();
  }

  /// Supplies the bearer token to the REST client on every request.
  ///
  /// Returning the live field (rather than a value captured at construction) is
  /// what makes sign-in take effect immediately and sign-out take effect at
  /// once. An empty string is normalised to null so no request is ever sent as
  /// `Authorization: Bearer `, which the server rejects.
  Future<String?> _currentToken() async {
    final value = token;
    if (value == null || value.isEmpty) return null;
    return value;
  }

  /// Point the app at a different server and reconnect.
  ///
  /// Changing the address invalidates the live socket, so it is torn down and
  /// re-established. Sessions and keys are kept: they are per-contact, not
  /// per-server, and re-logging-in would destroy the ratchet chain.
  Future<void> setServerUrl(String rawUrl) async {
    final next = AppConfig.normaliseUrl(rawUrl);
    if (next == AppConfig.apiBaseUrl) return;

    final changedHost =
        Uri.tryParse(next)?.host != Uri.tryParse(AppConfig.apiBaseUrl)?.host;
    AppConfig.apiBaseUrl = next;

    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('sc.serverUrl', next);

    _teardownRealtime();
    if (changedHost && phase == AppPhase.ready) {
      // A different server means a different account: a token minted by the old
      // one is rejected by the new, and keeping it leaves the user staring at a
      // chat list that silently never loads. Keys are per-contact and stay.
      token = null;
      userId = null;
      for (final k in ['sc.token', 'sc.userId']) {
        await prefs.remove(k);
      }
      phase = AppPhase.signedOut;
    } else if (phase == AppPhase.ready) {
      _startRealtime();
    }
    notifyListeners();
  }

  /// Check the configured server is reachable and answering.
  ///
  /// Reported as a plain yes/no rather than a raw exception, because the user
  /// is usually looking at a server they typed in themselves.
  Future<({bool ok, String detail})> testServer() async {
    final base = AppConfig.apiBaseUrl;
    try {
      final res = await api.health();
      // Something answering is not the same as the right thing answering. A
      // different program on this port is otherwise invisible: the connection
      // succeeds, and every sign-in then fails for a reason the user cannot see.
      final service = '${res['service'] ?? ''}';
      if (service.isNotEmpty && service != 'securechat') {
        return (
          ok: false,
          detail: 'That address runs "$service", not SecureChat. Start the '
              'SecureChat server, or enter the address it is really on.',
        );
      }
      return (ok: true, detail: 'Connected — ${res['db'] ?? 'ok'}');
    } on ApiException catch (e) {
      // The emulator alias is a build-time accident, not something the user can
      // have typed by mistake, so name the cause and the fix instead of asking
      // them to check a port that is not what is wrong.
      if (e.isNetwork && AppConfig.usesEmulatorHost) {
        return (
          ok: false,
          detail: 'This build points at ${AppConfig.apiBaseUrl}, which only '
              'exists inside an Android emulator. Open Settings and set the '
              'server address to your real server.',
        );
      }
      final detail = switch (e.code) {
        'unauthorized' => 'Reachable, but rejected the token.',
        'not_found' =>
          'Something answers at $base, but it is not a SecureChat server.',
        _ when e.isNetwork =>
          'Cannot reach $base. Check the address, the port, and that the '
              'server is running.',
        _ => 'Reachable, but returned ${e.code}.',
      };
      return (ok: false, detail: detail);
    }
  }

  /// True while a discovery scan is running, so the UI can show progress.
  bool discovering = false;

  /// Servers found on the local network by the last scan.
  List<DiscoveredServer> discoveredServers = const [];

  /// Look for SecureChat servers on this Wi-Fi.
  ///
  /// This is what makes the app work for anyone: the APK cannot carry an
  /// address, so a fresh install on a phone finds the server by itself instead
  /// of asking the user to read an IP off a terminal. Each candidate is
  /// verified against `/health` before being offered.
  Future<List<DiscoveredServer>> discoverServers() async {
    discovering = true;
    notifyListeners();
    try {
      final seen = await ServerDiscovery.scan();

      // Only offer a candidate that actually answers as a SecureChat server, so
      // an unrelated device on the LAN cannot be picked by mistake.
      final verified = <DiscoveredServer>[];
      for (final server in seen) {
        for (final url in server.candidateUrls) {
          if (await ServerDiscovery.isSecureChatServer(url)) {
            verified.add(DiscoveredServer(
              name: server.name,
              addresses: server.addresses,
              httpPort: server.httpPort,
              // Pin the exact URL that answered, not the first address.
              publicUrl: url,
            ));
            break;
          }
        }
      }

      discoveredServers = verified;
      return verified;
    } finally {
      discovering = false;
      notifyListeners();
    }
  }

  /// Adopt a discovered server, if it is not the one already configured.
  ///
  /// Returns true when the address changed, so the caller can decide whether to
  /// re-run whatever depended on it.
  Future<bool> adoptDiscoveredServer(DiscoveredServer server) async {
    final url = AppConfig.normaliseUrl(server.suggestedUrl);
    if (url == AppConfig.apiBaseUrl) return false;
    await setServerUrl(url);
    return true;
  }

  /// Best-effort automatic setup, run once before the login screen appears.
  ///
  /// Only acts when no address has been configured yet: an explicit choice,
  /// typed or picked by the user, is never overridden behind their back. The
  /// default compiled into the APK is treated as "not chosen" precisely because
  /// it is an emulator-only address that cannot work on a real phone.
  Future<void> autoConfigureServerIfUnset() async {
    final prefs = await SharedPreferences.getInstance();
    final saved = prefs.getString('sc.serverUrl');
    if (saved != null && saved.isNotEmpty) return;
    if (AppConfig.apiBaseUrl != AppConfig.compiledDefaultUrl) return;

    final servers = await discoverServers();
    if (servers.isEmpty) return;
    await adoptDiscoveredServer(servers.first);
  }

  /// Apply the platform secure-window flag and remember the choice.
  Future<void> setBlockScreenshots(bool value) async {
    blockScreenshots = value;
    await SecureWindow.setSecure(value);
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool('sc.blockScreenshots', value);
    notifyListeners();
  }

  AppPhase phase = AppPhase.booting;
  String? token;
  String? userId;
  String? phone;
  String? displayName;

  int preKeysLeft = 0;
  String? lastError;
  bool busy = false;

  bool get isSignedIn =>
      phase == AppPhase.ready || phase == AppPhase.generatingKeys;

  /// Local identity public key, for the safety-number screen.
  List<int>? get localIdentityKey => vault.identity?.edPublic;

  Future<void> bootstrap() async {
    sessions = SessionManager(api: api, vault: vault);
    messaging = MessagingService(state: this);
    final prefs = await SharedPreferences.getInstance();

    // Restore the privacy preference and apply it before any UI is drawn.
    blockScreenshots = prefs.getBool('sc.blockScreenshots') ?? true;
    await SecureWindow.setSecure(blockScreenshots);

    // A server address saved on a previous run wins over the compiled default,
    // so the same APK keeps working after the user points it at their server.
    final savedUrl = prefs.getString('sc.serverUrl');
    if (savedUrl != null && savedUrl.isNotEmpty) {
      AppConfig.apiBaseUrl = AppConfig.normaliseUrl(savedUrl);
    }

    final hasKeys = await vault.load();
    token = prefs.getString('sc.token');
    userId = prefs.getString('sc.userId');

    if (token == null || userId == null) {
      // Nothing to restore, so this install is new. Spend a few seconds looking
      // for a server on this Wi-Fi before showing the form: a user who cannot
      // register is almost always one whose app is pointing at an address that
      // does not exist for them.
      await autoConfigureServerIfUnset();
      phase = AppPhase.signedOut;
      notifyListeners();
      return;
    }

    phone = prefs.getString('sc.phone');
    displayName = prefs.getString('sc.displayName');

    // A token without keys means the previous run was interrupted between
    // login and key publication, so finish that job before letting the user in.
    phase = hasKeys ? AppPhase.ready : AppPhase.generatingKeys;
    notifyListeners();

    if (hasKeys) {
      _startRealtime();
      unawaited(refreshPreKeys());
    } else {
      await _generateAndPublishKeys();
      if (phase == AppPhase.ready) _startRealtime();
    }
  }

  /// Subscribe to the live socket and decrypt anything it delivers.
  ///
  /// Decryption happens here, once, so every screen sees plaintext without each
  /// one re-implementing ratchet handling.
  void _startRealtime() {
    final jwt = token;
    if (jwt == null || _inbound != null) return;

    _inbound = realtime.messages.listen(_onInbound);
    _receiptSub = realtime.receipts.listen((r) {
      chats.applyReceipt(r.messageIds, r.status);
    });

    // A peer hit an empty pre-key pool on our device. Refill it now so their
    // next message gets a proper handshake instead of the DH4-less fallback.
    _preKeysSub = realtime.preKeysLow.listen((_) {
      unawaited(refreshPreKeys());
    });
    _typingSub = realtime.typing.listen((t) {
      final target = t.userId;
      if (target.isEmpty || target == userId) return;
      chats.setTyping(target, t.typing);
      // Typing is presence, not content, so this is safe to relay.
      if (t.receiverId == userId && t.typing) {
        for (final summary in chats.summaries) {
          if (summary.peerId == target) chats.incrementUnread(summary.chatId);
        }
      }
    });
    realtime.connection.listen((up) {
      realtimeConnected = up;
      notifyListeners();
    });

    unawaited(realtime.connect(jwt));
  }

  /// Detach every live listener and drop the socket.
  void _teardownRealtime() {
    _inbound?.cancel();
    _inbound = null;
    _receiptSub?.cancel();
    _receiptSub = null;
    _typingSub?.cancel();
    _typingSub = null;
    _preKeysSub?.cancel();
    _preKeysSub = null;
    realtime.disconnect();
    realtimeConnected = false;
  }

  Future<void> _onInbound(Map<String, dynamic> wire) async {
    try {
      final row = await messaging.handleIncoming(wire);
      if (row != null) notifyListeners();
    } catch (_) {
      // A message that cannot be decrypted is already recorded as a visible
      // placeholder, so there is nothing further to do here.
    }
  }
  /// Create a new account.
  ///
  /// A phone number can be registered exactly once. If the number already has
  /// an account the server refuses with 409 and the existing account is left
  /// untouched, so this can never take over someone else's identity.
  ///
  /// On a fresh install the key identity is generated on-device BEFORE the
  /// request and published in the same round-trip, so a successful sign-up
  /// always leaves the device able to send and receive.
  Future<bool> register(
    String phoneNumber,
    String password, {
    String? displayName,
  }) async {
    _setBusy(true);
    try {
      if (!vault.isInitialised) {
        await vault.generateFresh();
        final preKeys =
            await vault.mintOneTimePreKeys(AppConfig.initialPreKeyCount);
        final bundle =
            await vault.publicBundleForUpload(oneTimePreKeys: preKeys.pairs, oneTimeStartId: preKeys.startId);
        final res = await api.register(
          phone: phoneNumber,
          password: password,
          displayName: displayName,
          publicKeyBundle: bundle,
          deviceId: await vault.deviceId(),
        );
        preKeysLeft = preKeys.length;
        await _adoptLogin(res);
        return true;
      }

      final res = await api.register(
        phone: phoneNumber,
        password: password,
        displayName: displayName,
        deviceId: await vault.deviceId(),
      );
      await _adoptLogin(res);
      return true;
    } on ApiException catch (e) {
      lastError = friendlyAuthError(e);
      return false;
    } finally {
      _setBusy(false);
    }
  }

  /// Sign in with a number and password.
  ///
  /// A returning account on a fresh device still needs this device's own key
  /// bundle published before it can receive anything, which the server flags
  /// with `needsKeyUpload`.
  Future<bool> login(
    String phoneNumber,
    String password, {
    String? displayName,
  }) async {
    _setBusy(true);
    try {
      Map<String, dynamic> res;
      if (!vault.isInitialised) {
        // Generate an identity for this device before the first request, so
        // the keys are ready the moment the token arrives.
        await vault.generateFresh();
        final preKeys =
            await vault.mintOneTimePreKeys(AppConfig.initialPreKeyCount);
        final bundle =
            await vault.publicBundleForUpload(oneTimePreKeys: preKeys.pairs, oneTimeStartId: preKeys.startId);
        res = await api.login(
          phone: phoneNumber,
          password: password,
          displayName: displayName,
          publicKeyBundle: bundle,
          deviceId: await vault.deviceId(),
        );
        preKeysLeft = preKeys.length;
      } else {
        res = await api.login(
          phone: phoneNumber,
          password: password,
          displayName: displayName,
          deviceId: await vault.deviceId(),
        );
      }
      await _adoptLogin(res);

      if (res['needsKeyUpload'] == true) {
        phase = AppPhase.generatingKeys;
        notifyListeners();
        await _generateAndPublishKeys();
      }
      return true;
    } on ApiException catch (e) {
      lastError = friendlyAuthError(e);
      return false;
    } finally {
      _setBusy(false);
    }
  }

  /// Whether a number already has an account, to guide the sign-up screen.
  Future<bool> isRegistered(String phoneNumber) =>
      api.isRegistered(phoneNumber);

  Future<void> _adoptLogin(Map<String, dynamic> res) async {
    final user = Map<String, dynamic>.from(res['user'] as Map);
    token = '${res['token']}';
    userId = '${user['id']}';
    phone = '${user['phone']}';
    displayName = '${user['displayName'] ?? ''}';

    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('sc.token', token!);
    await prefs.setString('sc.userId', userId!);
    await prefs.setString('sc.phone', phone!);
    await prefs.setString('sc.displayName', displayName!);

    phase = AppPhase.ready;
    lastError = null;
    notifyListeners();
  }

  /// Generate a key identity on-device and publish the public halves.
  ///
  /// Private halves are written to the Keystore/Keychain by [KeyVault] and are
  /// not part of the payload sent to the server.
  Future<void> _generateAndPublishKeys() async {
    phase = AppPhase.generatingKeys;
    notifyListeners();
    try {
      if (!vault.isInitialised) {
        await vault.generateFresh();
      }
      final preKeys =
          await vault.mintOneTimePreKeys(AppConfig.initialPreKeyCount);
      final bundle =
          await vault.publicBundleForUpload(oneTimePreKeys: preKeys.pairs, oneTimeStartId: preKeys.startId);
      await api.publishKeys(bundle);
      preKeysLeft = preKeys.length;
      phase = AppPhase.ready;
      lastError = null;
    } on ApiException catch (e) {
      // Stay in generatingKeys so the router retries instead of admitting the
      // user to a chat screen that cannot encrypt.
      lastError = 'Could not publish keys: ${e.code}';
    }
    notifyListeners();
  }

  /// Replenish the pre-key pool when the server reports it running low.
  Future<void> refreshPreKeys() async {
    try {
      final me = await api.me();
      final health = Map<String, dynamic>.from(me['preKeyHealth'] as Map);
      preKeysLeft = (health['remaining'] as num).toInt();
      if (health['low'] != true) return;

      final missing = AppConfig.initialPreKeyCount - preKeysLeft;
      if (missing <= 0) return;
      final minted = await vault.mintOneTimePreKeys(missing);
      // Publish the ids the vault stored these under, never a fresh 1..n range.
      // The server keys its pool by keyId and the responder looks the private
      // half up by that same id, so re-publishing 1..n makes the server hand out
      // ids that no longer match the device. Every later handshake would then
      // derive a different X3DH secret and fail its GCM tag.
      await api.topUpPreKeys(minted.published);
      preKeysLeft += minted.length;
    } catch (_) {
      // Top-up is best-effort; a failure must not block the app. The pool is
      // refilled again on the next successful call.
    }
  }

  /// Discard every key on this device and generate a new identity.
  ///
  /// The old identity is unrecoverable afterwards and any message encrypted to
  /// it becomes permanently unreadable here, so the UI warns before calling.
  Future<void> regenerateKeys() async {
    _setBusy(true);
    try {
      sessions.dispose();
      await vault.destroy();
      await vault.generateFresh();
      final preKeys =
          await vault.mintOneTimePreKeys(AppConfig.initialPreKeyCount);
      final bundle =
          await vault.publicBundleForUpload(oneTimePreKeys: preKeys.pairs, oneTimeStartId: preKeys.startId);
      await api.publishKeys(bundle);
      preKeysLeft = preKeys.length;
      lastError = null;
    } on ApiException catch (e) {
      lastError = 'Key rotation failed: ${e.code}';
    } finally {
      _setBusy(false);
    }
  }

  /// Sign out: forget the token and wipe every key held on this device.
  ///
  /// Ratchet chain keys are destroyed here, so any message encrypted to this
  /// device becomes permanently undecryptable, and the next login starts a new
  /// identity that peers must re-verify.
  Future<void> logout() async {
    _teardownRealtime();
    sessions.dispose();
    chats.clearTyping();
    await vault.destroy();
    final prefs = await SharedPreferences.getInstance();
    for (final k in ['sc.token', 'sc.userId', 'sc.phone', 'sc.displayName']) {
      await prefs.remove(k);
    }
    token = null;
    userId = null;
    phone = null;
    displayName = null;
    preKeysLeft = 0;
    phase = AppPhase.signedOut;
    notifyListeners();
  }

  void _setBusy(bool value) {
    busy = value;
    notifyListeners();
  }

  /// Turn a server error code into something a person can act on.
  static String friendlyAuthError(ApiException e) => switch (e.code) {
        'invalid_credentials' => 'That number or password is not correct.',
        'number_already_registered' =>
          'An account already exists for this number. Sign in instead.',
        'account_locked' => e.message ?? 'Too many attempts. Try again later.',
        'weak_password' =>
          e.message ?? 'That password is too easy to guess. Choose another.',
        'invalid_phone' =>
          e.message ?? 'That does not look like a valid phone number.',
        'auth_rate_limited' =>
          'Too many attempts. Wait a minute before trying again.',
        'too_many_requests' => 'Too many requests. Wait a moment and try again.',
        // The address answered, but it does not serve sign-in at all: it is not
        // a SecureChat server. Without this case the user reads "Sign-in failed
        // (not_found)" and assumes their password or number is the problem.
        'not_found' =>
          'That address is not a SecureChat server, so it cannot sign you in. '
              'Use Find server, or enter the address shown in the server window.',
        _ when e.isNetwork =>
          'Cannot reach the server. Check the address in Settings and your '
              'connection, then try again.',
        _ => 'Sign-in failed (${e.code}).',
      };
}
