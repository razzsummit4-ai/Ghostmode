import 'dart:typed_data';

import 'package:securechat/crypto/keys.dart';
import 'package:securechat/crypto/x3dh.dart';

/// A test device: an identity plus the pre-keys it would publish to the server.
class TestDevice {
  TestDevice(this.identity, this.signedPreKey, this.oneTimePreKeys);

  final IdentityKeyPair identity;
  final DhKeyPair signedPreKey;
  final List<DhKeyPair> oneTimePreKeys;
  final int registrationId = 1;

  late Uint8List _signedPreKeySignature;

  /// The public bundle exactly as it would be uploaded to the server.
  PreKeyBundle bundle(String userId) => PreKeyBundle(
    userId: userId,
    registrationId: registrationId,
    identityKey: identity.edPublic,
    signedPreKeyId: 1,
    signedPreKey: signedPreKey.publicKey,
    signedPreKeySignature: _signedPreKeySignature,
    oneTimePreKeyId: 1,
    oneTimePreKey: oneTimePreKeys.first.publicKey,
  );
}

/// Build a device whose signed pre-key is signed by its own identity key.
Future<TestDevice> makeDevice() async {
  final identity = await IdentityKeyPair.generate();
  final signedPreKey = await DhKeyPair.generate();
  final oneTimePreKeys = [await DhKeyPair.generate(), await DhKeyPair.generate()];

  final device = TestDevice(identity, signedPreKey, oneTimePreKeys);
  device._signedPreKeySignature =
      Uint8List.fromList((await identity.sign(signedPreKey.publicKey)).bytes);
  return device;
}
