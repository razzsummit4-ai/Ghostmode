import mongoose from 'mongoose';
import { assertNoPlaintext } from '../lib/zero-knowledge.js';

const { Schema } = mongoose;

/** One-time pre-key that has been consumed. Public half only, by definition. */
const consumedPreKeySchema = new Schema(
  {
    keyId: { type: Number, required: true },
    publicKey: { type: String, required: true }, // base64 X25519
    consumedAt: { type: Date, required: true },
    consumedBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
  },
  { _id: false },
);

/**
 * A public one-time pre-key awaiting use.
 * There is intentionally NO field for a private key here or anywhere else.
 */
const oneTimePreKeySchema = new Schema(
  {
    keyId: { type: Number, required: true },
    publicKey: { type: String, required: true }, // base64 X25519
    createdAt: { type: Date, default: Date.now },
  },
  { _id: false },
);

const userSchema = new Schema(
  {
    phone: {
      type: String,
      required: true,
      unique: true,
      index: true,
      match: /^\+[1-9]\d{7,14}$/,
    },
    displayName: { type: String, trim: true, maxlength: 64 },

    /**
     * Password credentials.
     *
     * `select: false` means these are omitted from every query unless a route
     * explicitly asks for them, so they cannot leak into a response by accident
     * through a `User.findById()` that someone forgot to trim.
     *
     * Only a scrypt hash and its salt are stored. The password itself exists
     * solely in the request that set it, and is never persisted or logged.
     * See lib/password.js for the parameters and the rationale.
     */
    passwordHash: { type: String, default: null, select: false },
    passwordSalt: { type: String, default: null, select: false },
    passwordUpdatedAt: { type: Date, default: null },

    /**
     * Brute-force protection.
     *
     * Lives on the document so it survives a server restart; otherwise a
     * restart would reset an attacker's attempt budget.
     */
    failedLogins: { type: Number, default: 0, select: false },
    lockedUntil: { type: Date, default: null, select: false },

    /**
     * Ed25519 identity public key (base64). The private half lives ONLY in the
     * device Keychain/Keystore and is never transmitted.
     *
     * `null` means this device has authenticated but not yet published a key
     * bundle - the state between OTP verification and the first key upload.
     */
    publicIdentityKey: { type: String, default: null },

    /**
     * X25519 signed pre-key: public half + Ed25519 signature over it.
     * Optional for the same reason as publicIdentityKey.
     */
    signedPreKey: {
      type: new Schema(
        {
          keyId: { type: Number, required: true },
          publicKey: { type: String, required: true },
          signature: { type: String, required: true },
          createdAt: { type: Date, default: Date.now },
        },
        { _id: false },
      ),
      default: undefined,
    },

    oneTimePreKeys: { type: [oneTimePreKeySchema], default: [] },
    consumedOneTimePreKeys: { type: [consumedPreKeySchema], default: [] },

    /** A per-device random id used as the Signal protocol address. */
    registrationId: { type: Number, required: true },

    /** Per-device state used to build the QR "add device" verification flow. */
    deviceName: { type: String, maxlength: 80, default: '' },
    deviceId: { type: String, maxlength: 64, default: '' },

    lastSeenAt: { type: Date, default: Date.now },
    avatarColor: { type: Number, default: 0 },

    /**
     * The code this account shares with people who want to talk to it.
     *
     * This is a gate, not a credential: it authorises a peer to open a
     * conversation, and is read out or sent over a channel the two of them
     * already trust. It is stored in the clear because the owner has to be able
     * to display it again in order to share it - the same reason a Wi-Fi
     * password is shown rather than hashed. It grants no access to this
     * account: it cannot read anything, and it is never used to sign anything.
     *
     * `null` means the owner has not created one yet, so nobody can open a
     * conversation with them.
     */
    verificationCode: { type: String, default: null, select: false },

    /**
     * Peers whose code this account has verified.
     *
     * One-directional by design: A verifying B's code says nothing about
     * whether B may talk to A. Each side grants independently, so a user who
     * has not handed over their code is not reachable either.
     */
    verifiedPeers: { type: [Schema.Types.ObjectId], ref: 'User', default: [] },
  },
  { timestamps: true, strict: 'throw' },
);

// Any unconsumed pre-keys, most useful first.
userSchema.index({ 'oneTimePreKeys.keyId': 1 });

userSchema.pre('validate', function guard(next) {
  try {
    assertNoPlaintext(this.toObject({ depopulate: true }));
    next();
  } catch (err) {
    next(err);
  }
});

export const User = mongoose.model('User', userSchema);
