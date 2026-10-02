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
