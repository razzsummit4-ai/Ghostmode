import mongoose from 'mongoose';
import { assertNoPlaintext } from '../lib/zero-knowledge.js';

const { Schema } = mongoose;

/** Ratchet header. Authenticated as AES-GCM additional data by the client. */
const headerSchema = new Schema(
  {
    type: { type: String, enum: ['prekey', 'msg', 'groupkey', 'group'], required: true },
    // PreKeySignalMessage
    preKeyId: { type: Number, default: null },
    signedPreKeyId: { type: Number, default: null },
    baseKey: { type: String, default: null }, // sender's ephemeral X25519 public key
    // SignalMessage (double ratchet)
    ratchetKey: { type: String, default: null },
    counter: { type: Number, default: null },
    previousCounter: { type: Number, default: null },
    // Sender-key (groups)
    senderKeyId: { type: String, default: null },
    senderChainId: { type: Number, default: null },
    senderIteration: { type: Number, default: null },
  },
  { _id: false },
);

/**
 * A single encrypted message.
 *
 * The schema is the enforcement point for the project's core rule: there is no
 * `text`, `body`, `content` or `plaintext` field, and `strict: 'throw'` makes
 * Mongoose itself reject an attempt to assign one.
 */
const messageSchema = new Schema(
  {
    /** Stable client-generated id (uuid) so senders can reconcile their outbox. */
    clientMessageId: { type: String, required: true },

    chatId: { type: String, required: true, index: true },
    conversationType: { type: String, enum: ['direct', 'group', 'mesh'], required: true },

    senderId: { type: Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    /** Single receiver for `direct`; null for `group`/`mesh`. */
    receiverId: { type: Schema.Types.ObjectId, ref: 'User', default: null, index: true },
    groupId: { type: Schema.Types.ObjectId, ref: 'Group', default: null, index: true },

    ciphertext: { type: String, required: true },
    iv: { type: String, required: true },
    mac: { type: String, default: '' },
    header: { type: headerSchema, required: true },

    /**
     * Coarse envelope metadata so the client can route/render without
     * decrypting. Deliberately non-semantic - never message content.
     */
    envelope: {
      type: { type: String, enum: ['text', 'media', 'key', 'system'], default: 'text' },
      attachmentCount: { type: Number, default: 0 },
      // Disappearing-messages lifetime in seconds, or 0 = off.
      expiresInSeconds: { type: Number, default: 0 },
    },

    // Delivery lifecycle.
    status: { type: String, enum: ['sent', 'delivered', 'read'], default: 'sent' },
    deliveredAt: { type: Date, default: null },
    readAt: { type: Date, default: null },
    /** Per-receiver read receipts for group chats. */
    receipts: [
      {
        _id: false,
        userId: { type: Schema.Types.ObjectId, ref: 'User' },
        deliveredAt: Date,
        readAt: Date,
      },
    ],

    /** MongoDB TTL index support for disappearing messages (backstop only). */
    expiresAt: { type: Date, default: null },

    replyToClientMessageId: { type: String, default: null },
  },
  { timestamps: true, strict: 'throw' },
);

// Chat timeline paging and dedupe.
messageSchema.index({ chatId: 1, createdAt: -1 });
messageSchema.index({ senderId: 1, clientMessageId: 1 }, { unique: true });
messageSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

messageSchema.pre('validate', function guard(next) {
  try {
    assertNoPlaintext(this.toObject({ depopulate: true }));
    next();
  } catch (err) {
    next(err);
  }
});

export const Message = mongoose.model('Message', messageSchema);
