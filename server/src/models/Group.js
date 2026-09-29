import mongoose from 'mongoose';

const { Schema } = mongoose;

const memberSchema = new Schema(
  {
    userId: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    role: { type: String, enum: ['owner', 'admin', 'member'], default: 'member' },
    joinedAt: { type: Date, default: Date.now },
  },
  { _id: false },
);

/**
 * A group conversation.
 *
 * The group carries NO group key. Each member generates its own Sender Key
 * chain and distributes it to the other members over the existing pairwise
 * encrypted sessions, so the server never sees any group secret.
 */
const groupSchema = new Schema(
  {
    name: { type: String, trim: true, maxlength: 80, default: '' },
    avatarColor: { type: Number, default: 0 },
    createdBy: { type: Schema.Types.ObjectId, ref: 'User', required: true },
    members: { type: [memberSchema], default: [] },
    /** Per-chat disappearing message default, in seconds (0 = off). */
    disappearingMessagesSeconds: { type: Number, default: 0, min: 0 },
  },
  { timestamps: true, strict: 'throw' },
);

groupSchema.index({ 'members.userId': 1 });

export const Group = mongoose.model('Group', groupSchema);
