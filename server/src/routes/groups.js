import { Router } from 'express';
import { z } from 'zod';
import { Group } from '../models/Group.js';
import { User } from '../models/User.js';
import { requireAuth } from '../middleware/auth.js';
import { asyncRoute, HttpError } from '../middleware/error.js';
import { zeroKnowledgeGuard } from '../middleware/zeroKnowledge.js';
import { logger } from '../logger.js';

const router = Router();

const createSchema = z.object({
  name: z.string().trim().min(1).max(80),
  memberIds: z.array(z.string().regex(/^[a-f\d]{24}$/i)).max(256).default([]),
  disappearingMessagesSeconds: z.number().int().min(0).max(60 * 60 * 24 * 30).default(0),
});

/**
 * POST /api/groups
 *
 * Creates the membership roster only. No group key is created or stored here:
 * each member generates its own Sender Key chain and distributes it over the
 * existing pairwise encrypted sessions, so the server never holds a group key.
 */
router.post(
  '/',
  requireAuth,
  zeroKnowledgeGuard(),
  asyncRoute(async (req, res) => {
    const body = createSchema.parse(req.body);
    const memberIds = [...new Set([String(req.user._id), ...body.memberIds])];
    const found = await User.countDocuments({ _id: { $in: memberIds } });
    if (found !== memberIds.length) {
      throw new HttpError(400, 'unknown_member', 'One or more member ids do not exist.');
    }

    const group = await Group.create({
      name: body.name,
      createdBy: req.user._id,
      members: memberIds.map((id, i) => ({
        userId: id,
        role: i === 0 ? 'owner' : 'member',
      })),
      disappearingMessagesSeconds: body.disappearingMessagesSeconds,
      avatarColor: Math.floor(Math.random() * 12),
    });

    logger.info('group.created', { groupId: String(group._id), size: memberIds.length });
    res.status(201).json({ group: serialiseGroup(group) });
  }),
);

/** GET /api/groups - groups I belong to. */
router.get(
  '/',
  requireAuth,
  asyncRoute(async (req, res) => {
    const groups = await Group.find({ 'members.userId': req.user._id }).sort({ updatedAt: -1 });
    res.json({ groups: groups.map(serialiseGroup) });
  }),
);

/** GET /api/groups/:id */
router.get(
  '/:id',
  requireAuth,
  asyncRoute(async (req, res) => {
    res.json({ group: serialiseGroup(await requireMembership(req.params.id, req.user)) });
  }),
);

/** PATCH /api/groups/:id - rename / set disappearing timer / colour. */
router.patch(
  '/:id',
  requireAuth,
  zeroKnowledgeGuard(),
  asyncRoute(async (req, res) => {
    const group = await requireMembership(req.params.id, req.user);
    const patch = z
      .object({
        name: z.string().trim().min(1).max(80).optional(),
        disappearingMessagesSeconds: z.number().int().min(0).max(60 * 60 * 24 * 30).optional(),
        avatarColor: z.number().int().min(0).max(11).optional(),
      })
      .parse(req.body);
    // Disappearing-message policy is a security setting: admins only.
    if (patch.disappearingMessagesSeconds !== undefined && !isAdmin(group, req.user)) {
      throw new HttpError(403, 'admin_only', 'Only admins can change disappearing messages.');
    }
    Object.assign(group, patch);
    await group.save();
    res.json({ group: serialiseGroup(group) });
  }),
);


/** POST /api/groups/:id/members */
router.post(
  '/:id/members',
  requireAuth,
  zeroKnowledgeGuard(),
  asyncRoute(async (req, res) => {
    const group = await requireMembership(req.params.id, req.user);
    if (!isAdmin(group, req.user)) {
      throw new HttpError(403, 'admin_only', 'Only admins can add members.');
    }
    const { memberIds } = z
      .object({ memberIds: z.array(z.string().regex(/^[a-f\d]{24}$/i)).min(1).max(256) })
      .parse(req.body);

    const existing = new Set(group.members.map((m) => String(m.userId)));
    const toAdd = memberIds.filter((id) => !existing.has(id));
    if (toAdd.length) {
      group.members.push(...toAdd.map((id) => ({ userId: id, role: 'member' })));
      await group.save();
    }
    res.json({ group: serialiseGroup(group), added: toAdd.length });
  }),
);

/** DELETE /api/groups/:id/members/:userId - kick, or self-leave. */
router.delete(
  '/:id/members/:userId',
  requireAuth,
  asyncRoute(async (req, res) => {
    const group = await requireMembership(req.params.id, req.user);
    const isSelf = req.params.userId === String(req.user._id);
    if (!isSelf && !isAdmin(group, req.user)) {
      throw new HttpError(403, 'admin_only', 'Only admins can remove other members.');
    }
    const before = group.members.length;
    group.members = group.members.filter((m) => String(m.userId) !== req.params.userId);
    if (group.members.length !== before) await group.save();
    res.json({ group: serialiseGroup(group) });
  }),
);

/** DELETE /api/groups/:id - leave, or delete when last member. */
router.delete(
  '/:id',
  requireAuth,
  asyncRoute(async (req, res) => {
    const group = await requireMembership(req.params.id, req.user);
    if (group.members.length <= 1) {
      await Group.deleteOne({ _id: group._id });
      res.json({ deleted: true });
      return;
    }
    group.members = group.members.filter((m) => String(m.userId) !== String(req.user._id));
    await group.save();
    res.json({ group: serialiseGroup(group) });
  }),
);

export default router;

async function requireMembership(id, user) {
  if (!/^[a-f\d]{24}$/i.test(String(id))) {
    throw new HttpError(400, 'invalid_group_id', 'Malformed group id.');
  }
  const group = await Group.findById(id);
  if (!group) throw new HttpError(404, 'group_not_found', 'No such group.');
  if (!group.members.some((m) => String(m.userId) === String(user._id))) {
    throw new HttpError(403, 'not_a_member', 'You are not a member of this group.');
  }
  return group;
}

function isAdmin(group, user) {
  const me = group.members.find((m) => String(m.userId) === String(user._id));
  return Boolean(me && (me.role === 'owner' || me.role === 'admin'));
}

export function serialiseGroup(group) {
  return {
    id: String(group._id),
    name: group.name,
    avatarColor: group.avatarColor,
    createdBy: String(group.createdBy),
    disappearingMessagesSeconds: group.disappearingMessagesSeconds,
    members: group.members.map((m) => ({
      userId: String(m.userId),
      role: m.role,
      joinedAt: m.joinedAt,
    })),
    createdAt: group.createdAt,
    updatedAt: group.updatedAt,
  };
}