import {
  createChannelIngressPluginId,
  createChannelIngressStringAdapter,
  createChannelIngressSubject,
  decideChannelIngress,
  findChannelIngressCommandGate,
  findChannelIngressSenderGate,
  resolveChannelIngressState,
  type ChannelIngressDecision,
  type IngressReasonCode,
  type RouteGateFacts,
} from "openclaw/plugin-sdk/channel-ingress";
import {
  resolveAllowlistProviderRuntimeGroupPolicy,
  resolveDefaultGroupPolicy,
  type DmPolicy,
  type GroupPolicy,
  type OpenClawConfig,
} from "../runtime-api.js";
import type { ResolvedNextcloudTalkAccount } from "./accounts.js";
import {
  normalizeNextcloudTalkAllowEntry,
  normalizeNextcloudTalkAllowlist,
  resolveNextcloudTalkAllowlistMatch,
  resolveNextcloudTalkRoomMatch,
} from "./policy.js";
import type { CoreConfig, NextcloudTalkRoomConfig } from "./types.js";

type NextcloudTalkAccessDecision = "allow" | "block" | "pairing";
type NextcloudTalkRoomMatch = ReturnType<typeof resolveNextcloudTalkRoomMatch>;
type NextcloudTalkRoomGateReason =
  | "room_not_allowlisted"
  | "room_disabled"
  | "room_sender_not_allowlisted";

const NEXTCLOUD_TALK_CHANNEL_ID = createChannelIngressPluginId("nextcloud-talk");
const nextcloudTalkIngressAdapter = createChannelIngressStringAdapter({
  normalizeEntry: normalizeNextcloudTalkIngressEntry,
  normalizeSubject: normalizeNextcloudTalkIngressEntry,
  sensitivity: "pii",
  resolveEntryId: ({ index }) => `nextcloud-talk-entry-${index + 1}`,
});

function normalizeNextcloudTalkIngressEntry(value: string): string | null {
  const normalized = normalizeNextcloudTalkAllowEntry(value);
  return normalized || null;
}

function stringEntries(entries: Array<string | number> | undefined): string[] {
  return (entries ?? []).map((entry) => String(entry));
}

function resolveConfiguredGroupAllowFrom(
  accountConfig: ResolvedNextcloudTalkAccount["config"],
): string[] {
  return accountConfig.groupAllowFrom?.length
    ? stringEntries(accountConfig.groupAllowFrom)
    : stringEntries(accountConfig.allowFrom);
}

async function readNextcloudTalkPairingStore(params: {
  isGroup: boolean;
  dmPolicy: DmPolicy;
  readAllowFromStore: () => Promise<string[]>;
}): Promise<string[]> {
  if (params.isGroup || params.dmPolicy === "allowlist" || params.dmPolicy === "open") {
    return [];
  }
  const entries = await params.readAllowFromStore().catch(() => []);
  return Array.isArray(entries) ? entries : [];
}

function hasEntries(entries: string[]): boolean {
  return normalizeNextcloudTalkAllowlist(entries).length > 0;
}

function roomSenderRouteFact(params: {
  senderId: string;
  outerGroupAllowFrom: string[];
  roomAllowFrom: string[];
}): RouteGateFacts | null {
  if (!hasEntries(params.outerGroupAllowFrom) || !hasEntries(params.roomAllowFrom)) {
    return null;
  }
  const match = resolveNextcloudTalkAllowlistMatch({
    allowFrom: params.roomAllowFrom,
    senderId: params.senderId,
  });
  return {
    id: "nextcloud-talk:room-sender",
    kind: "nestedAllowlist",
    gate: match.allowed ? "matched" : "not-matched",
    effect: match.allowed ? "allow" : "block-dispatch",
    precedence: 20,
    senderPolicy: "inherit",
    match: {
      matched: match.allowed,
      matchedEntryIds: match.allowed ? ["nextcloud-talk-room-sender"] : [],
    },
  };
}

function roomRouteFacts(params: {
  isGroup: boolean;
  groupPolicy: GroupPolicy;
  roomMatch: NextcloudTalkRoomMatch;
  roomConfig?: NextcloudTalkRoomConfig;
  senderId: string;
  outerGroupAllowFrom: string[];
  roomAllowFrom: string[];
}): RouteGateFacts[] {
  if (!params.isGroup) {
    return [];
  }
  const facts: RouteGateFacts[] = [];
  if (params.roomMatch.allowlistConfigured) {
    facts.push({
      id: "nextcloud-talk:room",
      kind: "route",
      gate: params.roomMatch.allowed ? "matched" : "not-matched",
      effect: params.roomMatch.allowed ? "allow" : "block-dispatch",
      precedence: 0,
      senderPolicy: "inherit",
      match: {
        matched: params.roomMatch.allowed,
        matchedEntryIds: params.roomMatch.allowed ? ["nextcloud-talk-room"] : [],
      },
    });
  }
  if (params.roomConfig?.enabled === false) {
    facts.push({
      id: "nextcloud-talk:room-enabled",
      kind: "route",
      gate: "disabled",
      effect: "block-dispatch",
      precedence: 10,
      senderPolicy: "inherit",
    });
  }
  if (params.groupPolicy === "allowlist") {
    const roomSender = roomSenderRouteFact({
      senderId: params.senderId,
      outerGroupAllowFrom: params.outerGroupAllowFrom,
      roomAllowFrom: params.roomAllowFrom,
    });
    if (roomSender) {
      facts.push(roomSender);
    }
  }
  return facts;
}

function resolveSenderGroupAllowFrom(params: {
  groupPolicy: GroupPolicy;
  outerGroupAllowFrom: string[];
  roomAllowFrom: string[];
}): string[] {
  if (
    params.groupPolicy === "allowlist" &&
    !hasEntries(params.outerGroupAllowFrom) &&
    hasEntries(params.roomAllowFrom)
  ) {
    return params.roomAllowFrom;
  }
  return params.outerGroupAllowFrom;
}

function findSenderGateReason(
  decision: ChannelIngressDecision,
  isGroup: boolean,
): IngressReasonCode {
  return findChannelIngressSenderGate(decision, { isGroup })?.reasonCode ?? decision.reasonCode;
}

function accessDecisionFromIngress(decision: ChannelIngressDecision): NextcloudTalkAccessDecision {
  if (decision.decision === "allow") {
    return "allow";
  }
  return decision.admission === "pairing-required" ? "pairing" : "block";
}

function commandAuthorizedFromIngress(decision: ChannelIngressDecision): boolean {
  return findChannelIngressCommandGate(decision)?.allowed === true;
}

function reasonFromIngress(reasonCode: IngressReasonCode): string {
  switch (reasonCode) {
    case "dm_policy_pairing_required":
      return "dmPolicy=pairing (not allowlisted)";
    case "dm_policy_disabled":
      return "dmPolicy=disabled";
    case "dm_policy_allowlisted":
      return "dmPolicy=allowlisted";
    case "group_policy_disabled":
      return "groupPolicy=disabled";
    case "group_policy_empty_allowlist":
      return "groupPolicy=allowlist (empty allowlist)";
    case "group_policy_allowed":
    case "group_policy_open":
      return "groupPolicy=allowed";
    case "route_blocked":
      return "route blocked";
    default:
      return "not allowlisted";
  }
}

function roomGateReason(params: {
  decision: ChannelIngressDecision;
  roomMatch: NextcloudTalkRoomMatch;
  roomConfig?: NextcloudTalkRoomConfig;
}): NextcloudTalkRoomGateReason | undefined {
  const decisiveId = params.decision.decisiveGateId;
  if (decisiveId === "nextcloud-talk:room" && !params.roomMatch.allowed) {
    return "room_not_allowlisted";
  }
  if (decisiveId === "nextcloud-talk:room-enabled" && params.roomConfig?.enabled === false) {
    return "room_disabled";
  }
  if (decisiveId === "nextcloud-talk:room-sender") {
    return "room_sender_not_allowlisted";
  }
  return undefined;
}

export async function resolveNextcloudTalkIngressAccess(params: {
  config: CoreConfig;
  account: ResolvedNextcloudTalkAccount;
  isGroup: boolean;
  roomToken: string;
  senderId: string;
  roomMatch: NextcloudTalkRoomMatch;
  allowTextCommands: boolean;
  hasControlCommand: boolean;
  readAllowFromStore: () => Promise<string[]>;
}): Promise<{
  ingress: ChannelIngressDecision;
  decision: NextcloudTalkAccessDecision;
  reason: string;
  reasonCode: IngressReasonCode;
  commandAuthorized: boolean;
  shouldBlockControlCommand: boolean;
  groupPolicy: GroupPolicy;
  providerMissingFallbackApplied: boolean;
  roomGateReason?: NextcloudTalkRoomGateReason;
}> {
  const dmPolicy = params.account.config.dmPolicy ?? "pairing";
  const allowFrom = stringEntries(params.account.config.allowFrom);
  const storeAllowFrom = await readNextcloudTalkPairingStore({
    isGroup: params.isGroup,
    dmPolicy,
    readAllowFromStore: params.readAllowFromStore,
  });
  const { groupPolicy, providerMissingFallbackApplied } =
    resolveAllowlistProviderRuntimeGroupPolicy({
      providerConfigPresent:
        ((params.config.channels as Record<string, unknown> | undefined)?.["nextcloud-talk"] ??
          undefined) !== undefined,
      groupPolicy: params.account.config.groupPolicy,
      defaultGroupPolicy: resolveDefaultGroupPolicy(params.config as OpenClawConfig),
    });
  const outerGroupAllowFrom = resolveConfiguredGroupAllowFrom(params.account.config);
  const roomConfig = params.roomMatch.roomConfig;
  const roomAllowFrom = stringEntries(roomConfig?.allowFrom);
  const senderGroupAllowFrom = resolveSenderGroupAllowFrom({
    groupPolicy,
    outerGroupAllowFrom,
    roomAllowFrom,
  });
  const state = await resolveChannelIngressState({
    channelId: NEXTCLOUD_TALK_CHANNEL_ID,
    accountId: params.account.accountId,
    subject: createChannelIngressSubject({
      opaqueId: "nextcloud-talk-user-id",
      value: params.senderId,
      sensitivity: "pii",
    }),
    conversation: {
      kind: params.isGroup ? "group" : "direct",
      id: params.isGroup ? params.roomToken : params.senderId,
    },
    adapter: nextcloudTalkIngressAdapter,
    accessGroups: (params.config as OpenClawConfig).accessGroups,
    routeFacts: roomRouteFacts({
      isGroup: params.isGroup,
      groupPolicy,
      roomMatch: params.roomMatch,
      roomConfig,
      senderId: params.senderId,
      outerGroupAllowFrom,
      roomAllowFrom,
    }),
    event: {
      kind: "message",
      authMode: "inbound",
      mayPair: !params.isGroup,
    },
    allowlists: {
      dm: allowFrom,
      group: senderGroupAllowFrom,
      pairingStore: storeAllowFrom,
      commandOwner: params.isGroup ? allowFrom : [...allowFrom, ...storeAllowFrom],
      commandGroup: params.isGroup ? outerGroupAllowFrom : [],
    },
  });
  const ingress = decideChannelIngress(state, {
    dmPolicy,
    groupPolicy,
    groupAllowFromFallbackToAllowFrom: false,
    command: {
      useAccessGroups:
        (params.config.commands as Record<string, unknown> | undefined)?.useAccessGroups !== false,
      allowTextCommands: false,
      hasControlCommand: params.hasControlCommand,
      modeWhenAccessGroupsOff: "allow",
    },
  });
  const reasonCode = findSenderGateReason(ingress, params.isGroup);
  const commandAuthorized = commandAuthorizedFromIngress(ingress);
  return {
    ingress,
    decision: accessDecisionFromIngress(ingress),
    reason: reasonFromIngress(
      ingress.reasonCode === "route_blocked" ? "route_blocked" : reasonCode,
    ),
    reasonCode,
    commandAuthorized,
    shouldBlockControlCommand:
      params.isGroup && params.allowTextCommands && params.hasControlCommand && !commandAuthorized,
    groupPolicy,
    providerMissingFallbackApplied,
    roomGateReason: roomGateReason({
      decision: ingress,
      roomMatch: params.roomMatch,
      roomConfig,
    }),
  };
}
