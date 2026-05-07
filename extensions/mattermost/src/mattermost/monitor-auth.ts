import {
  createChannelIngressPluginId,
  createChannelIngressMultiIdentifierAdapter,
  decideChannelIngress,
  findChannelIngressCommandGate,
  resolveChannelIngressState,
  type ChannelIngressAdapterEntry,
  type ChannelIngressDecision,
  type ChannelIngressEventInput,
  type ChannelIngressIdentifierKind,
  type ChannelIngressPolicyInput,
  type ChannelIngressSubject,
} from "openclaw/plugin-sdk/channel-ingress";
import { parseAccessGroupAllowFromEntry } from "openclaw/plugin-sdk/command-auth";
import { normalizeLowercaseStringOrEmpty } from "openclaw/plugin-sdk/text-runtime";
import type { ResolvedMattermostAccount } from "./accounts.js";
import type { MattermostChannel } from "./client.js";
import type { OpenClawConfig } from "./runtime-api.js";
import {
  isDangerousNameMatchingEnabled,
  resolveAllowlistMatchSimple,
  resolveEffectiveAllowFromLists,
} from "./runtime-api.js";

const MATTERMOST_CHANNEL_ID = createChannelIngressPluginId("mattermost");
const MATTERMOST_USER_NAME_KIND =
  "plugin:mattermost-user-name" as const satisfies ChannelIngressIdentifierKind;

export function normalizeMattermostAllowEntry(entry: string): string {
  const trimmed = entry.trim();
  if (!trimmed) {
    return "";
  }
  if (trimmed === "*") {
    return "*";
  }
  const accessGroupName = parseAccessGroupAllowFromEntry(trimmed);
  if (accessGroupName) {
    return `accessGroup:${accessGroupName}`;
  }
  return trimmed
    .replace(/^(mattermost|user):/i, "")
    .replace(/^@/, "")
    .trim()
    ? normalizeLowercaseStringOrEmpty(trimmed.replace(/^(mattermost|user):/i, "").replace(/^@/, ""))
    : "";
}

export function normalizeMattermostAllowList(entries: Array<string | number>): string[] {
  const normalized = entries
    .map((entry) => normalizeMattermostAllowEntry(String(entry)))
    .filter(Boolean);
  return Array.from(new Set(normalized));
}

function createMattermostAdapterEntry(params: {
  index: number;
  kind: ChannelIngressIdentifierKind;
  value: string;
  suffix: string;
  dangerous?: boolean;
}): ChannelIngressAdapterEntry {
  return {
    opaqueEntryId: `entry-${params.index + 1}:${params.suffix}`,
    kind: params.kind,
    value: params.value,
    dangerous: params.dangerous,
  };
}

function normalizeMattermostIngressEntry(
  rawEntry: string,
  index: number,
): ChannelIngressAdapterEntry[] {
  const entry = normalizeMattermostAllowEntry(rawEntry);
  if (!entry) {
    return [];
  }
  if (entry === "*") {
    return [
      createMattermostAdapterEntry({
        index,
        kind: "stable-id",
        value: "*",
        suffix: "wildcard",
      }),
    ];
  }
  return [
    createMattermostAdapterEntry({
      index,
      kind: "stable-id",
      value: entry,
      suffix: "user",
    }),
    createMattermostAdapterEntry({
      index,
      kind: MATTERMOST_USER_NAME_KIND,
      value: entry,
      suffix: "name",
      dangerous: true,
    }),
  ];
}

const mattermostIngressAdapter = createChannelIngressMultiIdentifierAdapter({
  normalizeEntry: normalizeMattermostIngressEntry,
});

function createMattermostIngressSubject(params: {
  senderId: string;
  senderName?: string;
}): ChannelIngressSubject {
  const identifiers: ChannelIngressSubject["identifiers"] = [];
  const senderId = normalizeMattermostAllowEntry(params.senderId);
  if (senderId) {
    identifiers.push({
      opaqueId: "sender-id",
      kind: "stable-id",
      value: senderId,
    });
  }
  const senderName = params.senderName ? normalizeMattermostAllowEntry(params.senderName) : "";
  if (senderName) {
    identifiers.push({
      opaqueId: "sender-name",
      kind: MATTERMOST_USER_NAME_KIND,
      value: senderName,
      dangerous: true,
    });
  }
  return { identifiers };
}

export function resolveMattermostEffectiveAllowFromLists(params: {
  allowFrom?: Array<string | number> | null;
  groupAllowFrom?: Array<string | number> | null;
  storeAllowFrom?: Array<string | number> | null;
  dmPolicy?: string | null;
}): {
  effectiveAllowFrom: string[];
  effectiveGroupAllowFrom: string[];
} {
  return resolveEffectiveAllowFromLists({
    allowFrom: normalizeMattermostAllowList(params.allowFrom ?? []),
    groupAllowFrom: normalizeMattermostAllowList(params.groupAllowFrom ?? []),
    storeAllowFrom: normalizeMattermostAllowList(params.storeAllowFrom ?? []),
    dmPolicy: params.dmPolicy,
  });
}

export function isMattermostSenderAllowed(params: {
  senderId: string;
  senderName?: string;
  allowFrom: string[];
  allowNameMatching?: boolean;
}): boolean {
  const allowFrom = normalizeMattermostAllowList(params.allowFrom);
  if (allowFrom.length === 0) {
    return false;
  }
  const match = resolveAllowlistMatchSimple({
    allowFrom,
    senderId: normalizeMattermostAllowEntry(params.senderId),
    senderName: params.senderName ? normalizeMattermostAllowEntry(params.senderName) : undefined,
    allowNameMatching: params.allowNameMatching,
  });
  return match.allowed;
}

function mapMattermostChannelKind(channelType?: string | null): "direct" | "group" | "channel" {
  const normalized = channelType?.trim().toUpperCase();
  if (normalized === "D") {
    return "direct";
  }
  if (normalized === "G" || normalized === "P") {
    return "group";
  }
  return "channel";
}

export type MattermostCommandAuthDecision =
  | {
      ok: true;
      commandAuthorized: boolean;
      channelInfo: MattermostChannel;
      kind: "direct" | "group" | "channel";
      chatType: "direct" | "group" | "channel";
      channelName: string;
      channelDisplay: string;
      roomLabel: string;
    }
  | {
      ok: false;
      denyReason:
        | "unknown-channel"
        | "dm-disabled"
        | "dm-pairing"
        | "unauthorized"
        | "channels-disabled"
        | "channel-no-allowlist";
      commandAuthorized: false;
      channelInfo: MattermostChannel | null;
      kind: "direct" | "group" | "channel";
      chatType: "direct" | "group" | "channel";
      channelName: string;
      channelDisplay: string;
      roomLabel: string;
    };

type MattermostCommandDenyReason = Extract<
  MattermostCommandAuthDecision,
  { ok: false }
>["denyReason"];

type MattermostCommandIngressResult = {
  decision: ChannelIngressDecision;
  commandAuthorized: boolean;
  shouldBlockControlCommand: boolean;
};

function commandResultFromDecision(
  decision: ChannelIngressDecision,
): MattermostCommandIngressResult {
  const commandGate = findChannelIngressCommandGate(decision);
  return {
    decision,
    commandAuthorized: decision.decision === "allow" ? (commandGate?.allowed ?? true) : false,
    shouldBlockControlCommand: commandGate?.command?.shouldBlockControlCommand === true,
  };
}

export type MattermostMonitorInboundAccessDecision = MattermostCommandIngressResult & {
  reasonCode: ChannelIngressDecision["reasonCode"];
  reason: string;
  effectiveAllowFrom: string[];
  effectiveGroupAllowFrom: string[];
};

function formatMattermostIngressReason(params: {
  decision: ChannelIngressDecision;
  dmPolicy: "pairing" | "allowlist" | "open" | "disabled";
  groupPolicy: "allowlist" | "open" | "disabled";
}): string {
  switch (params.decision.reasonCode) {
    case "dm_policy_disabled":
      return "dmPolicy=disabled";
    case "dm_policy_open":
      return "dmPolicy=open";
    case "dm_policy_allowlisted":
      return `dmPolicy=${params.dmPolicy} (allowlisted)`;
    case "dm_policy_pairing_required":
    case "event_pairing_not_allowed":
      return "dmPolicy=pairing (not allowlisted)";
    case "dm_policy_not_allowlisted":
      return `dmPolicy=${params.dmPolicy} (not allowlisted)`;
    case "group_policy_allowed":
      return `groupPolicy=${params.groupPolicy}`;
    case "group_policy_disabled":
      return "groupPolicy=disabled";
    case "group_policy_empty_allowlist":
      return "groupPolicy=allowlist (empty allowlist)";
    case "group_policy_not_allowlisted":
      return "groupPolicy=allowlist (not allowlisted)";
    default:
      return params.decision.reasonCode;
  }
}

async function resolveMattermostIngress(params: {
  cfg: OpenClawConfig;
  accountId: string;
  senderId: string;
  senderName: string;
  channelId: string;
  kind: "direct" | "group" | "channel";
  dmPolicy: "pairing" | "allowlist" | "open" | "disabled";
  groupPolicy: "allowlist" | "open" | "disabled";
  allowNameMatching: boolean;
  useAccessGroups: boolean;
  configAllowFrom: string[];
  storeAllowFrom: string[];
  effectiveGroupAllowFrom: string[];
  commandDmAllowFrom: string[];
  commandGroupAllowFrom: string[];
  allowTextCommands: boolean;
  hasControlCommand: boolean;
  eventKind: ChannelIngressEventInput["kind"];
  mayPair: boolean;
}): Promise<MattermostCommandIngressResult> {
  const isDirect = params.kind === "direct";
  const state = await resolveChannelIngressState({
    channelId: MATTERMOST_CHANNEL_ID,
    accountId: params.accountId,
    subject: createMattermostIngressSubject({
      senderId: params.senderId,
      senderName: params.senderName,
    }),
    conversation: {
      kind: params.kind,
      id: params.channelId,
    },
    adapter: mattermostIngressAdapter,
    accessGroups: params.cfg.accessGroups,
    event: {
      kind: params.eventKind,
      authMode: "inbound",
      mayPair: params.mayPair,
    },
    allowlists: {
      dm: isDirect ? params.configAllowFrom : [],
      pairingStore: isDirect ? params.storeAllowFrom : [],
      group: isDirect ? [] : params.effectiveGroupAllowFrom,
      commandOwner: params.commandDmAllowFrom,
      commandGroup: params.commandGroupAllowFrom,
    },
  });
  const policy: ChannelIngressPolicyInput = {
    dmPolicy: params.dmPolicy,
    groupPolicy: params.groupPolicy,
    groupAllowFromFallbackToAllowFrom: false,
    mutableIdentifierMatching: params.allowNameMatching ? "enabled" : "disabled",
    command: {
      useAccessGroups: params.useAccessGroups,
      allowTextCommands: params.allowTextCommands,
      hasControlCommand: params.allowTextCommands && params.hasControlCommand,
    },
  };
  return commandResultFromDecision(decideChannelIngress(state, policy));
}

export async function resolveMattermostMonitorInboundAccess(params: {
  account: ResolvedMattermostAccount;
  cfg: OpenClawConfig;
  senderId: string;
  senderName: string;
  channelId: string;
  kind: "direct" | "group" | "channel";
  groupPolicy: "allowlist" | "open" | "disabled";
  storeAllowFrom?: Array<string | number> | null;
  allowTextCommands: boolean;
  hasControlCommand: boolean;
  eventKind?: ChannelIngressEventInput["kind"];
  mayPair?: boolean;
}): Promise<MattermostMonitorInboundAccessDecision> {
  const {
    account,
    cfg,
    senderId,
    senderName,
    channelId,
    kind,
    groupPolicy,
    storeAllowFrom,
    allowTextCommands,
    hasControlCommand,
  } = params;
  const dmPolicy = account.config.dmPolicy ?? "pairing";
  const allowNameMatching = isDangerousNameMatchingEnabled(account.config);
  const configAllowFrom = normalizeMattermostAllowList(account.config.allowFrom ?? []);
  const configGroupAllowFrom = normalizeMattermostAllowList(account.config.groupAllowFrom ?? []);
  const normalizedStoreAllowFrom = normalizeMattermostAllowList(storeAllowFrom ?? []);
  const { effectiveAllowFrom, effectiveGroupAllowFrom } = resolveMattermostEffectiveAllowFromLists({
    allowFrom: configAllowFrom,
    groupAllowFrom: configGroupAllowFrom,
    storeAllowFrom: normalizedStoreAllowFrom,
    dmPolicy,
  });
  const useAccessGroups = cfg.commands?.useAccessGroups !== false;
  const commandDmAllowFrom = kind === "direct" ? effectiveAllowFrom : configAllowFrom;
  const commandGroupAllowFrom =
    kind === "direct"
      ? effectiveGroupAllowFrom
      : configGroupAllowFrom.length > 0
        ? configGroupAllowFrom
        : configAllowFrom;
  const ingress = await resolveMattermostIngress({
    cfg,
    accountId: account.accountId,
    senderId,
    senderName,
    channelId,
    kind,
    dmPolicy,
    groupPolicy,
    allowNameMatching,
    useAccessGroups,
    configAllowFrom,
    storeAllowFrom: normalizedStoreAllowFrom,
    effectiveGroupAllowFrom,
    commandDmAllowFrom,
    commandGroupAllowFrom,
    allowTextCommands,
    hasControlCommand,
    eventKind: params.eventKind ?? "message",
    mayPair: params.mayPair ?? true,
  });
  return {
    ...ingress,
    reasonCode: ingress.decision.reasonCode,
    reason: formatMattermostIngressReason({
      decision: ingress.decision,
      dmPolicy,
      groupPolicy,
    }),
    effectiveAllowFrom,
    effectiveGroupAllowFrom,
  };
}

function resolveMattermostCommandDenyReason(params: {
  decision: ChannelIngressDecision;
  kind: "direct" | "group" | "channel";
  dmPolicy: string;
}): MattermostCommandDenyReason | null {
  if (params.decision.decision === "allow") {
    return null;
  }
  if (params.kind === "direct") {
    if (params.decision.reasonCode === "dm_policy_disabled") {
      return "dm-disabled";
    }
    if (
      params.dmPolicy === "pairing" &&
      (params.decision.admission === "pairing-required" ||
        params.decision.reasonCode === "dm_policy_pairing_required")
    ) {
      return "dm-pairing";
    }
    return "unauthorized";
  }
  if (params.decision.reasonCode === "group_policy_disabled") {
    return "channels-disabled";
  }
  if (params.decision.reasonCode === "group_policy_empty_allowlist") {
    return "channel-no-allowlist";
  }
  return "unauthorized";
}

export async function authorizeMattermostCommandInvocation(params: {
  account: ResolvedMattermostAccount;
  cfg: OpenClawConfig;
  senderId: string;
  senderName: string;
  channelId: string;
  channelInfo: MattermostChannel | null;
  storeAllowFrom?: Array<string | number> | null;
  allowTextCommands: boolean;
  hasControlCommand: boolean;
}): Promise<MattermostCommandAuthDecision> {
  const {
    account,
    cfg,
    senderId,
    senderName,
    channelId,
    channelInfo,
    storeAllowFrom,
    allowTextCommands,
    hasControlCommand,
  } = params;

  if (!channelInfo) {
    return {
      ok: false,
      denyReason: "unknown-channel",
      commandAuthorized: false,
      channelInfo: null,
      kind: "channel",
      chatType: "channel",
      channelName: "",
      channelDisplay: "",
      roomLabel: `#${channelId}`,
    };
  }

  const kind = mapMattermostChannelKind(channelInfo.type);
  const chatType = kind;
  const channelName = channelInfo.name ?? "";
  const channelDisplay = channelInfo.display_name ?? channelName;
  const roomLabel = channelName ? `#${channelName}` : channelDisplay || `#${channelId}`;

  const defaultGroupPolicy = cfg.channels?.defaults?.groupPolicy;
  const groupPolicy = account.config.groupPolicy ?? defaultGroupPolicy ?? "allowlist";

  const ingress = await resolveMattermostMonitorInboundAccess({
    account,
    cfg,
    senderId,
    senderName,
    channelId,
    kind,
    groupPolicy,
    storeAllowFrom,
    allowTextCommands,
    hasControlCommand,
    eventKind: "native-command",
    mayPair: true,
  });
  const denyReason = resolveMattermostCommandDenyReason({
    decision: ingress.decision,
    kind,
    dmPolicy: account.config.dmPolicy ?? "pairing",
  });

  if (denyReason) {
    return {
      ok: false,
      denyReason,
      commandAuthorized: false,
      channelInfo,
      kind,
      chatType,
      channelName,
      channelDisplay,
      roomLabel,
    };
  }

  return {
    ok: true,
    commandAuthorized: ingress.commandAuthorized,
    channelInfo,
    kind,
    chatType,
    channelName,
    channelDisplay,
    roomLabel,
  };
}
