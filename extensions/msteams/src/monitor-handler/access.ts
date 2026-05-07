import {
  assertNeverChannelIngressReason,
  createChannelIngressPluginId,
  createChannelIngressMultiIdentifierAdapter,
  decideChannelIngress,
  findChannelIngressCommandGate,
  findChannelIngressSenderGate,
  resolveChannelIngressState,
  type ChannelIngressAdapterEntry,
  type ChannelIngressDecision,
  type ChannelIngressIdentifierKind,
  type ChannelIngressPolicyInput,
  type ChannelIngressSubject,
  type IngressReasonCode,
  type RouteGateFacts,
} from "openclaw/plugin-sdk/channel-ingress";
import { normalizeOptionalLowercaseString } from "openclaw/plugin-sdk/text-runtime";
import {
  DEFAULT_ACCOUNT_ID,
  createChannelPairingController,
  isDangerousNameMatchingEnabled,
  readStoreAllowFromForDmPolicy,
  resolveDefaultGroupPolicy,
  resolveEffectiveAllowFromLists,
  type OpenClawConfig,
} from "../../runtime-api.js";
import { normalizeMSTeamsConversationId } from "../inbound.js";
import { resolveMSTeamsRouteConfig } from "../policy.js";
import { getMSTeamsRuntime } from "../runtime.js";
import type { MSTeamsTurnContext } from "../sdk-types.js";

type MSTeamsDmPolicy = "open" | "pairing" | "allowlist" | "disabled";
type MSTeamsGroupPolicy = "open" | "allowlist" | "disabled";
type MSTeamsAccessDecision = {
  decision: "allow" | "block" | "pairing";
  reasonCode:
    | "group_policy_allowed"
    | "group_policy_disabled"
    | "group_policy_empty_allowlist"
    | "group_policy_not_allowlisted"
    | "dm_policy_open"
    | "dm_policy_disabled"
    | "dm_policy_allowlisted"
    | "dm_policy_pairing_required"
    | "dm_policy_not_allowlisted";
  reason: string;
  effectiveAllowFrom: string[];
  effectiveGroupAllowFrom: string[];
};
type MSTeamsSenderGroupAccess = {
  allowed: boolean;
  groupPolicy: MSTeamsGroupPolicy;
  providerMissingFallbackApplied: boolean;
  reason: "allowed" | "disabled" | "empty_allowlist" | "sender_not_allowlisted";
};

const MSTEAMS_SENDER_NAME_KIND =
  "plugin:msteams-sender-name" as const satisfies ChannelIngressIdentifierKind;
const MSTEAMS_CHANNEL_ID = createChannelIngressPluginId("msteams");

function normalizeIngressValue(value?: string | null): string | null {
  return normalizeOptionalLowercaseString(value) ?? null;
}

function createMSTeamsAdapterEntry(params: {
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

function normalizeMSTeamsIngressEntry(entry: string, index: number): ChannelIngressAdapterEntry[] {
  const normalized = normalizeIngressValue(entry);
  if (!normalized) {
    return [];
  }
  if (normalized === "*") {
    return [
      createMSTeamsAdapterEntry({
        index,
        kind: "stable-id",
        value: "*",
        suffix: "wildcard",
      }),
    ];
  }
  return [
    createMSTeamsAdapterEntry({
      index,
      kind: "stable-id",
      value: normalized,
      suffix: "id",
    }),
    createMSTeamsAdapterEntry({
      index,
      kind: MSTEAMS_SENDER_NAME_KIND,
      value: normalized,
      suffix: "name",
      dangerous: true,
    }),
  ];
}

const msteamsIngressAdapter = createChannelIngressMultiIdentifierAdapter({
  normalizeEntry: normalizeMSTeamsIngressEntry,
});

function createMSTeamsIngressSubject(params: {
  senderId: string;
  senderName: string;
}): ChannelIngressSubject {
  const identifiers: ChannelIngressSubject["identifiers"] = [];
  const senderId = normalizeIngressValue(params.senderId);
  if (senderId) {
    identifiers.push({
      opaqueId: "sender-id",
      kind: "stable-id",
      value: senderId,
    });
  }
  const senderName = normalizeIngressValue(params.senderName);
  if (senderName) {
    identifiers.push({
      opaqueId: "sender-name",
      kind: MSTEAMS_SENDER_NAME_KIND,
      value: senderName,
      dangerous: true,
    });
  }
  return { identifiers };
}

function createMSTeamsRouteFacts(params: {
  isDirectMessage: boolean;
  routeAllowed: boolean;
  routeAllowlistConfigured: boolean;
  groupPolicy: MSTeamsGroupPolicy;
  effectiveGroupAllowFrom: string[];
}): RouteGateFacts[] {
  if (params.isDirectMessage || !params.routeAllowlistConfigured) {
    return [];
  }
  return [
    {
      id: "msteams:team-channel",
      kind: "nestedAllowlist",
      gate: params.routeAllowed ? "matched" : "not-matched",
      effect: params.routeAllowed ? "allow" : "block-dispatch",
      precedence: 0,
      senderPolicy: params.groupPolicy === "allowlist" ? "deny-when-empty" : "inherit",
      senderAllowFrom: params.routeAllowed ? params.effectiveGroupAllowFrom : undefined,
      match: {
        matched: params.routeAllowed,
        matchedEntryIds: params.routeAllowed ? ["msteams-route"] : [],
      },
    },
  ];
}

function findGateReason(
  decision: ChannelIngressDecision,
  isDirectMessage: boolean,
): IngressReasonCode {
  return (
    findChannelIngressSenderGate(decision, { isGroup: !isDirectMessage })?.reasonCode ??
    decision.reasonCode
  );
}

function mapMSTeamsAccessReasonCode(params: {
  reasonCode: IngressReasonCode;
  isDirectMessage: boolean;
}): MSTeamsAccessDecision["reasonCode"] {
  switch (params.reasonCode) {
    case "group_policy_open":
    case "group_policy_allowed":
      return "group_policy_allowed";
    case "group_policy_disabled":
      return "group_policy_disabled";
    case "route_sender_empty":
    case "group_policy_empty_allowlist":
      return "group_policy_empty_allowlist";
    case "group_policy_not_allowlisted":
      return "group_policy_not_allowlisted";
    case "dm_policy_open":
      return "dm_policy_open";
    case "dm_policy_disabled":
      return "dm_policy_disabled";
    case "dm_policy_allowlisted":
      return "dm_policy_allowlisted";
    case "dm_policy_pairing_required":
      return "dm_policy_pairing_required";
    default:
      return params.isDirectMessage ? "dm_policy_not_allowlisted" : "group_policy_not_allowlisted";
  }
}

function msteamsAccessFromIngress(params: {
  ingress: ChannelIngressDecision;
  isDirectMessage: boolean;
  dmPolicy: MSTeamsDmPolicy;
  groupPolicy: MSTeamsGroupPolicy;
  effectiveAllowFrom: string[];
  effectiveGroupAllowFrom: string[];
}): MSTeamsAccessDecision {
  const reasonCode = mapMSTeamsAccessReasonCode({
    reasonCode: findGateReason(params.ingress, params.isDirectMessage),
    isDirectMessage: params.isDirectMessage,
  });
  const decision =
    reasonCode === "dm_policy_pairing_required"
      ? "pairing"
      : params.ingress.decision === "allow"
        ? "allow"
        : "block";
  const reason = (() => {
    switch (reasonCode) {
      case "group_policy_allowed":
        return `groupPolicy=${params.groupPolicy}`;
      case "group_policy_disabled":
        return "groupPolicy=disabled";
      case "group_policy_empty_allowlist":
        return "groupPolicy=allowlist (empty allowlist)";
      case "group_policy_not_allowlisted":
        return "groupPolicy=allowlist (not allowlisted)";
      case "dm_policy_open":
        return "dmPolicy=open";
      case "dm_policy_disabled":
        return "dmPolicy=disabled";
      case "dm_policy_allowlisted":
        return `dmPolicy=${params.dmPolicy} (allowlisted)`;
      case "dm_policy_pairing_required":
        return "dmPolicy=pairing (not allowlisted)";
      case "dm_policy_not_allowlisted":
        return `dmPolicy=${params.dmPolicy} (not allowlisted)`;
    }
    return assertNeverChannelIngressReason(reasonCode);
  })();
  return {
    decision,
    reasonCode,
    reason,
    effectiveAllowFrom: params.effectiveAllowFrom,
    effectiveGroupAllowFrom: params.effectiveGroupAllowFrom,
  };
}

function senderGroupAccessFromIngress(params: {
  ingress: ChannelIngressDecision;
  groupPolicy: MSTeamsGroupPolicy;
}): MSTeamsSenderGroupAccess {
  const reasonCode = findGateReason(params.ingress, false);
  if (params.groupPolicy === "disabled" || reasonCode === "group_policy_disabled") {
    return {
      allowed: false,
      groupPolicy: params.groupPolicy,
      providerMissingFallbackApplied: false,
      reason: "disabled",
    };
  }
  if (reasonCode === "route_sender_empty" || reasonCode === "group_policy_empty_allowlist") {
    return {
      allowed: false,
      groupPolicy: params.groupPolicy,
      providerMissingFallbackApplied: false,
      reason: "empty_allowlist",
    };
  }
  if (reasonCode === "group_policy_not_allowlisted") {
    return {
      allowed: false,
      groupPolicy: params.groupPolicy,
      providerMissingFallbackApplied: false,
      reason: "sender_not_allowlisted",
    };
  }
  return {
    allowed: true,
    groupPolicy: params.groupPolicy,
    providerMissingFallbackApplied: false,
    reason: "allowed",
  };
}

function commandAccessFromIngress(ingress: ChannelIngressDecision): {
  commandAuthorized: boolean;
  shouldBlockControlCommand: boolean;
} {
  const commandGate = findChannelIngressCommandGate(ingress);
  return {
    commandAuthorized: commandGate?.allowed === true,
    shouldBlockControlCommand: commandGate?.command?.shouldBlockControlCommand === true,
  };
}

export async function resolveMSTeamsSenderAccess(params: {
  cfg: OpenClawConfig;
  activity: MSTeamsTurnContext["activity"];
  hasControlCommand?: boolean;
}) {
  const activity = params.activity;
  const msteamsCfg = params.cfg.channels?.msteams;
  const conversationId = normalizeMSTeamsConversationId(activity.conversation?.id ?? "unknown");
  const convType = normalizeOptionalLowercaseString(activity.conversation?.conversationType);
  const isDirectMessage = convType === "personal" || (!convType && !activity.conversation?.isGroup);
  const senderId = activity.from?.aadObjectId ?? activity.from?.id ?? "unknown";
  const senderName = activity.from?.name ?? activity.from?.id ?? senderId;

  const core = getMSTeamsRuntime();
  const pairing = createChannelPairingController({
    core,
    channel: "msteams",
    accountId: DEFAULT_ACCOUNT_ID,
  });
  const dmPolicy = msteamsCfg?.dmPolicy ?? "pairing";
  const storedAllowFrom = await readStoreAllowFromForDmPolicy({
    provider: "msteams",
    accountId: pairing.accountId,
    dmPolicy,
    readStore: pairing.readStoreForDmPolicy,
  });
  const configuredDmAllowFrom = msteamsCfg?.allowFrom ?? [];
  const groupAllowFrom = msteamsCfg?.groupAllowFrom;
  const resolvedAllowFromLists = resolveEffectiveAllowFromLists({
    allowFrom: configuredDmAllowFrom,
    groupAllowFrom,
    storeAllowFrom: storedAllowFrom,
    dmPolicy,
  });
  const defaultGroupPolicy = resolveDefaultGroupPolicy(params.cfg);
  const groupPolicy =
    !isDirectMessage && msteamsCfg
      ? (msteamsCfg.groupPolicy ?? defaultGroupPolicy ?? "allowlist")
      : "disabled";
  const effectiveGroupAllowFrom = resolvedAllowFromLists.effectiveGroupAllowFrom;
  const commandDmAllowFrom = isDirectMessage
    ? resolvedAllowFromLists.effectiveAllowFrom
    : configuredDmAllowFrom;
  const allowNameMatching = isDangerousNameMatchingEnabled(msteamsCfg);
  const channelGate = resolveMSTeamsRouteConfig({
    cfg: msteamsCfg,
    teamId: activity.channelData?.team?.id,
    teamName: activity.channelData?.team?.name,
    conversationId,
    channelName: activity.channelData?.channel?.name,
    allowNameMatching,
  });

  const ingressState = await resolveChannelIngressState({
    channelId: MSTEAMS_CHANNEL_ID,
    accountId: pairing.accountId,
    subject: createMSTeamsIngressSubject({ senderId, senderName }),
    conversation: {
      kind: isDirectMessage ? "direct" : convType === "channel" ? "channel" : "group",
      id: conversationId,
      parentId: activity.channelData?.team?.id,
    },
    adapter: msteamsIngressAdapter,
    accessGroups: params.cfg.accessGroups,
    routeFacts: createMSTeamsRouteFacts({
      isDirectMessage,
      routeAllowed: channelGate.allowed,
      routeAllowlistConfigured: channelGate.allowlistConfigured,
      groupPolicy,
      effectiveGroupAllowFrom,
    }),
    event: {
      kind: "message",
      authMode: "inbound",
      mayPair: isDirectMessage,
    },
    allowlists: {
      dm: configuredDmAllowFrom,
      group: effectiveGroupAllowFrom,
      commandOwner: commandDmAllowFrom,
      commandGroup: effectiveGroupAllowFrom,
      pairingStore: storedAllowFrom,
    },
  });
  const ingressPolicy: ChannelIngressPolicyInput = {
    dmPolicy,
    groupPolicy,
    groupAllowFromFallbackToAllowFrom: false,
    mutableIdentifierMatching: allowNameMatching ? "enabled" : "disabled",
    command: {
      useAccessGroups: params.cfg.commands?.useAccessGroups !== false,
      allowTextCommands: true,
      hasControlCommand: params.hasControlCommand === true,
    },
  };
  const ingress = decideChannelIngress(ingressState, ingressPolicy);
  const access = msteamsAccessFromIngress({
    ingress,
    isDirectMessage,
    dmPolicy,
    groupPolicy,
    effectiveAllowFrom: resolvedAllowFromLists.effectiveAllowFrom,
    effectiveGroupAllowFrom,
  });
  const senderGroupAccess = senderGroupAccessFromIngress({
    ingress,
    groupPolicy,
  });
  const commandAccess = commandAccessFromIngress(ingress);

  return {
    msteamsCfg,
    pairing,
    isDirectMessage,
    conversationId,
    senderId,
    senderName,
    dmPolicy,
    channelGate,
    access,
    senderGroupAccess,
    commandAuthorized: commandAccess.commandAuthorized,
    shouldBlockControlCommand: commandAccess.shouldBlockControlCommand,
    configuredDmAllowFrom,
    effectiveDmAllowFrom: access.effectiveAllowFrom,
    effectiveGroupAllowFrom,
    allowNameMatching,
    groupPolicy,
  };
}
