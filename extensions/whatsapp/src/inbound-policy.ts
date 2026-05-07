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
} from "openclaw/plugin-sdk/channel-ingress";
import {
  resolveChannelGroupPolicy,
  resolveChannelGroupRequireMention,
} from "openclaw/plugin-sdk/channel-policy";
import type {
  ChannelGroupPolicy,
  DmPolicy,
  GroupPolicy,
  OpenClawConfig,
} from "openclaw/plugin-sdk/config-types";
import { resolveDefaultGroupPolicy } from "openclaw/plugin-sdk/runtime-group-policy";
import {
  readStoreAllowFromForDmPolicy,
  resolveEffectiveAllowFromLists,
} from "openclaw/plugin-sdk/security-runtime";
import { resolveGroupSessionKey } from "openclaw/plugin-sdk/session-store-runtime";
import { resolveWhatsAppAccount, type ResolvedWhatsAppAccount } from "./accounts.js";
import { getSelfIdentity, getSenderIdentity } from "./identity.js";
import type { WebInboundMessage } from "./inbound/types.js";
import { resolveWhatsAppRuntimeGroupPolicy } from "./runtime-group-policy.js";
import { isSelfChatMode, normalizeE164 } from "./text-runtime.js";

export type ResolvedWhatsAppInboundPolicy = {
  account: ResolvedWhatsAppAccount;
  dmPolicy: DmPolicy;
  groupPolicy: GroupPolicy;
  configuredAllowFrom: string[];
  dmAllowFrom: string[];
  groupAllowFrom: string[];
  isSelfChat: boolean;
  providerMissingFallbackApplied: boolean;
  shouldReadStorePairingApprovals: boolean;
  isSamePhone: (value?: string | null) => boolean;
  isDmSenderAllowed: (allowEntries: string[], sender?: string | null) => boolean;
  isGroupSenderAllowed: (allowEntries: string[], sender?: string | null) => boolean;
  resolveConversationGroupPolicy: (conversationId: string) => ChannelGroupPolicy;
  resolveConversationRequireMention: (conversationId: string) => boolean;
};

export type ResolvedWhatsAppIngressAccess = {
  ingress: ChannelIngressDecision;
  decision: "allow" | "block" | "pairing";
  reasonCode: IngressReasonCode;
  reason: string;
  commandAuthorized?: boolean;
};

const WHATSAPP_CHANNEL_ID = createChannelIngressPluginId("whatsapp");
const whatsappIngressAdapter = createChannelIngressStringAdapter({
  kind: "phone",
  normalizeEntry: normalizeWhatsAppIngressPhone,
  normalizeSubject: normalizeWhatsAppIngressPhone,
  sensitivity: "pii",
  resolveEntryId: ({ index }) => `whatsapp-entry-${index + 1}`,
});

function normalizeWhatsAppIngressPhone(value: string): string | null {
  const trimmed = value.trim();
  if (!trimmed) {
    return null;
  }
  return normalizeE164(trimmed);
}

function resolveGroupConversationId(conversationId: string): string {
  return (
    resolveGroupSessionKey({
      From: conversationId,
      ChatType: "group",
      Provider: "whatsapp",
    })?.id ?? conversationId
  );
}

function maybeSamePhoneDmAllowFrom(params: {
  isGroup: boolean;
  policy: ResolvedWhatsAppInboundPolicy;
  dmSenderId?: string | null;
}): string[] {
  if (params.isGroup || !params.dmSenderId || !params.policy.isSamePhone(params.dmSenderId)) {
    return [];
  }
  return [params.dmSenderId];
}

function findSenderGateReason(
  decision: ChannelIngressDecision,
  isGroup: boolean,
): IngressReasonCode {
  return findChannelIngressSenderGate(decision, { isGroup })?.reasonCode ?? decision.reasonCode;
}

function accessDecisionFromIngress(
  decision: ChannelIngressDecision,
): "allow" | "block" | "pairing" {
  if (decision.decision === "allow") {
    return "allow";
  }
  return decision.admission === "pairing-required" ? "pairing" : "block";
}

function reasonFromIngress(params: {
  reasonCode: IngressReasonCode;
  dmPolicy: DmPolicy;
  groupPolicy: GroupPolicy;
  isGroup: boolean;
}): string {
  switch (params.reasonCode) {
    case "group_policy_open":
    case "group_policy_allowed":
      return `groupPolicy=${params.groupPolicy}`;
    case "group_policy_disabled":
      return "groupPolicy=disabled";
    case "group_policy_empty_allowlist":
      return "groupPolicy=allowlist (empty allowlist)";
    case "dm_policy_open":
      return "dmPolicy=open";
    case "dm_policy_disabled":
      return "dmPolicy=disabled";
    case "dm_policy_allowlisted":
      return `dmPolicy=${params.dmPolicy} (allowlisted)`;
    case "dm_policy_pairing_required":
      return "dmPolicy=pairing (not allowlisted)";
    default:
      return params.isGroup
        ? "groupPolicy=allowlist (not allowlisted)"
        : `dmPolicy=${params.dmPolicy} (not allowlisted)`;
  }
}

function commandAuthorizedFromIngress(params: {
  decision: ChannelIngressDecision;
  includeCommand: boolean;
}): boolean | undefined {
  if (!params.includeCommand) {
    return undefined;
  }
  return findChannelIngressCommandGate(params.decision)?.allowed === true;
}

function isNormalizedSenderAllowed(allowEntries: string[], sender?: string | null): boolean {
  if (allowEntries.includes("*")) {
    return true;
  }
  const normalizedSender = normalizeE164(sender ?? "");
  if (!normalizedSender) {
    return false;
  }
  const normalizedEntrySet = new Set(
    allowEntries
      .map((entry) => normalizeE164(entry))
      .filter((entry): entry is string => Boolean(entry)),
  );
  return normalizedEntrySet.has(normalizedSender);
}

function buildResolvedWhatsAppGroupConfig(params: {
  groupPolicy: GroupPolicy;
  groups: ResolvedWhatsAppAccount["groups"];
}): OpenClawConfig {
  return {
    channels: {
      whatsapp: {
        groupPolicy: params.groupPolicy,
        groups: params.groups,
      },
    },
  } as OpenClawConfig;
}

export function resolveWhatsAppInboundPolicy(params: {
  cfg: OpenClawConfig;
  accountId?: string | null;
  selfE164?: string | null;
}): ResolvedWhatsAppInboundPolicy {
  const account = resolveWhatsAppAccount({
    cfg: params.cfg,
    accountId: params.accountId,
  });
  const configuredAllowFrom = account.allowFrom ?? [];
  const dmPolicy = account.dmPolicy ?? "pairing";
  const dmAllowFrom =
    configuredAllowFrom.length > 0 ? configuredAllowFrom : params.selfE164 ? [params.selfE164] : [];
  const groupAllowFrom =
    account.groupAllowFrom ??
    (configuredAllowFrom.length > 0 ? configuredAllowFrom : undefined) ??
    [];
  const { effectiveGroupAllowFrom } = resolveEffectiveAllowFromLists({
    allowFrom: configuredAllowFrom,
    groupAllowFrom,
  });
  const defaultGroupPolicy = resolveDefaultGroupPolicy(params.cfg);
  const { groupPolicy, providerMissingFallbackApplied } = resolveWhatsAppRuntimeGroupPolicy({
    providerConfigPresent: params.cfg.channels?.whatsapp !== undefined,
    groupPolicy: account.groupPolicy,
    defaultGroupPolicy,
  });
  const resolvedGroupCfg = buildResolvedWhatsAppGroupConfig({
    groupPolicy,
    groups: account.groups,
  });
  const isSamePhone = (value?: string | null) =>
    typeof value === "string" && typeof params.selfE164 === "string" && value === params.selfE164;
  return {
    account,
    dmPolicy,
    groupPolicy,
    configuredAllowFrom,
    dmAllowFrom,
    groupAllowFrom,
    isSelfChat: account.selfChatMode ?? isSelfChatMode(params.selfE164, configuredAllowFrom),
    providerMissingFallbackApplied,
    shouldReadStorePairingApprovals: dmPolicy !== "allowlist",
    isSamePhone,
    isDmSenderAllowed: (allowEntries, sender) =>
      isSamePhone(sender) || isNormalizedSenderAllowed(allowEntries, sender),
    isGroupSenderAllowed: (allowEntries, sender) => isNormalizedSenderAllowed(allowEntries, sender),
    resolveConversationGroupPolicy: (conversationId) =>
      resolveChannelGroupPolicy({
        cfg: resolvedGroupCfg,
        channel: "whatsapp",
        groupId: resolveGroupConversationId(conversationId),
        hasGroupAllowFrom: effectiveGroupAllowFrom.length > 0,
      }),
    resolveConversationRequireMention: (conversationId) =>
      resolveChannelGroupRequireMention({
        cfg: resolvedGroupCfg,
        channel: "whatsapp",
        groupId: resolveGroupConversationId(conversationId),
      }),
  };
}

export async function resolveWhatsAppIngressAccess(params: {
  cfg: OpenClawConfig;
  policy: ResolvedWhatsAppInboundPolicy;
  isGroup: boolean;
  conversationId: string;
  senderId?: string | null;
  dmSenderId?: string | null;
  includeCommand?: boolean;
}): Promise<ResolvedWhatsAppIngressAccess> {
  const storeAllowFrom = params.isGroup
    ? []
    : await readStoreAllowFromForDmPolicy({
        provider: "whatsapp",
        accountId: params.policy.account.accountId,
        dmPolicy: params.policy.dmPolicy,
        shouldRead: params.policy.shouldReadStorePairingApprovals,
      });
  const samePhoneDmAllowFrom = maybeSamePhoneDmAllowFrom({
    isGroup: params.isGroup,
    policy: params.policy,
    dmSenderId: params.dmSenderId,
  });
  const dmAllowFrom = [...params.policy.dmAllowFrom, ...samePhoneDmAllowFrom];
  const commandOwner = params.isGroup
    ? params.policy.dmAllowFrom
    : [...dmAllowFrom, ...storeAllowFrom];
  const state = await resolveChannelIngressState({
    channelId: WHATSAPP_CHANNEL_ID,
    accountId: params.policy.account.accountId,
    subject: createChannelIngressSubject({
      opaqueId: "whatsapp-sender-phone",
      kind: "phone",
      value: params.senderId ?? "",
      sensitivity: "pii",
    }),
    conversation: {
      kind: params.isGroup ? "group" : "direct",
      id: params.conversationId,
    },
    adapter: whatsappIngressAdapter,
    accessGroups: params.cfg.accessGroups,
    event: {
      kind: "message",
      authMode: "inbound",
      mayPair: !params.isGroup,
    },
    allowlists: {
      dm: dmAllowFrom,
      group: params.policy.groupAllowFrom,
      pairingStore: storeAllowFrom,
      commandOwner,
      commandGroup: params.policy.groupAllowFrom,
    },
  });
  const ingress = decideChannelIngress(state, {
    dmPolicy: params.policy.dmPolicy,
    groupPolicy: params.policy.groupPolicy,
    groupAllowFromFallbackToAllowFrom: false,
    ...(params.includeCommand
      ? {
          command: {
            useAccessGroups: params.cfg.commands?.useAccessGroups !== false,
            allowTextCommands: false,
            hasControlCommand: true,
            modeWhenAccessGroupsOff: "allow",
          },
        }
      : {}),
  });
  const reasonCode = findSenderGateReason(ingress, params.isGroup);
  return {
    ingress,
    decision: accessDecisionFromIngress(ingress),
    reasonCode,
    reason: reasonFromIngress({
      reasonCode,
      dmPolicy: params.policy.dmPolicy,
      groupPolicy: params.policy.groupPolicy,
      isGroup: params.isGroup,
    }),
    commandAuthorized: commandAuthorizedFromIngress({
      decision: ingress,
      includeCommand: params.includeCommand === true,
    }),
  };
}

export async function resolveWhatsAppCommandAuthorized(params: {
  cfg: OpenClawConfig;
  msg: WebInboundMessage;
  policy?: ResolvedWhatsAppInboundPolicy;
}): Promise<boolean> {
  const useAccessGroups = params.cfg.commands?.useAccessGroups !== false;
  if (!useAccessGroups) {
    return true;
  }

  const self = getSelfIdentity(params.msg);
  const policy =
    params.policy ??
    resolveWhatsAppInboundPolicy({
      cfg: params.cfg,
      accountId: params.msg.accountId,
      selfE164: self.e164 ?? null,
    });
  const isGroup = params.msg.chatType === "group";
  const sender = getSenderIdentity(params.msg);
  const dmSender = sender.e164 ?? params.msg.from ?? "";
  const groupSender = sender.e164 ?? "";
  if (!normalizeE164(isGroup ? groupSender : dmSender)) {
    return false;
  }

  const access = await resolveWhatsAppIngressAccess({
    cfg: params.cfg,
    policy,
    isGroup,
    conversationId: params.msg.conversationId ?? params.msg.chatId ?? params.msg.from,
    senderId: isGroup ? groupSender : dmSender,
    dmSenderId: dmSender,
    includeCommand: true,
  });
  return access.commandAuthorized === true;
}
