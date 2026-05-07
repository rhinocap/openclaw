import {
  mergeDmAllowFromSources,
  resolveGroupAllowFromSources,
} from "openclaw/plugin-sdk/allow-from";
import {
  createChannelIngressPluginId,
  createChannelIngressMultiIdentifierAdapter,
  createChannelIngressSubject,
  decideChannelIngress,
  findChannelIngressSenderGate,
  resolveChannelIngressState,
  type ChannelIngressDecision,
  type IngressReasonCode,
} from "openclaw/plugin-sdk/channel-ingress";
import type { DmPolicy, GroupPolicy, OpenClawConfig } from "openclaw/plugin-sdk/config-types";
import {
  DM_GROUP_ACCESS_REASON,
  type DmGroupAccessDecision,
  type DmGroupAccessReasonCode,
} from "openclaw/plugin-sdk/security-runtime";
import { normalizeOptionalLowercaseString } from "openclaw/plugin-sdk/text-runtime";

const ZALOUSER_CHANNEL_ID = createChannelIngressPluginId("zalouser");

export function normalizeZalouserAllowEntry(entry: string): string {
  return entry.replace(/^(zalouser|zlu):/i, "").trim();
}

function normalizeZalouserSender(value: string): string | null {
  const normalized = normalizeOptionalLowercaseString(normalizeZalouserAllowEntry(value));
  return normalized || null;
}

const zalouserIngressAdapter = createChannelIngressMultiIdentifierAdapter({
  normalizeEntry(entry, index) {
    const raw = entry.trim();
    const normalized = raw === "*" ? "*" : normalizeZalouserSender(raw);
    return normalized
      ? [
          {
            opaqueEntryId: `zalouser-entry-${index + 1}`,
            kind: "stable-id" as const,
            value: normalized,
            sensitivity: "pii" as const,
          },
        ]
      : [];
  },
  getSubjectMatchKeys(identifier) {
    if (identifier.kind !== "stable-id") {
      return [];
    }
    const normalized = normalizeZalouserSender(identifier.value);
    return normalized ? [`stable-id:${normalized}`] : [];
  },
});

function normalizeDmPolicy(policy: string): DmPolicy {
  return policy === "open" || policy === "allowlist" || policy === "disabled" ? policy : "pairing";
}

function normalizeGroupPolicy(policy: string): GroupPolicy {
  return policy === "open" || policy === "disabled" ? policy : "allowlist";
}

function findSenderGateReason(
  decision: ChannelIngressDecision,
  isGroup: boolean,
): IngressReasonCode {
  return findChannelIngressSenderGate(decision, { isGroup })?.reasonCode ?? decision.reasonCode;
}

function mapReasonCode(params: {
  reasonCode: IngressReasonCode;
  isGroup: boolean;
}): DmGroupAccessReasonCode {
  switch (params.reasonCode) {
    case "group_policy_open":
    case "group_policy_allowed":
      return DM_GROUP_ACCESS_REASON.GROUP_POLICY_ALLOWED;
    case "group_policy_disabled":
      return DM_GROUP_ACCESS_REASON.GROUP_POLICY_DISABLED;
    case "group_policy_empty_allowlist":
      return DM_GROUP_ACCESS_REASON.GROUP_POLICY_EMPTY_ALLOWLIST;
    case "group_policy_not_allowlisted":
      return DM_GROUP_ACCESS_REASON.GROUP_POLICY_NOT_ALLOWLISTED;
    case "dm_policy_open":
      return DM_GROUP_ACCESS_REASON.DM_POLICY_OPEN;
    case "dm_policy_disabled":
      return DM_GROUP_ACCESS_REASON.DM_POLICY_DISABLED;
    case "dm_policy_allowlisted":
      return DM_GROUP_ACCESS_REASON.DM_POLICY_ALLOWLISTED;
    case "dm_policy_pairing_required":
      return DM_GROUP_ACCESS_REASON.DM_POLICY_PAIRING_REQUIRED;
    default:
      return params.isGroup
        ? DM_GROUP_ACCESS_REASON.GROUP_POLICY_NOT_ALLOWLISTED
        : DM_GROUP_ACCESS_REASON.DM_POLICY_NOT_ALLOWLISTED;
  }
}

function accessDecisionFromIngress(params: {
  ingress: ChannelIngressDecision;
  reasonCode: DmGroupAccessReasonCode;
}): DmGroupAccessDecision {
  if (params.reasonCode === DM_GROUP_ACCESS_REASON.DM_POLICY_PAIRING_REQUIRED) {
    return "pairing";
  }
  return params.ingress.decision === "allow" ? "allow" : "block";
}

export async function resolveZalouserIngressAccess(params: {
  cfg: OpenClawConfig;
  accountId: string;
  isGroup: boolean;
  senderId: string;
  dmPolicy: string;
  groupPolicy: string;
  allowFrom?: Array<string | number>;
  groupAllowFrom?: Array<string | number>;
  storeAllowFrom?: Array<string | number>;
}): Promise<{
  ingress: ChannelIngressDecision;
  decision: DmGroupAccessDecision;
  reasonCode: DmGroupAccessReasonCode;
  effectiveAllowFrom: string[];
  effectiveGroupAllowFrom: string[];
}> {
  const dmPolicy = normalizeDmPolicy(params.dmPolicy);
  const groupPolicy = normalizeGroupPolicy(params.groupPolicy);
  const effectiveAllowFrom = mergeDmAllowFromSources({
    allowFrom: params.allowFrom,
    storeAllowFrom: params.storeAllowFrom,
    dmPolicy,
  });
  const effectiveGroupAllowFrom = resolveGroupAllowFromSources({
    allowFrom: params.allowFrom,
    groupAllowFrom: params.groupAllowFrom,
    fallbackToAllowFrom: false,
  });
  const state = await resolveChannelIngressState({
    channelId: ZALOUSER_CHANNEL_ID,
    accountId: params.accountId,
    subject: createChannelIngressSubject({
      value: params.senderId,
      sensitivity: "pii",
    }),
    conversation: {
      kind: params.isGroup ? "group" : "direct",
      id: params.isGroup ? "group" : params.senderId,
    },
    adapter: zalouserIngressAdapter,
    accessGroups: params.cfg.accessGroups,
    event: {
      kind: "message",
      authMode: "inbound",
      mayPair: !params.isGroup,
    },
    allowlists: {
      dm: params.allowFrom,
      group: params.groupAllowFrom,
      pairingStore: params.isGroup ? [] : params.storeAllowFrom,
    },
  });
  const ingress = decideChannelIngress(state, {
    dmPolicy,
    groupPolicy,
    groupAllowFromFallbackToAllowFrom: false,
  });
  const mappedReasonCode = mapReasonCode({
    reasonCode: findSenderGateReason(ingress, params.isGroup),
    isGroup: params.isGroup,
  });
  return {
    ingress,
    decision: accessDecisionFromIngress({
      ingress,
      reasonCode: mappedReasonCode,
    }),
    reasonCode: mappedReasonCode,
    effectiveAllowFrom,
    effectiveGroupAllowFrom,
  };
}
