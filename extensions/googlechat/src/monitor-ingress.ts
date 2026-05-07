import {
  assertNeverChannelIngressReason,
  createChannelIngressPluginId,
  createChannelIngressMultiIdentifierAdapter,
  decideChannelIngress,
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
import { normalizeLowercaseStringOrEmpty } from "openclaw/plugin-sdk/text-runtime";
import type { OpenClawConfig } from "../runtime-api.js";

type GoogleChatDmPolicy = "open" | "pairing" | "allowlist" | "disabled";
type GoogleChatGroupPolicy = "open" | "allowlist" | "disabled";
type GoogleChatAccessDecision = {
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

const GOOGLECHAT_EMAIL_KIND =
  "plugin:googlechat-email" as const satisfies ChannelIngressIdentifierKind;
const GOOGLECHAT_CHANNEL_ID = createChannelIngressPluginId("googlechat");

function normalizeUserId(raw?: string | null): string {
  const trimmed = typeof raw === "string" ? raw.trim() : "";
  if (!trimmed) {
    return "";
  }
  return normalizeLowercaseStringOrEmpty(trimmed.replace(/^users\//i, ""));
}

function normalizeEntryValue(raw?: string | null): string {
  return normalizeLowercaseStringOrEmpty(raw ?? "");
}

function isEmailLike(value: string): boolean {
  return value.includes("@");
}

function createGoogleChatAdapterEntry(params: {
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

function normalizeGoogleChatIngressEntry(
  entry: string,
  index: number,
): ChannelIngressAdapterEntry[] {
  const normalized = normalizeEntryValue(entry);
  if (!normalized) {
    return [];
  }
  if (normalized === "*") {
    return [
      createGoogleChatAdapterEntry({
        index,
        kind: "stable-id",
        value: "*",
        suffix: "wildcard",
      }),
    ];
  }
  const withoutPrefix = normalized.replace(/^(googlechat|google-chat|gchat):/i, "");
  if (withoutPrefix.startsWith("users/")) {
    return [
      createGoogleChatAdapterEntry({
        index,
        kind: "stable-id",
        value: normalizeUserId(withoutPrefix),
        suffix: "user",
      }),
    ];
  }
  const entries = [
    createGoogleChatAdapterEntry({
      index,
      kind: "stable-id",
      value: withoutPrefix,
      suffix: "user",
    }),
  ];
  if (isEmailLike(withoutPrefix)) {
    entries.push(
      createGoogleChatAdapterEntry({
        index,
        kind: GOOGLECHAT_EMAIL_KIND,
        value: withoutPrefix,
        suffix: "email",
        dangerous: true,
      }),
    );
  }
  return entries;
}

const googleChatIngressAdapter = createChannelIngressMultiIdentifierAdapter({
  normalizeEntry: normalizeGoogleChatIngressEntry,
});

function createGoogleChatIngressSubject(params: {
  senderId: string;
  senderEmail?: string;
}): ChannelIngressSubject {
  const identifiers: ChannelIngressSubject["identifiers"] = [];
  const senderId = normalizeUserId(params.senderId);
  if (senderId) {
    identifiers.push({
      opaqueId: "sender-id",
      kind: "stable-id",
      value: senderId,
    });
  }
  const senderEmail = normalizeEntryValue(params.senderEmail);
  if (senderEmail) {
    identifiers.push({
      opaqueId: "sender-email",
      kind: GOOGLECHAT_EMAIL_KIND,
      value: senderEmail,
      dangerous: true,
    });
  }
  return { identifiers };
}

function createGoogleChatRouteFacts(params: {
  isGroup: boolean;
  groupPolicy: GoogleChatGroupPolicy;
  routeAllowlistConfigured: boolean;
  routeMatched: boolean;
  routeEnabled: boolean;
  groupAllowFrom: string[];
}): RouteGateFacts[] {
  if (!params.isGroup || params.groupPolicy === "disabled") {
    return [];
  }
  if (params.routeMatched && !params.routeEnabled) {
    return [
      {
        id: "googlechat:space",
        kind: "route",
        gate: "disabled",
        effect: "block-dispatch",
        precedence: 0,
        senderPolicy: "inherit",
        match: {
          matched: true,
          matchedEntryIds: ["googlechat-space"],
        },
      },
    ];
  }
  if (params.groupPolicy === "allowlist" && params.routeAllowlistConfigured) {
    return [
      {
        id: "googlechat:space",
        kind: "route",
        gate: params.routeMatched ? "matched" : "not-matched",
        effect: params.routeMatched ? "allow" : "block-dispatch",
        precedence: 0,
        senderPolicy: "deny-when-empty",
        senderAllowFrom: params.routeMatched ? params.groupAllowFrom : undefined,
        match: {
          matched: params.routeMatched,
          matchedEntryIds: params.routeMatched ? ["googlechat-space"] : [],
        },
      },
    ];
  }
  return [];
}

function effectiveDmAllowFrom(params: {
  allowFrom: string[];
  storeAllowFrom: string[];
  dmPolicy: GoogleChatDmPolicy;
}): string[] {
  return params.dmPolicy === "allowlist" || params.dmPolicy === "open"
    ? params.allowFrom
    : [...params.allowFrom, ...params.storeAllowFrom];
}

function resolveSenderGroupPolicy(params: {
  groupPolicy: GoogleChatGroupPolicy;
  routeAllowlistConfigured: boolean;
  groupAllowFrom: string[];
}): GoogleChatGroupPolicy {
  if (params.routeAllowlistConfigured && params.groupAllowFrom.length === 0) {
    return params.groupPolicy;
  }
  if (params.groupPolicy === "disabled") {
    return "disabled";
  }
  return params.groupAllowFrom.length > 0 ? "allowlist" : "open";
}

function findSenderGateReason(
  decision: ChannelIngressDecision,
  isGroup: boolean,
): IngressReasonCode {
  return findChannelIngressSenderGate(decision, { isGroup })?.reasonCode ?? decision.reasonCode;
}

function mapGoogleChatAccessReasonCode(params: {
  reasonCode: IngressReasonCode;
  isGroup: boolean;
}): GoogleChatAccessDecision["reasonCode"] {
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
      return params.isGroup ? "group_policy_not_allowlisted" : "dm_policy_not_allowlisted";
  }
}

function accessFromIngress(params: {
  ingress: ChannelIngressDecision;
  isGroup: boolean;
  dmPolicy: GoogleChatDmPolicy;
  groupPolicy: GoogleChatGroupPolicy;
  effectiveAllowFrom: string[];
  effectiveGroupAllowFrom: string[];
}): GoogleChatAccessDecision {
  const reasonCode = mapGoogleChatAccessReasonCode({
    reasonCode: findSenderGateReason(params.ingress, params.isGroup),
    isGroup: params.isGroup,
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

export async function resolveGoogleChatIngressAccess(params: {
  accountId: string;
  accessGroups?: OpenClawConfig["accessGroups"];
  isGroup: boolean;
  spaceId: string;
  senderId: string;
  senderEmail?: string;
  allowNameMatching: boolean;
  dmPolicy: GoogleChatDmPolicy;
  groupPolicy: GoogleChatGroupPolicy;
  routeAllowlistConfigured: boolean;
  routeMatched: boolean;
  routeEnabled: boolean;
  allowFrom: string[];
  groupAllowFrom: string[];
  storeAllowFrom: string[];
}) {
  const senderGroupPolicy = resolveSenderGroupPolicy({
    groupPolicy: params.groupPolicy,
    routeAllowlistConfigured: params.routeAllowlistConfigured,
    groupAllowFrom: params.groupAllowFrom,
  });
  const state = await resolveChannelIngressState({
    channelId: GOOGLECHAT_CHANNEL_ID,
    accountId: params.accountId,
    subject: createGoogleChatIngressSubject({
      senderId: params.senderId,
      senderEmail: params.senderEmail,
    }),
    conversation: {
      kind: params.isGroup ? "group" : "direct",
      id: params.spaceId,
    },
    adapter: googleChatIngressAdapter,
    accessGroups: params.accessGroups,
    routeFacts: createGoogleChatRouteFacts({
      isGroup: params.isGroup,
      groupPolicy: params.groupPolicy,
      routeAllowlistConfigured: params.routeAllowlistConfigured,
      routeMatched: params.routeMatched,
      routeEnabled: params.routeEnabled,
      groupAllowFrom: params.groupAllowFrom,
    }),
    event: {
      kind: "message",
      authMode: "inbound",
      mayPair: !params.isGroup,
    },
    allowlists: {
      dm: params.allowFrom,
      group: params.groupAllowFrom,
      pairingStore: params.storeAllowFrom,
    },
  });
  const policy: ChannelIngressPolicyInput = {
    dmPolicy: params.dmPolicy,
    groupPolicy: senderGroupPolicy,
    groupAllowFromFallbackToAllowFrom: false,
    mutableIdentifierMatching: params.allowNameMatching ? "enabled" : "disabled",
  };
  const ingress = decideChannelIngress(state, policy);
  const access = accessFromIngress({
    ingress,
    isGroup: params.isGroup,
    dmPolicy: params.dmPolicy,
    groupPolicy: senderGroupPolicy,
    effectiveAllowFrom: effectiveDmAllowFrom({
      allowFrom: params.allowFrom,
      storeAllowFrom: params.storeAllowFrom,
      dmPolicy: params.dmPolicy,
    }),
    effectiveGroupAllowFrom: params.groupAllowFrom,
  });
  return {
    ingress,
    access,
  };
}
