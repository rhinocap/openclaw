import {
  assertNeverChannelIngressReason,
  createChannelIngressPluginId,
  createChannelIngressMultiIdentifierAdapter,
  decideChannelIngressBundle,
  findChannelIngressCommandGate,
  findChannelIngressSenderGate,
  resolveChannelIngressState,
  type ChannelIngressAdapterEntry,
  type ChannelIngressDecision,
  type ChannelIngressIdentifierKind,
  type ChannelIngressSubject,
  type IngressReasonCode,
} from "openclaw/plugin-sdk/channel-ingress";
import { createChannelPairingChallengeIssuer } from "openclaw/plugin-sdk/channel-pairing";
import { upsertChannelPairingRequest } from "openclaw/plugin-sdk/conversation-runtime";
import {
  DM_GROUP_ACCESS_REASON,
  type DmGroupAccessDecision,
  type DmGroupAccessReasonCode,
  readStoreAllowFromForDmPolicy,
  resolveEffectiveAllowFromLists,
} from "openclaw/plugin-sdk/security-runtime";
import {
  isSignalSenderAllowed,
  looksLikeUuid,
  normalizeSignalAllowRecipient,
  type SignalSender,
} from "../identity.js";

type SignalDmPolicy = "open" | "pairing" | "allowlist" | "disabled";
type SignalGroupPolicy = "open" | "allowlist" | "disabled";
type SignalAccessDecision = {
  decision: DmGroupAccessDecision;
  reasonCode: DmGroupAccessReasonCode;
  reason: string;
  effectiveAllowFrom: string[];
  effectiveGroupAllowFrom: string[];
};

const SIGNAL_UUID_KIND = "plugin:signal-uuid" as const satisfies ChannelIngressIdentifierKind;
const SIGNAL_GROUP_KIND = "plugin:signal-group" as const satisfies ChannelIngressIdentifierKind;

function isSignalGroupAllowed(groupId: string | undefined, allowEntries: string[]): boolean {
  if (!groupId) {
    return false;
  }
  const candidates = new Set([groupId, `group:${groupId}`, `signal:group:${groupId}`]);
  return allowEntries.some((entry) => candidates.has(entry));
}

function signalEntryId(params: { index: number; suffix: string }): string {
  return `entry-${params.index + 1}:${params.suffix}`;
}

function createSignalAdapterEntry(params: {
  index: number;
  kind: ChannelIngressIdentifierKind;
  value: string;
  suffix: string;
  sensitivity?: ChannelIngressAdapterEntry["sensitivity"];
}): ChannelIngressAdapterEntry {
  return {
    opaqueEntryId: signalEntryId(params),
    kind: params.kind,
    value: params.value,
    sensitivity: params.sensitivity,
  };
}

function normalizeSignalIngressEntry(entry: string, index: number): ChannelIngressAdapterEntry[] {
  const trimmed = entry.trim();
  if (!trimmed) {
    return [];
  }
  if (trimmed === "*") {
    return [
      createSignalAdapterEntry({
        index,
        kind: "stable-id",
        value: "*",
        suffix: "wildcard",
      }),
    ];
  }

  const signalStripped = trimmed.replace(/^signal:/i, "").trim();
  const lower = signalStripped.toLowerCase();
  if (lower.startsWith("group:")) {
    const groupId = signalStripped.slice("group:".length).trim();
    return groupId
      ? [
          createSignalAdapterEntry({
            index,
            kind: SIGNAL_GROUP_KIND,
            value: groupId,
            suffix: "group",
          }),
        ]
      : [];
  }

  const entries: ChannelIngressAdapterEntry[] = [
    createSignalAdapterEntry({
      index,
      kind: SIGNAL_GROUP_KIND,
      value: trimmed,
      suffix: "group",
    }),
  ];
  if (lower.startsWith("uuid:")) {
    const raw = signalStripped.slice("uuid:".length).trim();
    if (raw) {
      entries.push(
        createSignalAdapterEntry({
          index,
          kind: SIGNAL_UUID_KIND,
          value: raw,
          suffix: "uuid",
          sensitivity: "pii",
        }),
      );
    }
    return entries;
  }

  if (looksLikeUuid(signalStripped)) {
    entries.push(
      createSignalAdapterEntry({
        index,
        kind: SIGNAL_UUID_KIND,
        value: signalStripped,
        suffix: "uuid",
        sensitivity: "pii",
      }),
    );
    return entries;
  }

  const normalized = normalizeSignalAllowRecipient(trimmed);
  if (normalized) {
    entries.push(
      createSignalAdapterEntry({
        index,
        kind: "phone",
        value: normalized,
        suffix: "phone",
        sensitivity: "pii",
      }),
    );
  }
  return entries;
}

const signalIngressAdapter = createChannelIngressMultiIdentifierAdapter({
  normalizeEntry: normalizeSignalIngressEntry,
});

function createSignalIngressSubject(params: {
  sender: SignalSender;
  groupId?: string;
}): ChannelIngressSubject {
  const identifiers: ChannelIngressSubject["identifiers"] = [];
  if (params.sender.kind === "phone") {
    identifiers.push({
      opaqueId: "sender-phone",
      kind: "phone",
      value: params.sender.e164,
      sensitivity: "pii",
    });
  } else {
    identifiers.push({
      opaqueId: "sender-uuid",
      kind: SIGNAL_UUID_KIND,
      value: params.sender.raw,
      sensitivity: "pii",
    });
  }
  if (params.groupId) {
    identifiers.push({
      opaqueId: "signal-group",
      kind: SIGNAL_GROUP_KIND,
      value: params.groupId,
    });
  }
  return { identifiers };
}

function findSenderGateReason(
  decision: ChannelIngressDecision,
  isGroup: boolean,
): IngressReasonCode {
  return findChannelIngressSenderGate(decision, { isGroup })?.reasonCode ?? decision.reasonCode;
}

function mapSignalReasonCode(params: {
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

function signalDecisionFromIngress(params: {
  ingress: ChannelIngressDecision;
  isGroup: boolean;
  dmPolicy: SignalDmPolicy;
  groupPolicy: SignalGroupPolicy;
  effectiveAllowFrom: string[];
  effectiveGroupAllowFrom: string[];
}): SignalAccessDecision {
  const senderReasonCode = findSenderGateReason(params.ingress, params.isGroup);
  const reasonCode = mapSignalReasonCode({
    reasonCode: senderReasonCode,
    isGroup: params.isGroup,
  });
  const decision: DmGroupAccessDecision =
    reasonCode === DM_GROUP_ACCESS_REASON.DM_POLICY_PAIRING_REQUIRED
      ? "pairing"
      : params.ingress.decision === "allow"
        ? "allow"
        : "block";
  const reason = (() => {
    switch (reasonCode) {
      case DM_GROUP_ACCESS_REASON.GROUP_POLICY_ALLOWED:
        return `groupPolicy=${params.groupPolicy}`;
      case DM_GROUP_ACCESS_REASON.GROUP_POLICY_DISABLED:
        return "groupPolicy=disabled";
      case DM_GROUP_ACCESS_REASON.GROUP_POLICY_EMPTY_ALLOWLIST:
        return "groupPolicy=allowlist (empty allowlist)";
      case DM_GROUP_ACCESS_REASON.GROUP_POLICY_NOT_ALLOWLISTED:
        return "groupPolicy=allowlist (not allowlisted)";
      case DM_GROUP_ACCESS_REASON.DM_POLICY_OPEN:
        return "dmPolicy=open";
      case DM_GROUP_ACCESS_REASON.DM_POLICY_DISABLED:
        return "dmPolicy=disabled";
      case DM_GROUP_ACCESS_REASON.DM_POLICY_ALLOWLISTED:
        return `dmPolicy=${params.dmPolicy} (allowlisted)`;
      case DM_GROUP_ACCESS_REASON.DM_POLICY_PAIRING_REQUIRED:
        return "dmPolicy=pairing (not allowlisted)";
      case DM_GROUP_ACCESS_REASON.DM_POLICY_NOT_ALLOWLISTED:
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

export async function resolveSignalAccessState(params: {
  accountId: string;
  dmPolicy: SignalDmPolicy;
  groupPolicy: SignalGroupPolicy;
  allowFrom: string[];
  groupAllowFrom: string[];
  sender: SignalSender;
  groupId?: string;
  hasControlCommand?: boolean;
  useAccessGroups?: boolean;
}) {
  const storeAllowFrom = await readStoreAllowFromForDmPolicy({
    provider: "signal",
    accountId: params.accountId,
    dmPolicy: params.dmPolicy,
  });
  const { effectiveAllowFrom, effectiveGroupAllowFrom } = resolveEffectiveAllowFromLists({
    allowFrom: params.allowFrom,
    groupAllowFrom: params.groupAllowFrom,
    storeAllowFrom,
    dmPolicy: params.dmPolicy,
  });
  const directSubject = createSignalIngressSubject({ sender: params.sender });
  const groupSubject = createSignalIngressSubject({
    sender: params.sender,
    groupId: params.groupId,
  });
  const isSenderAllowed = (allowEntries: string[]) =>
    isSignalSenderAllowed(params.sender, allowEntries);
  const isSenderOrGroupAllowed = (allowEntries: string[]) =>
    isSenderAllowed(allowEntries) || isSignalGroupAllowed(params.groupId, allowEntries);
  const channelId = createChannelIngressPluginId("signal");
  const [directState, groupState] = await Promise.all([
    resolveChannelIngressState({
      channelId,
      accountId: params.accountId,
      subject: directSubject,
      conversation: {
        kind: "direct",
        id: params.sender.raw,
      },
      adapter: signalIngressAdapter,
      event: {
        kind: "message",
        authMode: "inbound",
        mayPair: true,
      },
      allowlists: {
        dm: params.allowFrom,
        group: params.groupAllowFrom,
        commandOwner: effectiveAllowFrom,
        commandGroup: effectiveGroupAllowFrom,
        pairingStore: storeAllowFrom,
      },
    }),
    resolveChannelIngressState({
      channelId,
      accountId: params.accountId,
      subject: groupSubject,
      conversation: {
        kind: "group",
        id: params.groupId ?? "unknown",
      },
      adapter: signalIngressAdapter,
      event: {
        kind: "message",
        authMode: "inbound",
        mayPair: false,
      },
      allowlists: {
        dm: params.allowFrom,
        group: effectiveGroupAllowFrom,
        commandOwner: params.allowFrom,
        commandGroup: effectiveGroupAllowFrom,
        pairingStore: storeAllowFrom,
      },
    }),
  ]);
  const basePolicy = {
    dmPolicy: params.dmPolicy,
    groupPolicy: params.groupPolicy,
  };
  const commandPolicy = {
    ...basePolicy,
    command: {
      useAccessGroups: params.useAccessGroups !== false,
      allowTextCommands: true,
      hasControlCommand: params.hasControlCommand === true,
    },
  };
  const ingressBundle = decideChannelIngressBundle({
    directState,
    groupState,
    basePolicy,
    commandPolicy,
  });
  const dmAccess = signalDecisionFromIngress({
    ingress: ingressBundle.dm,
    isGroup: false,
    dmPolicy: params.dmPolicy,
    groupPolicy: params.groupPolicy,
    effectiveAllowFrom,
    effectiveGroupAllowFrom,
  });
  const groupAccess = signalDecisionFromIngress({
    ingress: ingressBundle.group,
    isGroup: true,
    dmPolicy: params.dmPolicy,
    groupPolicy: params.groupPolicy,
    effectiveAllowFrom,
    effectiveGroupAllowFrom,
  });
  const resolveAccessDecision = (isGroup: boolean) => (isGroup ? groupAccess : dmAccess);
  const resolveCommandAccess = (isGroup: boolean) =>
    commandAccessFromIngress(isGroup ? ingressBundle.groupCommand : ingressBundle.dmCommand);
  return {
    resolveAccessDecision,
    resolveCommandAccess,
    isGroupAllowed: isSenderOrGroupAllowed,
    dmAccess,
    effectiveDmAllow: effectiveAllowFrom,
    effectiveGroupAllow: effectiveGroupAllowFrom,
  };
}

export async function handleSignalDirectMessageAccess(params: {
  dmPolicy: SignalDmPolicy;
  dmAccessDecision: "allow" | "block" | "pairing";
  senderId: string;
  senderIdLine: string;
  senderDisplay: string;
  senderName?: string;
  accountId: string;
  sendPairingReply: (text: string) => Promise<void>;
  log: (message: string) => void;
}): Promise<boolean> {
  if (params.dmAccessDecision === "allow") {
    return true;
  }
  if (params.dmAccessDecision === "block") {
    if (params.dmPolicy !== "disabled") {
      params.log(`Blocked signal sender ${params.senderDisplay} (dmPolicy=${params.dmPolicy})`);
    }
    return false;
  }
  if (params.dmPolicy === "pairing") {
    await createChannelPairingChallengeIssuer({
      channel: "signal",
      upsertPairingRequest: async ({ id, meta }) =>
        await upsertChannelPairingRequest({
          channel: "signal",
          id,
          accountId: params.accountId,
          meta,
        }),
    })({
      senderId: params.senderId,
      senderIdLine: params.senderIdLine,
      meta: { name: params.senderName },
      sendPairingReply: params.sendPairingReply,
      onCreated: () => {
        params.log(`signal pairing request sender=${params.senderId}`);
      },
      onReplyError: (err) => {
        params.log(`signal pairing reply failed for ${params.senderId}: ${String(err)}`);
      },
    });
  }
  return false;
}
