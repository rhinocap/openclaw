import {
  createChannelIngressPluginId,
  createChannelIngressStringAdapter,
  createChannelIngressSubject,
  decideChannelIngress,
  findChannelIngressCommandGate,
  findChannelIngressSenderGate,
  resolveChannelIngressState,
  type ChannelIngressDecision,
  type ChannelIngressPolicyInput,
  type IngressReasonCode,
} from "openclaw/plugin-sdk/channel-ingress";
import type { OpenClawConfig } from "openclaw/plugin-sdk/config-types";
import type { GroupPolicy, SenderGroupAccessDecision } from "openclaw/plugin-sdk/group-access";
import { normalizeZaloAllowEntry, resolveZaloRuntimeGroupPolicy } from "./group-access.js";
import type { ZaloAccountConfig } from "./types.js";

type ZaloDmPolicy = "open" | "pairing" | "allowlist" | "disabled";
type ZaloAccessDecision = "allow" | "block" | "pairing";
type ZaloCommandRuntime = {
  shouldComputeCommandAuthorized: (rawBody: string, cfg: OpenClawConfig) => boolean;
};

const ZALO_CHANNEL_ID = createChannelIngressPluginId("zalo");
const zaloIngressAdapter = createChannelIngressStringAdapter({
  normalizeEntry: normalizeZaloAllowEntry,
  normalizeSubject: normalizeZaloAllowEntry,
  sensitivity: "pii",
  resolveEntryId: ({ index }) => `zalo-entry-${index + 1}`,
});

function stringEntries(entries: Array<string | number> | undefined): string[] {
  return (entries ?? []).map((entry) => String(entry));
}

function effectiveGroupAllowFrom(params: {
  allowFrom: string[];
  groupAllowFrom: string[];
}): string[] {
  return params.groupAllowFrom.length > 0 ? params.groupAllowFrom : params.allowFrom;
}

async function readZaloPairingStore(params: {
  isGroup: boolean;
  dmPolicy: ZaloDmPolicy;
  readAllowFromStore: () => Promise<string[]>;
}): Promise<string[]> {
  if (params.isGroup || params.dmPolicy === "allowlist" || params.dmPolicy === "open") {
    return [];
  }
  return await params.readAllowFromStore().catch(() => []);
}

function findSenderGateReason(
  decision: ChannelIngressDecision,
  isGroup: boolean,
): IngressReasonCode {
  return findChannelIngressSenderGate(decision, { isGroup })?.reasonCode ?? decision.reasonCode;
}

function mapZaloGroupReason(reasonCode: IngressReasonCode): SenderGroupAccessDecision["reason"] {
  switch (reasonCode) {
    case "group_policy_open":
    case "group_policy_allowed":
      return "allowed";
    case "group_policy_disabled":
      return "disabled";
    case "group_policy_empty_allowlist":
      return "empty_allowlist";
    default:
      return "sender_not_allowlisted";
  }
}

function groupAccessFromIngress(params: {
  decision: ChannelIngressDecision;
  groupPolicy: GroupPolicy;
  providerMissingFallbackApplied: boolean;
}): SenderGroupAccessDecision {
  const reason = mapZaloGroupReason(findSenderGateReason(params.decision, true));
  return {
    allowed: reason === "allowed" && params.decision.decision === "allow",
    groupPolicy: params.groupPolicy,
    providerMissingFallbackApplied: params.providerMissingFallbackApplied,
    reason,
  };
}

function accessDecisionFromIngress(decision: ChannelIngressDecision): ZaloAccessDecision {
  if (decision.decision === "allow") {
    return "allow";
  }
  return decision.admission === "pairing-required" ? "pairing" : "block";
}

function commandAuthorizedFromIngress(params: {
  decision: ChannelIngressDecision;
  shouldComputeAuth: boolean;
}): boolean | undefined {
  if (!params.shouldComputeAuth) {
    return undefined;
  }
  return findChannelIngressCommandGate(params.decision)?.allowed === true;
}

export async function resolveZaloMessageIngressAccess(params: {
  accountId: string;
  cfg: OpenClawConfig;
  accountConfig: ZaloAccountConfig;
  providerConfigPresent: boolean;
  defaultGroupPolicy?: GroupPolicy;
  isGroup: boolean;
  chatId: string;
  senderId: string;
  rawBody: string;
  readAllowFromStore: () => Promise<string[]>;
  commandRuntime: ZaloCommandRuntime;
}): Promise<{
  decision: ChannelIngressDecision;
  access: { decision: ZaloAccessDecision; reasonCode: IngressReasonCode };
  groupAccess?: SenderGroupAccessDecision;
  commandAuthorized: boolean | undefined;
}> {
  const dmPolicy = params.accountConfig.dmPolicy ?? "pairing";
  const allowFrom = stringEntries(params.accountConfig.allowFrom);
  const configuredGroupAllowFrom = stringEntries(params.accountConfig.groupAllowFrom);
  const groupAllowFrom = effectiveGroupAllowFrom({
    allowFrom,
    groupAllowFrom: configuredGroupAllowFrom,
  });
  const { groupPolicy, providerMissingFallbackApplied } = resolveZaloRuntimeGroupPolicy({
    providerConfigPresent: params.providerConfigPresent,
    groupPolicy: params.accountConfig.groupPolicy,
    defaultGroupPolicy: params.defaultGroupPolicy,
  });
  const storeAllowFrom = await readZaloPairingStore({
    isGroup: params.isGroup,
    dmPolicy,
    readAllowFromStore: params.readAllowFromStore,
  });
  const shouldComputeAuth = params.commandRuntime.shouldComputeCommandAuthorized(
    params.rawBody,
    params.cfg,
  );
  const commandOwner = params.isGroup ? allowFrom : [...allowFrom, ...storeAllowFrom];
  const policy: ChannelIngressPolicyInput = {
    dmPolicy,
    groupPolicy,
    groupAllowFromFallbackToAllowFrom: false,
    ...(shouldComputeAuth
      ? {
          command: {
            useAccessGroups: params.cfg.commands?.useAccessGroups !== false,
            allowTextCommands: false,
            hasControlCommand: true,
            modeWhenAccessGroupsOff: "allow",
          },
        }
      : {}),
  };
  const state = await resolveChannelIngressState({
    channelId: ZALO_CHANNEL_ID,
    accountId: params.accountId,
    subject: createChannelIngressSubject({
      opaqueId: "zalo-user-id",
      value: params.senderId,
      sensitivity: "pii",
    }),
    conversation: {
      kind: params.isGroup ? "group" : "direct",
      id: params.chatId,
    },
    adapter: zaloIngressAdapter,
    accessGroups: params.cfg.accessGroups,
    event: {
      kind: "message",
      authMode: "inbound",
      mayPair: !params.isGroup,
    },
    allowlists: {
      dm: allowFrom,
      group: groupAllowFrom,
      pairingStore: storeAllowFrom,
      commandOwner,
      commandGroup: groupAllowFrom,
    },
  });
  const decision = decideChannelIngress(state, policy);
  return {
    decision,
    access: {
      decision: accessDecisionFromIngress(decision),
      reasonCode: findSenderGateReason(decision, params.isGroup),
    },
    groupAccess: params.isGroup
      ? groupAccessFromIngress({
          decision,
          groupPolicy,
          providerMissingFallbackApplied,
        })
      : undefined,
    commandAuthorized: commandAuthorizedFromIngress({
      decision,
      shouldComputeAuth,
    }),
  };
}
