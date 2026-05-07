import {
  createChannelIngressPluginId,
  createChannelIngressStringAdapter,
  createChannelIngressSubject,
  decideChannelIngress,
  findChannelIngressCommandGate,
  findChannelIngressSenderGate,
  resolveChannelIngressState,
  type ChannelIngressDecision,
  type ChannelIngressEventInput,
  type IngressReasonCode,
  type RouteGateFacts,
} from "openclaw/plugin-sdk/channel-ingress";
import type { DmPolicy, GroupPolicy, OpenClawConfig } from "openclaw/plugin-sdk/config-types";
import {
  resolveAllowlistProviderRuntimeGroupPolicy,
  resolveDefaultGroupPolicy,
} from "openclaw/plugin-sdk/runtime-group-policy";
import { firstDefined, normalizeLineAllowEntry } from "./bot-access.js";
import type { LineAccountConfig, LineGroupConfig } from "./types.js";

type LineAccessDecision = "allow" | "block" | "pairing";

const LINE_CHANNEL_ID = createChannelIngressPluginId("line");
const lineIngressAdapter = createChannelIngressStringAdapter({
  normalizeEntry: normalizeLineIngressEntry,
  normalizeSubject: normalizeLineIngressEntry,
  sensitivity: "pii",
  resolveEntryId: ({ index }) => `line-entry-${index + 1}`,
});

function normalizeLineIngressEntry(value: string): string | null {
  const normalized = normalizeLineAllowEntry(value);
  return normalized || null;
}

function stringEntries(entries: Array<string | number> | undefined): string[] {
  return (entries ?? []).map((entry) => String(entry));
}

async function readLinePairingStore(params: {
  isGroup: boolean;
  dmPolicy: DmPolicy;
  readAllowFromStore: () => Promise<string[]>;
}): Promise<string[]> {
  if (params.isGroup || params.dmPolicy === "allowlist" || params.dmPolicy === "open") {
    return [];
  }
  return await params.readAllowFromStore().catch(() => []);
}

function resolveLineGroupAllowFrom(params: {
  accountConfig: LineAccountConfig;
  groupConfig?: LineGroupConfig;
}): string[] {
  const fallbackGroupAllowFrom = params.accountConfig.allowFrom?.length
    ? params.accountConfig.allowFrom
    : undefined;
  return stringEntries(
    firstDefined(
      params.groupConfig?.allowFrom,
      params.accountConfig.groupAllowFrom,
      fallbackGroupAllowFrom,
    ),
  );
}

function resolveIngressGroupPolicy(params: {
  groupPolicy: GroupPolicy;
  groupConfig?: LineGroupConfig;
}): GroupPolicy {
  if (params.groupPolicy === "disabled") {
    return "disabled";
  }
  return params.groupConfig?.allowFrom !== undefined ? "allowlist" : params.groupPolicy;
}

function routeFactsForLineGroupConfig(params: {
  isGroup: boolean;
  groupConfig?: LineGroupConfig;
}): RouteGateFacts[] {
  if (!params.isGroup || params.groupConfig?.enabled !== false) {
    return [];
  }
  return [
    {
      id: "line:group-config",
      kind: "route",
      gate: "disabled",
      effect: "block-dispatch",
      precedence: 0,
      senderPolicy: "inherit",
    },
  ];
}

function findSenderGateReason(
  decision: ChannelIngressDecision,
  isGroup: boolean,
): IngressReasonCode {
  return findChannelIngressSenderGate(decision, { isGroup })?.reasonCode ?? decision.reasonCode;
}

function accessDecisionFromIngress(decision: ChannelIngressDecision): LineAccessDecision {
  if (decision.decision === "allow") {
    return "allow";
  }
  return decision.admission === "pairing-required" ? "pairing" : "block";
}

function commandAuthorizedFromIngress(decision: ChannelIngressDecision): boolean {
  return findChannelIngressCommandGate(decision)?.allowed === true;
}

export async function resolveLineIngressAccess(params: {
  cfg: OpenClawConfig;
  accountId: string;
  accountConfig: LineAccountConfig;
  providerConfigPresent: boolean;
  isGroup: boolean;
  conversationId: string;
  senderId: string;
  hasControlCommand: boolean;
  eventKind: ChannelIngressEventInput["kind"];
  groupConfig?: LineGroupConfig;
  readAllowFromStore: () => Promise<string[]>;
}): Promise<{
  ingress: ChannelIngressDecision;
  decision: LineAccessDecision;
  reasonCode: IngressReasonCode;
  commandAuthorized: boolean;
  groupPolicy: GroupPolicy;
  providerMissingFallbackApplied: boolean;
}> {
  const dmPolicy = params.accountConfig.dmPolicy ?? "pairing";
  const allowFrom = stringEntries(params.accountConfig.allowFrom);
  const storeAllowFrom = await readLinePairingStore({
    isGroup: params.isGroup,
    dmPolicy,
    readAllowFromStore: params.readAllowFromStore,
  });
  const { groupPolicy: runtimeGroupPolicy, providerMissingFallbackApplied } =
    resolveAllowlistProviderRuntimeGroupPolicy({
      providerConfigPresent: params.providerConfigPresent,
      groupPolicy: params.accountConfig.groupPolicy,
      defaultGroupPolicy: resolveDefaultGroupPolicy(params.cfg),
    });
  const groupPolicy = resolveIngressGroupPolicy({
    groupPolicy: runtimeGroupPolicy,
    groupConfig: params.groupConfig,
  });
  const groupAllowFrom = resolveLineGroupAllowFrom({
    accountConfig: params.accountConfig,
    groupConfig: params.groupConfig,
  });
  const state = await resolveChannelIngressState({
    channelId: LINE_CHANNEL_ID,
    accountId: params.accountId,
    subject: createChannelIngressSubject({
      opaqueId: "line-user-id",
      value: params.senderId,
      sensitivity: "pii",
    }),
    conversation: {
      kind: params.isGroup ? "group" : "direct",
      id: params.conversationId,
    },
    adapter: lineIngressAdapter,
    accessGroups: params.cfg.accessGroups,
    routeFacts: routeFactsForLineGroupConfig({
      isGroup: params.isGroup,
      groupConfig: params.groupConfig,
    }),
    event: {
      kind: params.eventKind,
      authMode: "inbound",
      mayPair: !params.isGroup,
    },
    allowlists: {
      dm: allowFrom,
      group: groupAllowFrom,
      pairingStore: storeAllowFrom,
      commandOwner: params.isGroup ? [] : [...allowFrom, ...storeAllowFrom],
      commandGroup: params.isGroup ? groupAllowFrom : [],
    },
  });
  const ingress = decideChannelIngress(state, {
    dmPolicy,
    groupPolicy,
    groupAllowFromFallbackToAllowFrom: false,
    command: {
      useAccessGroups: params.cfg.commands?.useAccessGroups !== false,
      allowTextCommands: false,
      hasControlCommand: params.hasControlCommand,
      modeWhenAccessGroupsOff: "allow",
    },
  });
  return {
    ingress,
    decision: accessDecisionFromIngress(ingress),
    reasonCode: findSenderGateReason(ingress, params.isGroup),
    commandAuthorized: commandAuthorizedFromIngress(ingress),
    groupPolicy,
    providerMissingFallbackApplied,
  };
}
