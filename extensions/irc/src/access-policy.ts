import {
  createChannelIngressPluginId,
  createChannelIngressMultiIdentifierAdapter,
  decideChannelIngress,
  findChannelIngressCommandGate,
  resolveChannelIngressState,
  type ChannelIngressAdapterEntry,
  type ChannelIngressIdentifierKind,
  type ChannelIngressSubject,
} from "openclaw/plugin-sdk/channel-ingress";
import { normalizeLowercaseStringOrEmpty } from "openclaw/plugin-sdk/text-runtime";
import { buildIrcAllowlistCandidates, normalizeIrcAllowEntry } from "./normalize.js";
import type { IrcInboundMessage } from "./types.js";

const IRC_CHANNEL_ID = createChannelIngressPluginId("irc");
const IRC_NICK_KIND = "plugin:irc-nick" as const satisfies ChannelIngressIdentifierKind;

function isBareNick(value: string): boolean {
  return !value.includes("!") && !value.includes("@");
}

function createIrcAdapterEntry(params: {
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
    sensitivity: "pii",
  };
}

function normalizeIrcIngressEntry(entry: string, index: number): ChannelIngressAdapterEntry[] {
  const normalized = normalizeIrcAllowEntry(entry);
  if (!normalized) {
    return [];
  }
  if (normalized === "*") {
    return [
      createIrcAdapterEntry({
        index,
        kind: "stable-id",
        value: "*",
        suffix: "wildcard",
      }),
    ];
  }
  if (isBareNick(normalized)) {
    return [
      createIrcAdapterEntry({
        index,
        kind: IRC_NICK_KIND,
        value: normalized,
        suffix: "nick",
        dangerous: true,
      }),
    ];
  }
  return [
    createIrcAdapterEntry({
      index,
      kind: "stable-id",
      value: normalized,
      suffix: "id",
    }),
  ];
}

const ircIngressAdapter = createChannelIngressMultiIdentifierAdapter({
  normalizeEntry: normalizeIrcIngressEntry,
});

function createIrcIngressSubject(message: IrcInboundMessage): ChannelIngressSubject {
  const identifiers: ChannelIngressSubject["identifiers"] = [];
  for (const candidate of buildIrcAllowlistCandidates(message, { allowNameMatching: true })) {
    if (isBareNick(candidate)) {
      identifiers.push({
        opaqueId: "sender-nick",
        kind: IRC_NICK_KIND,
        value: normalizeLowercaseStringOrEmpty(candidate),
        dangerous: true,
        sensitivity: "pii",
      });
      continue;
    }
    identifiers.push({
      opaqueId: `sender-id-${identifiers.length + 1}`,
      kind: "stable-id",
      value: normalizeLowercaseStringOrEmpty(candidate),
      sensitivity: "pii",
    });
  }
  return { identifiers };
}

export async function resolveIrcCommandAccess(params: {
  accountId: string;
  message: IrcInboundMessage;
  effectiveAllowFrom: string[];
  effectiveGroupAllowFrom: string[];
  allowNameMatching: boolean;
  allowTextCommands: boolean;
  hasControlCommand: boolean;
  useAccessGroups: boolean;
}): Promise<{ commandAuthorized: boolean; shouldBlockControlCommand: boolean }> {
  const state = await resolveChannelIngressState({
    channelId: IRC_CHANNEL_ID,
    accountId: params.accountId,
    subject: createIrcIngressSubject(params.message),
    conversation: {
      kind: params.message.isGroup ? "group" : "direct",
      id: params.message.target,
    },
    adapter: ircIngressAdapter,
    event: {
      kind: "message",
      authMode: "command",
      mayPair: false,
    },
    allowlists: {
      commandOwner: params.message.isGroup ? [] : params.effectiveAllowFrom,
      commandGroup: params.message.isGroup ? params.effectiveGroupAllowFrom : [],
    },
  });
  const decision = decideChannelIngress(state, {
    dmPolicy: "allowlist",
    groupPolicy: "allowlist",
    mutableIdentifierMatching: params.allowNameMatching ? "enabled" : "disabled",
    command: {
      useAccessGroups: params.useAccessGroups,
      allowTextCommands: params.allowTextCommands,
      hasControlCommand: params.hasControlCommand,
    },
  });
  const commandGate = findChannelIngressCommandGate(decision);
  return {
    commandAuthorized: commandGate?.allowed === true,
    shouldBlockControlCommand: commandGate?.command?.shouldBlockControlCommand === true,
  };
}
