import {
  createChannelIngressPluginId,
  createChannelIngressMultiIdentifierAdapter,
  decideChannelIngress,
  findChannelIngressCommandGate,
  resolveChannelIngressState,
  type AccessGroupMembershipFact,
  type ChannelIngressAdapterEntry,
  type ChannelIngressEventInput,
  type ChannelIngressIdentifierKind,
  type ChannelIngressPolicyInput,
  type ChannelIngressSubject,
} from "openclaw/plugin-sdk/channel-ingress";
import { parseAccessGroupAllowFromEntry } from "openclaw/plugin-sdk/command-auth";
import type { OpenClawConfig } from "openclaw/plugin-sdk/config-types";
import type { AccessGroupConfig } from "openclaw/plugin-sdk/config-types";
import { logVerbose } from "openclaw/plugin-sdk/runtime-env";
import {
  readStoreAllowFromForDmPolicy,
  type DmGroupAccessDecision,
} from "openclaw/plugin-sdk/security-runtime";
import type { RequestClient } from "../internal/discord.js";
import { canViewDiscordGuildChannel } from "../send.permissions.js";
import { normalizeDiscordAllowList, resolveDiscordAllowListMatch } from "./allow-list.js";

const DISCORD_ALLOW_LIST_PREFIXES = ["discord:", "user:", "pk:"];
const DISCORD_CHANNEL_ID = createChannelIngressPluginId("discord");
const DISCORD_USER_ID_KIND = "stable-id" satisfies ChannelIngressIdentifierKind;
const DISCORD_USER_NAME_KIND = "username" satisfies ChannelIngressIdentifierKind;

export type DiscordDmPolicy = "open" | "pairing" | "allowlist" | "disabled";

export type DiscordDmCommandAccess = {
  decision: DmGroupAccessDecision;
  reason: string;
  commandAuthorized: boolean;
  allowMatch: ReturnType<typeof resolveDiscordAllowListMatch> | { allowed: false };
};

export type DiscordTextCommandAccess = {
  commandAuthorized: boolean;
  shouldBlockControlCommand: boolean;
};

function resolveSenderAllowMatch(params: {
  allowEntries: string[];
  sender: { id: string; name?: string; tag?: string };
  allowNameMatching: boolean;
}) {
  const allowList = normalizeDiscordAllowList(params.allowEntries, DISCORD_ALLOW_LIST_PREFIXES);
  return allowList
    ? resolveDiscordAllowListMatch({
        allowList,
        candidate: params.sender,
        allowNameMatching: params.allowNameMatching,
      })
    : ({ allowed: false } as const);
}

function createDiscordIngressAdapterEntry(params: {
  index: number;
  suffix: string;
  kind: ChannelIngressIdentifierKind;
  value: string;
  dangerous?: boolean;
}): ChannelIngressAdapterEntry {
  return {
    opaqueEntryId: `discord-entry-${params.index + 1}:${params.suffix}`,
    kind: params.kind,
    value: params.value,
    dangerous: params.dangerous,
  };
}

function normalizeDiscordIngressEntry(entry: string, index: number): ChannelIngressAdapterEntry[] {
  const text = entry.trim();
  if (!text) {
    return [];
  }
  if (text === "*") {
    return [
      createDiscordIngressAdapterEntry({
        index,
        suffix: "wildcard",
        kind: DISCORD_USER_ID_KIND,
        value: "*",
      }),
    ];
  }
  const maybeId = text.replace(/^<@!?/, "").replace(/>$/, "");
  if (/^\d+$/.test(maybeId)) {
    return [
      createDiscordIngressAdapterEntry({
        index,
        suffix: "id",
        kind: DISCORD_USER_ID_KIND,
        value: maybeId,
      }),
    ];
  }
  const prefix = DISCORD_ALLOW_LIST_PREFIXES.find((entryPrefix) => text.startsWith(entryPrefix));
  if (prefix) {
    const candidate = text.slice(prefix.length).trim();
    return candidate
      ? [
          createDiscordIngressAdapterEntry({
            index,
            suffix: "id",
            kind: DISCORD_USER_ID_KIND,
            value: candidate,
          }),
        ]
      : [];
  }
  const nameSlug = normalizeDiscordAllowList([text], DISCORD_ALLOW_LIST_PREFIXES)
    ?.names.values()
    .next().value;
  return typeof nameSlug === "string" && nameSlug
    ? [
        createDiscordIngressAdapterEntry({
          index,
          suffix: "name",
          kind: DISCORD_USER_NAME_KIND,
          value: nameSlug,
          dangerous: true,
        }),
      ]
    : [];
}

const discordDmIngressAdapter = createChannelIngressMultiIdentifierAdapter({
  normalizeEntry: normalizeDiscordIngressEntry,
});

function createDiscordDmIngressSubject(sender: {
  id: string;
  name?: string;
  tag?: string;
}): ChannelIngressSubject {
  const identifiers: ChannelIngressSubject["identifiers"] = [
    {
      opaqueId: "discord-user-id",
      kind: DISCORD_USER_ID_KIND,
      value: sender.id,
    },
  ];
  for (const [opaqueId, value] of [
    ["discord-user-name", sender.name],
    ["discord-user-tag", sender.tag],
  ] as const) {
    const nameSlug = value
      ? normalizeDiscordAllowList([value], DISCORD_ALLOW_LIST_PREFIXES)?.names.values().next().value
      : undefined;
    if (typeof nameSlug === "string" && nameSlug) {
      identifiers.push({
        opaqueId,
        kind: DISCORD_USER_NAME_KIND,
        value: nameSlug,
        dangerous: true,
      });
    }
  }
  return { identifiers };
}

function uniqueAccessGroupNames(lists: readonly string[][]): string[] {
  return Array.from(
    new Set(
      lists
        .flat()
        .map((entry) => parseAccessGroupAllowFromEntry(entry))
        .filter((entry): entry is string => entry != null),
    ),
  );
}

function createDiscordDynamicAccessGroupResolver(params: {
  cfg: OpenClawConfig;
  token?: string;
  rest?: RequestClient;
}): (lookup: {
  group: AccessGroupConfig;
  accountId: string;
  senderId: string;
}) => Promise<boolean> {
  return async ({ group, accountId, senderId }) => {
    if (group.type !== "discord.channelAudience") {
      return false;
    }
    const membership = group.membership ?? "canViewChannel";
    if (membership !== "canViewChannel") {
      return false;
    }
    return await canViewDiscordGuildChannel(group.guildId, group.channelId, senderId, {
      cfg: params.cfg,
      accountId,
      token: params.token,
      rest: params.rest,
    });
  };
}

async function resolveDiscordDynamicAccessGroupMembershipFacts(params: {
  cfg?: OpenClawConfig;
  allowlists: readonly string[][];
  accountId: string;
  sender: { id: string };
  token?: string;
  rest?: RequestClient;
}): Promise<AccessGroupMembershipFact[]> {
  const accessGroups = params.cfg?.accessGroups;
  if (!accessGroups || !params.cfg) {
    return [];
  }
  const resolveMembership = createDiscordDynamicAccessGroupResolver({
    cfg: params.cfg,
    token: params.token,
    rest: params.rest,
  });
  const facts: AccessGroupMembershipFact[] = [];
  for (const groupName of uniqueAccessGroupNames(params.allowlists)) {
    const group = accessGroups[groupName];
    if (!group || group.type === "message.senders") {
      continue;
    }
    if (group.type !== "discord.channelAudience") {
      facts.push({
        kind: "unsupported",
        groupName,
        source: "dynamic",
        reasonCode: "access_group_unsupported",
      });
      continue;
    }
    try {
      const matched = await resolveMembership({
        group,
        accountId: params.accountId,
        senderId: params.sender.id,
      });
      facts.push(
        matched
          ? {
              kind: "matched",
              groupName,
              source: "dynamic",
              matchedEntryIds: [`discord-access-group-${facts.length + 1}`],
            }
          : {
              kind: "not-matched",
              groupName,
              source: "dynamic",
            },
      );
    } catch (err) {
      logVerbose(
        `discord: accessGroup:${groupName} lookup failed for user ${params.sender.id}: ${String(err)}`,
      );
      facts.push({
        kind: "failed",
        groupName,
        source: "dynamic",
        reasonCode: "access_group_failed",
      });
    }
  }
  return facts;
}

function resolveCompatibilityAllowMatch(params: {
  allowEntries: string[];
  sender: { id: string; name?: string; tag?: string };
  allowNameMatching: boolean;
  ingressMatched: boolean;
  wildcardMatched: boolean;
}): DiscordDmCommandAccess["allowMatch"] {
  const directMatch = resolveSenderAllowMatch({
    allowEntries: params.allowEntries,
    sender: params.sender,
    allowNameMatching: params.allowNameMatching,
  });
  if (directMatch.allowed) {
    return directMatch;
  }
  if (!params.ingressMatched) {
    return { allowed: false };
  }
  return {
    allowed: true,
    matchKey: params.wildcardMatched ? "*" : "access-group",
    matchSource: params.wildcardMatched ? "wildcard" : "id",
  };
}

function resolveDiscordDmAccessReason(params: {
  dmPolicy: DiscordDmPolicy;
  decision: DmGroupAccessDecision;
  reasonCode: string;
}): string {
  if (params.reasonCode === "dm_policy_disabled") {
    return "dmPolicy=disabled";
  }
  if (params.reasonCode === "dm_policy_open") {
    return "dmPolicy=open";
  }
  if (params.reasonCode === "dm_policy_allowlisted") {
    return `dmPolicy=${params.dmPolicy} (allowlisted)`;
  }
  if (params.reasonCode === "dm_policy_pairing_required") {
    return "dmPolicy=pairing (not allowlisted)";
  }
  if (params.dmPolicy === "open") {
    return "dmPolicy=open (not allowlisted)";
  }
  return params.decision === "pairing"
    ? "dmPolicy=pairing (not allowlisted)"
    : `dmPolicy=${params.dmPolicy} (not allowlisted)`;
}

export async function resolveDiscordDmCommandAccess(params: {
  accountId: string;
  dmPolicy: DiscordDmPolicy;
  configuredAllowFrom: string[];
  sender: { id: string; name?: string; tag?: string };
  allowNameMatching: boolean;
  useAccessGroups: boolean;
  cfg?: OpenClawConfig;
  token?: string;
  rest?: RequestClient;
  readStoreAllowFrom?: () => Promise<string[]>;
  eventKind?: ChannelIngressEventInput["kind"];
}): Promise<DiscordDmCommandAccess> {
  const storeAllowFrom = params.readStoreAllowFrom
    ? params.dmPolicy === "open"
      ? []
      : await params.readStoreAllowFrom().catch(() => [])
    : await readStoreAllowFromForDmPolicy({
        provider: "discord",
        accountId: params.accountId,
        dmPolicy: params.dmPolicy,
        shouldRead: params.dmPolicy !== "open",
      });
  const commandAllowFrom = [...params.configuredAllowFrom, ...storeAllowFrom];
  const accessGroupMembership = await resolveDiscordDynamicAccessGroupMembershipFacts({
    cfg: params.cfg,
    allowlists: [params.configuredAllowFrom, storeAllowFrom, commandAllowFrom],
    accountId: params.accountId,
    sender: params.sender,
    token: params.token,
    rest: params.rest,
  });
  const ingressState = await resolveChannelIngressState({
    channelId: DISCORD_CHANNEL_ID,
    accountId: params.accountId,
    subject: createDiscordDmIngressSubject(params.sender),
    conversation: {
      kind: "direct",
      id: params.sender.id,
    },
    adapter: discordDmIngressAdapter,
    accessGroups: params.cfg?.accessGroups,
    accessGroupMembership,
    event: {
      kind: params.eventKind ?? "native-command",
      authMode: "inbound",
      mayPair: true,
    },
    allowlists: {
      dm: params.configuredAllowFrom,
      pairingStore: storeAllowFrom,
      commandOwner: commandAllowFrom,
    },
  });
  const policy: ChannelIngressPolicyInput = {
    dmPolicy: params.dmPolicy,
    groupPolicy: "disabled",
    mutableIdentifierMatching: params.allowNameMatching ? "enabled" : "disabled",
    command: {
      useAccessGroups: params.useAccessGroups,
      allowTextCommands: false,
      hasControlCommand: false,
      modeWhenAccessGroupsOff: "configured",
    },
  };
  const decision = decideChannelIngress(ingressState, policy);
  const commandGate = findChannelIngressCommandGate(decision);
  const senderMatched =
    ingressState.allowlists.dm.match.matched || ingressState.allowlists.pairingStore.match.matched;
  const allowMatch = resolveCompatibilityAllowMatch({
    allowEntries: commandAllowFrom,
    sender: params.sender,
    allowNameMatching: params.allowNameMatching,
    ingressMatched: senderMatched,
    wildcardMatched: ingressState.allowlists.dm.hasWildcard,
  });
  const dmDecision = decision.decision as DmGroupAccessDecision;
  return {
    decision: dmDecision,
    reason: resolveDiscordDmAccessReason({
      dmPolicy: params.dmPolicy,
      decision: dmDecision,
      reasonCode: decision.reasonCode,
    }),
    commandAuthorized: dmDecision === "allow" ? (commandGate?.allowed ?? false) : false,
    allowMatch,
  };
}

export async function resolveDiscordTextCommandAccess(params: {
  accountId: string;
  sender: { id: string; name?: string; tag?: string };
  ownerAllowFrom?: string[];
  memberAccessConfigured: boolean;
  memberAllowed: boolean;
  allowNameMatching: boolean;
  useAccessGroups: boolean;
  allowTextCommands: boolean;
  hasControlCommand: boolean;
  cfg?: OpenClawConfig;
  token?: string;
  rest?: RequestClient;
}): Promise<DiscordTextCommandAccess> {
  const ownerAllowFrom = (params.ownerAllowFrom ?? []).filter((entry) => entry.trim() !== "*");
  const memberAccessGroup = "discord-member-access";
  const commandGroup = params.memberAccessConfigured ? [`accessGroup:${memberAccessGroup}`] : [];
  const accessGroupMembership: AccessGroupMembershipFact[] = [
    ...(await resolveDiscordDynamicAccessGroupMembershipFacts({
      cfg: params.cfg,
      allowlists: [ownerAllowFrom],
      accountId: params.accountId,
      sender: params.sender,
      token: params.token,
      rest: params.rest,
    })),
    ...(params.memberAccessConfigured
      ? [
          params.memberAllowed
            ? ({
                kind: "matched",
                groupName: memberAccessGroup,
                source: "dynamic",
                matchedEntryIds: ["discord-member-access"],
              } satisfies AccessGroupMembershipFact)
            : ({
                kind: "not-matched",
                groupName: memberAccessGroup,
                source: "dynamic",
              } satisfies AccessGroupMembershipFact),
        ]
      : []),
  ];
  const ingressState = await resolveChannelIngressState({
    channelId: DISCORD_CHANNEL_ID,
    accountId: params.accountId,
    subject: createDiscordDmIngressSubject(params.sender),
    conversation: {
      kind: "group",
      id: "discord-command",
    },
    adapter: discordDmIngressAdapter,
    accessGroups: params.cfg?.accessGroups,
    accessGroupMembership,
    event: {
      kind: "message",
      authMode: "command",
      mayPair: false,
    },
    allowlists: {
      commandOwner: ownerAllowFrom,
      commandGroup,
    },
  });
  const decision = decideChannelIngress(ingressState, {
    dmPolicy: "allowlist",
    groupPolicy: "allowlist",
    mutableIdentifierMatching: params.allowNameMatching ? "enabled" : "disabled",
    command: {
      useAccessGroups: params.useAccessGroups,
      allowTextCommands: params.allowTextCommands,
      hasControlCommand: params.hasControlCommand,
      modeWhenAccessGroupsOff: "configured",
    },
  });
  const commandGate = findChannelIngressCommandGate(decision);
  return {
    commandAuthorized: commandGate?.allowed === true,
    shouldBlockControlCommand: commandGate?.command?.shouldBlockControlCommand === true,
  };
}
