import {
  decideChannelIngress,
  findChannelIngressCommandGate,
  resolveChannelIngressState,
  type ChannelIngressEventInput,
} from "openclaw/plugin-sdk/channel-ingress";
import type { DmPolicy, OpenClawConfig } from "openclaw/plugin-sdk/config-types";
import type { NormalizedAllowFrom } from "./bot-access.js";
import {
  createTelegramIngressSubject,
  telegramAllowEntries,
  TELEGRAM_CHANNEL_ID,
  telegramIngressAdapter,
} from "./ingress.js";

type TelegramOwnerCommandAccess = {
  ownerList: string[];
  senderIsOwner: boolean;
};

function ownerCommandEntries(params: {
  ownerAccess: TelegramOwnerCommandAccess;
  senderId: string;
}): string[] {
  if (params.ownerAccess.senderIsOwner) {
    return [params.senderId || "*"];
  }
  return params.ownerAccess.ownerList;
}

export async function resolveTelegramCommandIngressAuthorization(params: {
  accountId: string;
  cfg: OpenClawConfig;
  dmPolicy: DmPolicy;
  isGroup: boolean;
  chatId: string | number;
  resolvedThreadId?: number;
  senderId: string;
  effectiveDmAllow: NormalizedAllowFrom;
  effectiveGroupAllow: NormalizedAllowFrom;
  ownerAccess: TelegramOwnerCommandAccess;
  useAccessGroups: boolean;
  eventKind?: ChannelIngressEventInput["kind"];
  allowTextCommands?: boolean;
  hasControlCommand?: boolean;
  modeWhenAccessGroupsOff?: "allow" | "deny" | "configured";
  includeDmAllowForGroupCommands?: boolean;
}): Promise<{ commandAuthorized: boolean; shouldBlockControlCommand: boolean }> {
  const commandOwner = [
    ...(params.isGroup && params.includeDmAllowForGroupCommands === false
      ? []
      : telegramAllowEntries(params.effectiveDmAllow)),
    ...ownerCommandEntries({
      ownerAccess: params.ownerAccess,
      senderId: params.senderId,
    }),
  ];
  const state = await resolveChannelIngressState({
    channelId: TELEGRAM_CHANNEL_ID,
    accountId: params.accountId,
    subject: createTelegramIngressSubject(params.senderId),
    conversation: {
      kind: params.isGroup ? "group" : "direct",
      id: String(params.chatId),
      ...(params.resolvedThreadId != null ? { threadId: String(params.resolvedThreadId) } : {}),
    },
    adapter: telegramIngressAdapter,
    accessGroups: params.cfg.accessGroups,
    event: {
      kind: params.eventKind ?? "native-command",
      authMode: "command",
      mayPair: false,
    },
    allowlists: {
      commandOwner,
      commandGroup: params.isGroup ? telegramAllowEntries(params.effectiveGroupAllow) : [],
    },
  });
  const decision = decideChannelIngress(state, {
    dmPolicy: params.dmPolicy,
    groupPolicy: "allowlist",
    command: {
      useAccessGroups: params.useAccessGroups,
      allowTextCommands: params.allowTextCommands ?? false,
      hasControlCommand: params.hasControlCommand ?? false,
      modeWhenAccessGroupsOff: params.modeWhenAccessGroupsOff ?? "configured",
    },
  });
  const commandGate = findChannelIngressCommandGate(decision);
  return {
    commandAuthorized: commandGate?.allowed === true,
    shouldBlockControlCommand:
      commandGate?.command?.shouldBlockControlCommand ?? commandGate?.effect === "block-command",
  };
}
