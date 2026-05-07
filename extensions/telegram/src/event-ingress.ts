import {
  decideChannelIngress,
  resolveChannelIngressState,
  type ChannelIngressEventInput,
  type IngressReasonCode,
} from "openclaw/plugin-sdk/channel-ingress";
import type { DmPolicy } from "openclaw/plugin-sdk/config-types";
import type { NormalizedAllowFrom } from "./bot-access.js";
import {
  createTelegramIngressSubject,
  telegramAllowEntries,
  TELEGRAM_CHANNEL_ID,
  telegramIngressAdapter,
} from "./ingress.js";

export async function resolveTelegramEventIngressAuthorization(params: {
  accountId: string;
  dmPolicy: DmPolicy;
  isGroup: boolean;
  chatId: number;
  resolvedThreadId?: number;
  senderId: string;
  effectiveDmAllow: NormalizedAllowFrom;
  effectiveGroupAllow: NormalizedAllowFrom;
  enforceGroupAuthorization: boolean;
  eventKind: Extract<ChannelIngressEventInput["kind"], "reaction" | "button">;
}): Promise<{ allowed: boolean; reasonCode: IngressReasonCode }> {
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
    event: {
      kind: params.eventKind,
      authMode: "inbound",
      mayPair: false,
    },
    allowlists: {
      dm: telegramAllowEntries(params.effectiveDmAllow),
      group: params.enforceGroupAuthorization
        ? telegramAllowEntries(params.effectiveGroupAllow)
        : [],
    },
  });
  const decision = decideChannelIngress(state, {
    dmPolicy: params.dmPolicy,
    groupPolicy: params.enforceGroupAuthorization ? "allowlist" : "open",
  });
  return {
    allowed: decision.decision === "allow",
    reasonCode: decision.reasonCode,
  };
}
