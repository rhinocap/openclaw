import {
  createChannelIngressPluginId,
  createChannelIngressStringAdapter,
  createChannelIngressSubject,
} from "openclaw/plugin-sdk/channel-ingress";
import type { ChannelIngressSubject } from "openclaw/plugin-sdk/channel-ingress";
import type { NormalizedAllowFrom } from "./bot-access.js";

export const TELEGRAM_CHANNEL_ID = createChannelIngressPluginId("telegram");

export const telegramIngressAdapter = createChannelIngressStringAdapter();

export function createTelegramIngressSubject(senderId: string): ChannelIngressSubject {
  return createChannelIngressSubject({
    opaqueId: "telegram-user-id",
    value: senderId,
  });
}

export function telegramAllowEntries(allow: NormalizedAllowFrom): string[] {
  return [...(allow.hasWildcard ? ["*"] : []), ...allow.entries];
}
