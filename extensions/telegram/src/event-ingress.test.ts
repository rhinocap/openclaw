import { describe, expect, it } from "vitest";
import { normalizeAllowFrom } from "./bot-access.js";
import { resolveTelegramEventIngressAuthorization } from "./event-ingress.js";

async function authorize(params: {
  dmPolicy?: "open" | "allowlist" | "pairing" | "disabled";
  isGroup?: boolean;
  senderId?: string;
  dmAllow?: Array<string | number>;
  groupAllow?: Array<string | number>;
  enforceGroupAuthorization?: boolean;
}) {
  return await resolveTelegramEventIngressAuthorization({
    accountId: "default",
    dmPolicy: params.dmPolicy ?? "open",
    isGroup: params.isGroup ?? false,
    chatId: params.isGroup ? -100999 : 1234,
    resolvedThreadId: params.isGroup ? 42 : undefined,
    senderId: params.senderId ?? "9",
    effectiveDmAllow: normalizeAllowFrom(params.dmAllow ?? []),
    effectiveGroupAllow: normalizeAllowFrom(params.groupAllow ?? []),
    enforceGroupAuthorization: params.enforceGroupAuthorization ?? false,
    eventKind: "reaction",
  });
}

describe("telegram event ingress authorization", () => {
  it("allows direct events when open DM policy has wildcard access", async () => {
    await expect(authorize({ dmAllow: ["*"] })).resolves.toMatchObject({
      allowed: true,
    });
  });

  it("blocks direct events when open DM policy is constrained and sender does not match", async () => {
    await expect(authorize({ dmAllow: ["12345"] })).resolves.toMatchObject({
      allowed: false,
      reasonCode: "dm_policy_not_allowlisted",
    });
  });

  it("allows pairing-mode direct events from effective paired allowlist entries", async () => {
    await expect(authorize({ dmPolicy: "pairing", dmAllow: ["9"] })).resolves.toMatchObject({
      allowed: true,
    });
  });

  it("blocks pairing-mode direct events instead of requesting pairing", async () => {
    await expect(authorize({ dmPolicy: "pairing", dmAllow: [] })).resolves.toMatchObject({
      allowed: false,
      reasonCode: "event_pairing_not_allowed",
    });
  });

  it("lets caller-owned group policy stand when group event authorization is not requested", async () => {
    await expect(
      authorize({
        isGroup: true,
        groupAllow: [],
        enforceGroupAuthorization: false,
      }),
    ).resolves.toMatchObject({ allowed: true });
  });

  it("enforces group sender authorization when requested", async () => {
    await expect(
      authorize({
        isGroup: true,
        groupAllow: ["12345"],
        enforceGroupAuthorization: true,
      }),
    ).resolves.toMatchObject({
      allowed: false,
      reasonCode: "group_policy_not_allowlisted",
    });
  });
});
