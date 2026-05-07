import type { OpenClawConfig } from "openclaw/plugin-sdk/config-types";
import { describe, expect, it } from "vitest";
import { normalizeAllowFrom } from "./bot-access.js";
import { resolveTelegramCommandIngressAuthorization } from "./command-ingress.js";

async function authorize(params: {
  cfg?: OpenClawConfig;
  isGroup?: boolean;
  senderId?: string;
  dmAllow?: Array<string | number>;
  groupAllow?: Array<string | number>;
  ownerList?: string[];
  senderIsOwner?: boolean;
  useAccessGroups?: boolean;
  allowTextCommands?: boolean;
  hasControlCommand?: boolean;
  modeWhenAccessGroupsOff?: "allow" | "deny" | "configured";
  includeDmAllowForGroupCommands?: boolean;
}) {
  return await resolveTelegramCommandIngressAuthorization({
    accountId: "default",
    cfg: params.cfg ?? ({} as OpenClawConfig),
    dmPolicy: "pairing",
    isGroup: params.isGroup ?? false,
    chatId: params.isGroup ? -100999 : 1234,
    resolvedThreadId: params.isGroup ? 42 : undefined,
    senderId: params.senderId ?? "200",
    effectiveDmAllow: normalizeAllowFrom(params.dmAllow ?? []),
    effectiveGroupAllow: normalizeAllowFrom(params.groupAllow ?? []),
    ownerAccess: {
      ownerList: params.ownerList ?? [],
      senderIsOwner: params.senderIsOwner ?? false,
    },
    useAccessGroups: params.useAccessGroups ?? true,
    allowTextCommands: params.allowTextCommands,
    hasControlCommand: params.hasControlCommand,
    modeWhenAccessGroupsOff: params.modeWhenAccessGroupsOff,
    includeDmAllowForGroupCommands: params.includeDmAllowForGroupCommands,
  });
}

describe("telegram command ingress authorization", () => {
  it("authorizes direct commands from effective DM allowlist entries", async () => {
    await expect(authorize({ dmAllow: ["200"] })).resolves.toMatchObject({
      commandAuthorized: true,
    });
  });

  it("authorizes group commands from effective group allowlist entries", async () => {
    await expect(
      authorize({
        isGroup: true,
        dmAllow: [],
        groupAllow: ["200"],
      }),
    ).resolves.toMatchObject({ commandAuthorized: true });
  });

  it("keeps account allowFrom as a group command owner source", async () => {
    await expect(
      authorize({
        isGroup: true,
        dmAllow: ["200"],
        groupAllow: [],
      }),
    ).resolves.toMatchObject({ commandAuthorized: true });
  });

  it("can keep text group commands scoped to group allowlists only", async () => {
    await expect(
      authorize({
        isGroup: true,
        dmAllow: ["200"],
        groupAllow: [],
        includeDmAllowForGroupCommands: false,
      }),
    ).resolves.toMatchObject({ commandAuthorized: false });
  });

  it("does not let paired DM store entries authorize group commands when omitted from the DM list", async () => {
    await expect(
      authorize({
        isGroup: true,
        dmAllow: [],
        groupAllow: [],
      }),
    ).resolves.toMatchObject({ commandAuthorized: false });
  });

  it("authorizes explicit command owners without requiring channel allowlists", async () => {
    await expect(authorize({ ownerList: ["200"], senderIsOwner: true })).resolves.toMatchObject({
      commandAuthorized: true,
    });
  });

  it("keeps configured-but-unmatched command owner lists denied", async () => {
    await expect(authorize({ ownerList: ["999"] })).resolves.toMatchObject({
      commandAuthorized: false,
    });
  });

  it("allows command fallback when access-group command gating is disabled and no source is configured", async () => {
    await expect(authorize({ useAccessGroups: false })).resolves.toMatchObject({
      commandAuthorized: true,
    });
  });

  it("can preserve text-command allow mode when access-group command gating is disabled", async () => {
    await expect(
      authorize({
        useAccessGroups: false,
        modeWhenAccessGroupsOff: "allow",
        dmAllow: ["999"],
      }),
    ).resolves.toMatchObject({
      commandAuthorized: true,
    });
  });

  it("blocks unauthorized text control commands", async () => {
    await expect(
      authorize({
        isGroup: true,
        useAccessGroups: true,
        allowTextCommands: true,
        hasControlCommand: true,
      }),
    ).resolves.toMatchObject({
      commandAuthorized: false,
      shouldBlockControlCommand: true,
    });
  });
});
