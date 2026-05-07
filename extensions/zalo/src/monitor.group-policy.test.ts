import type { OpenClawConfig } from "openclaw/plugin-sdk/config-types";
import { describe, expect, it, vi } from "vitest";
import { resolveZaloMessageIngressAccess } from "./access-policy.js";
import type { ZaloAccountConfig } from "./types.js";

async function resolveAccess(
  params: {
    cfg?: OpenClawConfig;
    accountConfig?: ZaloAccountConfig;
    providerConfigPresent?: boolean;
    defaultGroupPolicy?: "open" | "allowlist" | "disabled";
    isGroup?: boolean;
    senderId?: string;
    rawBody?: string;
    storeAllowFrom?: string[];
    shouldComputeCommandAuthorized?: boolean;
  } = {},
) {
  const readAllowFromStore = vi.fn(async () => params.storeAllowFrom ?? []);
  const result = await resolveZaloMessageIngressAccess({
    accountId: "default",
    cfg: params.cfg ?? ({} as OpenClawConfig),
    accountConfig: {
      dmPolicy: "pairing",
      groupPolicy: "allowlist",
      allowFrom: [],
      groupAllowFrom: [],
      ...params.accountConfig,
    },
    providerConfigPresent: params.providerConfigPresent ?? true,
    defaultGroupPolicy: params.defaultGroupPolicy ?? "open",
    isGroup: params.isGroup ?? true,
    chatId: "chat-1",
    senderId: params.senderId ?? "123",
    rawBody: params.rawBody ?? "hello",
    readAllowFromStore,
    commandRuntime: {
      shouldComputeCommandAuthorized: () => params.shouldComputeCommandAuthorized ?? false,
    },
  });
  return { result, readAllowFromStore };
}

describe("zalo shared ingress access policy", () => {
  it("blocks all group messages when policy is disabled", async () => {
    const { result } = await resolveAccess({
      accountConfig: {
        groupPolicy: "disabled",
        groupAllowFrom: ["zalo:123"],
      },
    });

    expect(result.groupAccess).toMatchObject({
      allowed: false,
      groupPolicy: "disabled",
      reason: "disabled",
    });
  });

  it("blocks group messages on allowlist policy with empty allowlist", async () => {
    const { result } = await resolveAccess({
      accountConfig: {
        groupPolicy: "allowlist",
        groupAllowFrom: [],
      },
      senderId: "attacker",
    });

    expect(result.groupAccess).toMatchObject({
      allowed: false,
      groupPolicy: "allowlist",
      reason: "empty_allowlist",
    });
  });

  it("blocks sender not in group allowlist", async () => {
    const { result } = await resolveAccess({
      accountConfig: {
        groupPolicy: "allowlist",
        groupAllowFrom: ["zalo:victim-user-001"],
      },
      senderId: "attacker-user-999",
    });

    expect(result.groupAccess).toMatchObject({
      allowed: false,
      groupPolicy: "allowlist",
      reason: "sender_not_allowlisted",
    });
  });

  it("allows sender in group allowlist", async () => {
    const { result } = await resolveAccess({
      accountConfig: {
        groupPolicy: "allowlist",
        groupAllowFrom: ["zl:12345"],
      },
      senderId: "12345",
    });

    expect(result.groupAccess).toMatchObject({
      allowed: true,
      groupPolicy: "allowlist",
      reason: "allowed",
    });
  });

  it("allows group sender through allowFrom fallback when groupAllowFrom is unset", async () => {
    const { result } = await resolveAccess({
      accountConfig: {
        groupPolicy: "allowlist",
        allowFrom: ["zl:12345"],
        groupAllowFrom: [],
      },
      senderId: "12345",
    });

    expect(result.groupAccess).toMatchObject({
      allowed: true,
      groupPolicy: "allowlist",
      reason: "allowed",
    });
  });

  it("allows any sender with wildcard allowlist", async () => {
    const { result } = await resolveAccess({
      accountConfig: {
        groupPolicy: "allowlist",
        groupAllowFrom: ["*"],
      },
      senderId: "random-user",
    });

    expect(result.groupAccess).toMatchObject({
      allowed: true,
      groupPolicy: "allowlist",
      reason: "allowed",
    });
  });

  it("allows all group senders on open policy", async () => {
    const { result } = await resolveAccess({
      accountConfig: {
        groupPolicy: "open",
        groupAllowFrom: [],
      },
      senderId: "attacker-user-999",
    });

    expect(result.groupAccess).toMatchObject({
      allowed: true,
      groupPolicy: "open",
      reason: "allowed",
    });
  });

  it("keeps group control-command authorization separate from group sender access", async () => {
    const { result } = await resolveAccess({
      accountConfig: {
        groupPolicy: "open",
        allowFrom: [],
        groupAllowFrom: [],
      },
      rawBody: "/reset",
      shouldComputeCommandAuthorized: true,
    });

    expect(result.access.decision).toBe("allow");
    expect(result.commandAuthorized).toBe(false);
  });

  it("authorizes direct commands from the pairing store", async () => {
    const { result, readAllowFromStore } = await resolveAccess({
      isGroup: false,
      accountConfig: {
        dmPolicy: "pairing",
        allowFrom: [],
      },
      senderId: "12345",
      storeAllowFrom: ["zl:12345"],
      rawBody: "/status",
      shouldComputeCommandAuthorized: true,
    });

    expect(readAllowFromStore).toHaveBeenCalledTimes(1);
    expect(result.access).toMatchObject({
      decision: "allow",
      reasonCode: "dm_policy_allowlisted",
    });
    expect(result.commandAuthorized).toBe(true);
  });

  it("requires an explicit wildcard or allowlist match for open DMs", async () => {
    const { result, readAllowFromStore } = await resolveAccess({
      isGroup: false,
      accountConfig: {
        dmPolicy: "open",
        allowFrom: [],
      },
      senderId: "12345",
    });

    expect(readAllowFromStore).not.toHaveBeenCalled();
    expect(result.access).toMatchObject({
      decision: "block",
      reasonCode: "dm_policy_not_allowlisted",
    });
  });

  it("matches static access-group entries through the shared ingress resolver", async () => {
    const { result } = await resolveAccess({
      cfg: {
        accessGroups: {
          operators: {
            type: "message.senders",
            members: {
              zalo: ["zl:12345"],
            },
          },
        },
      } as OpenClawConfig,
      accountConfig: {
        groupPolicy: "allowlist",
        groupAllowFrom: ["accessGroup:operators"],
      },
      senderId: "12345",
    });

    expect(result.groupAccess).toMatchObject({
      allowed: true,
      groupPolicy: "allowlist",
      reason: "allowed",
    });
  });
});
