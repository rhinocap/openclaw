import { describe, expect, it } from "vitest";
import type { OpenClawConfig } from "../config/types.openclaw.js";
import {
  expandAllowFromWithAccessGroups,
  resolveAccessGroupAllowFromState,
} from "./access-groups.js";

describe("resolveAccessGroupAllowFromState", () => {
  it("reports referenced, matched, missing, and unsupported groups", async () => {
    const state = await resolveAccessGroupAllowFromState({
      accessGroups: {
        admins: {
          type: "message.senders",
          members: {
            "*": ["global-admin"],
            test: ["local-admin"],
          },
        },
        audience: {
          type: "discord.channelAudience",
          guildId: "guild-1",
          channelId: "channel-1",
        },
      },
      allowFrom: ["accessGroup:admins", "accessGroup:missing", "accessGroup:audience"],
      channel: "test",
      accountId: "default",
      senderId: "local-admin",
      isSenderAllowed: (senderId, allowFrom) => allowFrom.includes(senderId),
    });

    expect(state).toMatchObject({
      referenced: ["admins", "missing", "audience"],
      matched: ["admins"],
      missing: ["missing"],
      unsupported: ["audience"],
      failed: [],
      matchedAllowFromEntries: ["accessGroup:admins"],
      hasReferences: true,
      hasMatch: true,
    });
  });

  it("reports failed dynamic membership without throwing", async () => {
    const state = await resolveAccessGroupAllowFromState({
      accessGroups: {
        audience: {
          type: "discord.channelAudience",
          guildId: "guild-1",
          channelId: "channel-1",
        },
      },
      allowFrom: ["accessGroup:audience"],
      channel: "discord",
      accountId: "default",
      senderId: "discord:123",
      resolveMembership: async () => {
        throw new Error("discord lookup failed");
      },
    });

    expect(state).toMatchObject({
      referenced: ["audience"],
      matched: [],
      missing: [],
      unsupported: [],
      failed: ["audience"],
      hasMatch: false,
    });
  });

  it("keeps compatibility expansion behavior for matched groups", async () => {
    const cfg = {
      accessGroups: {
        operators: {
          type: "message.senders",
          members: {
            test: ["operator"],
          },
        },
      },
    } as OpenClawConfig;

    await expect(
      expandAllowFromWithAccessGroups({
        cfg,
        allowFrom: ["accessGroup:operators"],
        channel: "test",
        accountId: "default",
        senderId: "operator",
        isSenderAllowed: (senderId, allowFrom) => allowFrom.includes(senderId),
      }),
    ).resolves.toEqual(["accessGroup:operators", "operator"]);
  });
});
