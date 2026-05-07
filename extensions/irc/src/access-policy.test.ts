import { describe, expect, it } from "vitest";
import { resolveIrcCommandAccess } from "./access-policy.js";
import type { IrcInboundMessage } from "./types.js";

function createMessage(overrides: Partial<IrcInboundMessage> = {}): IrcInboundMessage {
  return {
    messageId: "msg-1",
    target: "#ops",
    senderNick: "alice",
    senderUser: "ident",
    senderHost: "example.com",
    text: "/config",
    timestamp: Date.now(),
    isGroup: true,
    ...overrides,
  };
}

async function resolveCommand(params: {
  message?: Partial<IrcInboundMessage>;
  effectiveAllowFrom?: string[];
  effectiveGroupAllowFrom?: string[];
  allowNameMatching?: boolean;
  allowTextCommands?: boolean;
  hasControlCommand?: boolean;
  useAccessGroups?: boolean;
}) {
  return await resolveIrcCommandAccess({
    accountId: "default",
    message: createMessage(params.message),
    effectiveAllowFrom: params.effectiveAllowFrom ?? [],
    effectiveGroupAllowFrom: params.effectiveGroupAllowFrom ?? [],
    allowNameMatching: params.allowNameMatching ?? false,
    allowTextCommands: params.allowTextCommands ?? true,
    hasControlCommand: params.hasControlCommand ?? true,
    useAccessGroups: params.useAccessGroups ?? true,
  });
}

describe("irc access policy", () => {
  it("authorizes group commands from stable sender identities", async () => {
    await expect(
      resolveCommand({
        effectiveGroupAllowFrom: ["alice!ident@example.com"],
      }),
    ).resolves.toEqual({
      commandAuthorized: true,
      shouldBlockControlCommand: false,
    });
  });

  it("blocks unauthorized group control commands", async () => {
    await expect(
      resolveCommand({
        effectiveGroupAllowFrom: ["bob!ident@example.com"],
      }),
    ).resolves.toEqual({
      commandAuthorized: false,
      shouldBlockControlCommand: true,
    });
  });

  it("requires explicit name matching for bare nick command authorization", async () => {
    await expect(resolveCommand({ effectiveGroupAllowFrom: ["alice"] })).resolves.toEqual({
      commandAuthorized: false,
      shouldBlockControlCommand: true,
    });
    await expect(
      resolveCommand({
        effectiveGroupAllowFrom: ["alice"],
        allowNameMatching: true,
      }),
    ).resolves.toEqual({
      commandAuthorized: true,
      shouldBlockControlCommand: false,
    });
  });

  it("preserves command allow mode when access groups are disabled", async () => {
    await expect(
      resolveCommand({
        effectiveGroupAllowFrom: [],
        useAccessGroups: false,
      }),
    ).resolves.toEqual({
      commandAuthorized: true,
      shouldBlockControlCommand: false,
    });
  });
});
