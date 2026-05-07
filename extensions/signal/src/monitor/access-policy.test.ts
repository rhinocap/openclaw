import type { AccessGroupsConfig } from "openclaw/plugin-sdk/config-types";
import { readStoreAllowFromForDmPolicy } from "openclaw/plugin-sdk/security-runtime";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { handleSignalDirectMessageAccess, resolveSignalAccessState } from "./access-policy.js";

vi.mock("openclaw/plugin-sdk/security-runtime", async (importOriginal) => ({
  ...(await importOriginal<typeof import("openclaw/plugin-sdk/security-runtime")>()),
  readStoreAllowFromForDmPolicy: vi.fn(async () => []),
}));

const SIGNAL_GROUP_ID = "signal-group-id";
const OTHER_SIGNAL_GROUP_ID = "other-signal-group-id";
const SIGNAL_SENDER = {
  kind: "phone" as const,
  e164: "+15551230000",
  raw: "+15551230000",
};

beforeEach(() => {
  vi.mocked(readStoreAllowFromForDmPolicy).mockResolvedValue([]);
});

async function resolveGroupAccess(params: {
  allowFrom?: string[];
  groupAllowFrom?: string[];
  groupId?: string;
  accessGroups?: AccessGroupsConfig;
}) {
  const access = await resolveSignalAccessState({
    accountId: "default",
    dmPolicy: "allowlist",
    groupPolicy: "allowlist",
    allowFrom: params.allowFrom ?? [],
    groupAllowFrom: params.groupAllowFrom ?? [],
    sender: SIGNAL_SENDER,
    groupId: params.groupId,
    accessGroups: params.accessGroups,
  });
  return {
    ...access,
    groupDecision: access.resolveAccessDecision(true),
  };
}

describe("resolveSignalAccessState", () => {
  it("allows group messages when groupAllowFrom contains the inbound Signal group id", async () => {
    const { groupDecision } = await resolveGroupAccess({
      groupAllowFrom: [SIGNAL_GROUP_ID],
      groupId: SIGNAL_GROUP_ID,
    });

    expect(groupDecision.decision).toBe("allow");
  });

  it("allows Signal group target forms in groupAllowFrom", async () => {
    const groupTargetDecision = await resolveGroupAccess({
      groupAllowFrom: [`group:${SIGNAL_GROUP_ID}`],
      groupId: SIGNAL_GROUP_ID,
    });
    const signalGroupTargetDecision = await resolveGroupAccess({
      groupAllowFrom: [`signal:group:${SIGNAL_GROUP_ID}`],
      groupId: SIGNAL_GROUP_ID,
    });

    expect(groupTargetDecision.groupDecision.decision).toBe("allow");
    expect(signalGroupTargetDecision.groupDecision.decision).toBe("allow");
  });

  it("blocks group messages when groupAllowFrom contains a different Signal group id", async () => {
    const { groupDecision } = await resolveGroupAccess({
      groupAllowFrom: [OTHER_SIGNAL_GROUP_ID],
      groupId: SIGNAL_GROUP_ID,
    });

    expect(groupDecision.decision).toBe("block");
  });

  it("keeps sender allowlist compatibility for Signal group messages", async () => {
    const { groupDecision } = await resolveGroupAccess({
      groupAllowFrom: [SIGNAL_SENDER.e164],
      groupId: SIGNAL_GROUP_ID,
    });

    expect(groupDecision.decision).toBe("allow");
  });

  it("falls back to allowFrom for group sender access when groupAllowFrom is unset", async () => {
    const { groupDecision } = await resolveGroupAccess({
      allowFrom: [SIGNAL_SENDER.e164],
      groupId: SIGNAL_GROUP_ID,
    });

    expect(groupDecision.decision).toBe("allow");
  });

  it("does not match group ids against direct-message allowFrom entries", async () => {
    const { dmAccess } = await resolveSignalAccessState({
      accountId: "default",
      dmPolicy: "allowlist",
      groupPolicy: "allowlist",
      allowFrom: [SIGNAL_GROUP_ID],
      groupAllowFrom: [],
      sender: SIGNAL_SENDER,
      groupId: SIGNAL_GROUP_ID,
    });

    expect(dmAccess.decision).toBe("block");
  });

  it("allows direct messages through static message sender access groups", async () => {
    const { dmAccess } = await resolveSignalAccessState({
      accountId: "default",
      dmPolicy: "allowlist",
      groupPolicy: "allowlist",
      allowFrom: ["accessGroup:operators"],
      groupAllowFrom: [],
      sender: SIGNAL_SENDER,
      accessGroups: {
        operators: {
          type: "message.senders",
          members: {
            signal: [SIGNAL_SENDER.e164],
          },
        },
      },
    });

    expect(dmAccess.decision).toBe("allow");
  });

  it("allows group messages through static message sender access groups", async () => {
    const { groupDecision } = await resolveGroupAccess({
      groupAllowFrom: ["accessGroup:operators"],
      groupId: SIGNAL_GROUP_ID,
      accessGroups: {
        operators: {
          type: "message.senders",
          members: {
            signal: [SIGNAL_SENDER.e164],
          },
        },
      },
    });

    expect(groupDecision.decision).toBe("allow");
  });

  it("allows paired direct senders from the pairing store", async () => {
    vi.mocked(readStoreAllowFromForDmPolicy).mockResolvedValue([SIGNAL_SENDER.e164]);

    const { dmAccess } = await resolveSignalAccessState({
      accountId: "default",
      dmPolicy: "pairing",
      groupPolicy: "allowlist",
      allowFrom: [],
      groupAllowFrom: [],
      sender: SIGNAL_SENDER,
    });

    expect(dmAccess.decision).toBe("allow");
    expect(dmAccess.effectiveAllowFrom).toEqual([SIGNAL_SENDER.e164]);
  });

  it("does not let pairing-store senders satisfy group access", async () => {
    vi.mocked(readStoreAllowFromForDmPolicy).mockResolvedValue([SIGNAL_SENDER.e164]);

    const { groupDecision } = await resolveGroupAccess({
      groupAllowFrom: [],
      groupId: SIGNAL_GROUP_ID,
    });

    expect(groupDecision.decision).toBe("block");
  });

  it("does not let group ids in allowFrom satisfy an explicit groupAllowFrom mismatch", async () => {
    const { groupDecision } = await resolveGroupAccess({
      allowFrom: [SIGNAL_GROUP_ID],
      groupAllowFrom: [OTHER_SIGNAL_GROUP_ID],
      groupId: SIGNAL_GROUP_ID,
    });

    expect(groupDecision.decision).toBe("block");
  });

  it("keeps sender access allowed while blocking unauthorized group control commands", async () => {
    const access = await resolveSignalAccessState({
      accountId: "default",
      dmPolicy: "allowlist",
      groupPolicy: "open",
      allowFrom: [],
      groupAllowFrom: [],
      sender: SIGNAL_SENDER,
      groupId: SIGNAL_GROUP_ID,
      hasControlCommand: true,
    });

    expect(access.resolveAccessDecision(true).decision).toBe("allow");
    expect(access.resolveCommandAccess(true)).toEqual({
      commandAuthorized: false,
      shouldBlockControlCommand: true,
    });
  });

  it("authorizes group control commands from the shared ingress command gate", async () => {
    const access = await resolveSignalAccessState({
      accountId: "default",
      dmPolicy: "allowlist",
      groupPolicy: "allowlist",
      allowFrom: [],
      groupAllowFrom: [SIGNAL_SENDER.e164],
      sender: SIGNAL_SENDER,
      groupId: SIGNAL_GROUP_ID,
      hasControlCommand: true,
    });

    expect(access.resolveCommandAccess(true)).toEqual({
      commandAuthorized: true,
      shouldBlockControlCommand: false,
    });
  });
});

describe("handleSignalDirectMessageAccess", () => {
  it("returns true for already-allowed direct messages", async () => {
    await expect(
      handleSignalDirectMessageAccess({
        dmPolicy: "open",
        dmAccessDecision: "allow",
        senderId: "+15551230000",
        senderIdLine: "Signal number: +15551230000",
        senderDisplay: "Alice",
        accountId: "default",
        sendPairingReply: async () => {},
        log: () => {},
      }),
    ).resolves.toBe(true);
  });

  it("issues a pairing challenge for pairing-gated senders", async () => {
    const replies: string[] = [];
    const sendPairingReply = vi.fn(async (text: string) => {
      replies.push(text);
    });

    await expect(
      handleSignalDirectMessageAccess({
        dmPolicy: "pairing",
        dmAccessDecision: "pairing",
        senderId: "+15551230000",
        senderIdLine: "Signal number: +15551230000",
        senderDisplay: "Alice",
        senderName: "Alice",
        accountId: "default",
        sendPairingReply,
        log: () => {},
      }),
    ).resolves.toBe(false);

    expect(sendPairingReply).toHaveBeenCalledTimes(1);
    expect(replies[0]).toContain("Pairing code:");
  });
});
