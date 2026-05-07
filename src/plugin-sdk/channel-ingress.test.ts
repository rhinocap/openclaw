import { describe, expect, it } from "vitest";
import {
  createChannelIngressMultiIdentifierAdapter,
  createChannelIngressPluginId,
  createChannelIngressStringAdapter,
  createChannelIngressSubject,
  decideChannelIngress,
  decideChannelIngressBundle,
  findChannelIngressCommandGate,
  findChannelIngressSenderGate,
  projectIngressAccessFacts,
  resolveChannelIngressState,
} from "./channel-ingress.js";

describe("plugin-sdk/channel-ingress", () => {
  it("resolves sender policy through the experimental SDK facade", async () => {
    const rawSender = "secret-sender@example.test";
    const state = await resolveChannelIngressState({
      channelId: createChannelIngressPluginId("test-channel"),
      accountId: "default",
      subject: createChannelIngressSubject({
        value: rawSender,
      }),
      conversation: {
        kind: "direct",
        id: "dm-1",
      },
      adapter: createChannelIngressStringAdapter(),
      event: {
        kind: "message",
        authMode: "inbound",
        mayPair: false,
      },
      allowlists: {
        dm: [rawSender],
      },
    });

    const decision = decideChannelIngress(state, {
      dmPolicy: "allowlist",
      groupPolicy: "open",
    });

    expect(decision).toMatchObject({
      admission: "dispatch",
      decision: "allow",
    });
    expect(projectIngressAccessFacts(decision)).toMatchObject({
      dm: {
        decision: "allow",
        allowlist: {
          configured: true,
          matched: true,
        },
      },
    });
    expect(JSON.stringify(state)).not.toContain(rawSender);
    expect(JSON.stringify(decision)).not.toContain(rawSender);
  });

  it("matches multi-identifier adapters and selects gates without id literals", async () => {
    const adapter = createChannelIngressMultiIdentifierAdapter({
      normalizeEntry(entry, index) {
        const normalized = entry.trim().toLowerCase();
        if (!normalized) {
          return [];
        }
        return [
          {
            opaqueEntryId: `entry-${index + 1}`,
            kind: normalized.startsWith("@") ? "username" : "stable-id",
            value: normalized.replace(/^@/, ""),
            dangerous: normalized.startsWith("@"),
          },
        ];
      },
      getSubjectMatchKeys(identifier) {
        return [`${identifier.kind}:${identifier.value.toLowerCase().replace(/^@/, "")}`];
      },
    });
    const subject = createChannelIngressSubject({
      identifiers: [
        { opaqueId: "sender-id", kind: "stable-id", value: "user-1" },
        { opaqueId: "sender-name", kind: "username", value: "@Alice", dangerous: true },
      ],
    });
    const stateInput = {
      channelId: createChannelIngressPluginId("test-channel"),
      accountId: "default",
      subject,
      adapter,
      event: {
        kind: "message" as const,
        authMode: "inbound" as const,
        mayPair: false,
      },
      allowlists: {
        dm: ["@alice"],
        group: ["user-1"],
        commandOwner: ["@alice"],
      },
    };
    const [directState, groupState] = await Promise.all([
      resolveChannelIngressState({
        ...stateInput,
        conversation: { kind: "direct", id: "dm-1" },
      }),
      resolveChannelIngressState({
        ...stateInput,
        conversation: { kind: "group", id: "room-1" },
      }),
    ]);

    const bundle = decideChannelIngressBundle({
      directState,
      groupState,
      basePolicy: {
        dmPolicy: "allowlist",
        groupPolicy: "allowlist",
      },
      commandPolicy: {
        dmPolicy: "allowlist",
        groupPolicy: "allowlist",
        mutableIdentifierMatching: "enabled",
        command: {
          allowTextCommands: true,
          hasControlCommand: true,
        },
      },
    });

    expect(findChannelIngressSenderGate(bundle.dm, { isGroup: false })).toMatchObject({
      allowed: false,
      reasonCode: "dm_policy_not_allowlisted",
    });
    expect(findChannelIngressSenderGate(bundle.group, { isGroup: true })).toMatchObject({
      allowed: true,
      reasonCode: "group_policy_allowed",
    });
    expect(findChannelIngressCommandGate(bundle.dmCommand)).toMatchObject({
      allowed: true,
      reasonCode: "command_authorized",
    });
    expect(JSON.stringify(directState)).not.toContain("Alice");
  });
});
