import { describe, expect, it } from "vitest";
import {
  decideChannelIngress,
  mapChannelIngressDecisionToTurnAdmission,
  projectIngressAccessFacts,
  resolveChannelIngressState,
  type ChannelIngressPolicyInput,
  type ChannelIngressStateInput,
  type InternalChannelIngressAdapter,
  type InternalChannelIngressSubject,
} from "./index.js";

function subject(value: string, kind: "stable-id" | "plugin:nostr" = "stable-id") {
  return {
    identifiers: [
      {
        opaqueId: "subject-1",
        kind,
        value,
      },
    ],
  } satisfies InternalChannelIngressSubject;
}

function prefixedAdapter(params: {
  prefix?: string;
  kind?: "stable-id" | "plugin:nostr";
  normalize?: (value: string) => string;
}): InternalChannelIngressAdapter {
  const normalize = params.normalize ?? ((value: string) => value);
  return {
    normalizeEntries({ entries }) {
      return {
        matchable: entries.map((entry, index) => {
          const value = entry === "*" ? "*" : normalize(entry.replace(params.prefix ?? "", ""));
          return {
            opaqueEntryId: `entry-${index + 1}`,
            kind: params.kind ?? "stable-id",
            value,
          };
        }),
        invalid: [],
        disabled: [],
      };
    },
    matchSubject({ subject, entries }) {
      const values = new Set(subject.identifiers.map((identifier) => normalize(identifier.value)));
      const matchedEntryIds = entries
        .filter((entry) => entry.value === "*" || values.has(entry.value))
        .map((entry) => entry.opaqueEntryId);
      return {
        matched: matchedEntryIds.length > 0,
        matchedEntryIds,
      };
    },
  };
}

const exactAdapter = prefixedAdapter({});
const nostrAdapter = prefixedAdapter({
  prefix: "nostr:",
  kind: "plugin:nostr",
  normalize: (value) => value.toLowerCase(),
});
const qqbotAdapter = prefixedAdapter({
  prefix: "QQBot:",
  normalize: (value) => value.toUpperCase(),
});

const basePolicy: ChannelIngressPolicyInput = {
  dmPolicy: "pairing",
  groupPolicy: "allowlist",
};

function input(overrides: Partial<ChannelIngressStateInput> = {}): ChannelIngressStateInput {
  return {
    channelId: "qa-channel",
    accountId: "default",
    subject: subject("sender-1"),
    conversation: {
      kind: "direct",
      id: "dm-1",
    },
    adapter: exactAdapter,
    event: {
      kind: "message",
      authMode: "inbound",
      mayPair: true,
    },
    allowlists: {},
    ...overrides,
  };
}

describe("channel message access conformance mirrors", () => {
  it("mirrors QA Channel open synthetic ingress and command context", async () => {
    const rawSender = "secret-qa-user@example.test";
    const state = await resolveChannelIngressState(
      input({
        channelId: "qa-channel",
        subject: subject(rawSender),
        allowlists: {
          dm: ["*"],
        },
      }),
    );

    const decision = decideChannelIngress(state, {
      ...basePolicy,
      dmPolicy: "open",
    });
    const facts = projectIngressAccessFacts(decision);

    expect(decision).toMatchObject({
      admission: "dispatch",
      decision: "allow",
      reasonCode: "activation_allowed",
    });
    expect(facts.commands).toMatchObject({
      authorized: true,
    });
    expect(JSON.stringify(state)).not.toContain(rawSender);
    expect(JSON.stringify(decision)).not.toContain(rawSender);
  });

  it("mirrors QA Channel group mentions without requiring activation", async () => {
    const state = await resolveChannelIngressState(
      input({
        conversation: {
          kind: "channel",
          id: "qa-room",
        },
        mentionFacts: {
          canDetectMention: true,
          wasMentioned: false,
        },
      }),
    );

    const decision = decideChannelIngress(state, {
      ...basePolicy,
      groupPolicy: "open",
    });

    expect(decision).toMatchObject({
      admission: "dispatch",
      decision: "allow",
    });
    expect(projectIngressAccessFacts(decision)).toMatchObject({
      group: {
        policy: "open",
        requireMention: false,
      },
      mentions: {
        canDetectMention: true,
        wasMentioned: false,
        shouldSkip: false,
      },
    });
  });

  it("mirrors Nostr pre-crypto pairing for unknown direct senders", async () => {
    const state = await resolveChannelIngressState(
      input({
        channelId: "nostr",
        adapter: nostrAdapter,
        subject: subject("abc123", "plugin:nostr"),
        event: {
          kind: "message",
          authMode: "inbound",
          mayPair: true,
        },
      }),
    );

    const decision = decideChannelIngress(state, {
      ...basePolicy,
      dmPolicy: "pairing",
    });

    expect(decision).toMatchObject({
      admission: "pairing-required",
      decision: "pairing",
      reasonCode: "dm_policy_pairing_required",
    });
    expect(
      mapChannelIngressDecisionToTurnAdmission(decision, { kind: "pairing-reply-sent" }),
    ).toMatchObject({
      kind: "handled",
    });
  });

  it("mirrors Nostr allowlist prefix normalization without serializing pubkeys", async () => {
    const rawPubkey = "ABC123";
    const state = await resolveChannelIngressState(
      input({
        channelId: "nostr",
        adapter: nostrAdapter,
        subject: subject(rawPubkey, "plugin:nostr"),
        allowlists: {
          dm: [`nostr:${rawPubkey}`],
        },
      }),
    );

    const decision = decideChannelIngress(state, {
      ...basePolicy,
      dmPolicy: "allowlist",
    });

    expect(decision).toMatchObject({
      admission: "dispatch",
      decision: "allow",
    });
    expect(JSON.stringify(state)).not.toContain(rawPubkey);
    expect(JSON.stringify(decision)).not.toContain(rawPubkey);
  });

  it("mirrors QQBot legacy empty allowFrom as plugin-local wildcard normalization", async () => {
    const state = await resolveChannelIngressState(
      input({
        channelId: "qqbot",
        adapter: qqbotAdapter,
        subject: subject("USER1"),
        allowlists: {
          dm: ["*"],
        },
      }),
    );

    const decision = decideChannelIngress(state, {
      ...basePolicy,
      dmPolicy: "open",
    });

    expect(decision).toMatchObject({
      admission: "dispatch",
      decision: "allow",
    });
    expect(projectIngressAccessFacts(decision)).toMatchObject({
      dm: {
        decision: "allow",
        reason: "dm_policy_open",
      },
    });
  });

  it("mirrors QQBot group fallback to allowFrom plus mention skip", async () => {
    const state = await resolveChannelIngressState(
      input({
        channelId: "qqbot",
        adapter: qqbotAdapter,
        subject: subject("USER1"),
        conversation: {
          kind: "group",
          id: "group-1",
        },
        mentionFacts: {
          canDetectMention: true,
          wasMentioned: false,
          hasAnyMention: false,
        },
        allowlists: {
          dm: ["QQBot:user1"],
        },
      }),
    );

    const decision = decideChannelIngress(state, {
      ...basePolicy,
      dmPolicy: "allowlist",
      groupPolicy: "allowlist",
      groupAllowFromFallbackToAllowFrom: true,
      activation: {
        requireMention: true,
        allowTextCommands: true,
      },
    });

    expect(decision).toMatchObject({
      admission: "skip",
      decision: "allow",
      reasonCode: "activation_skipped",
    });
    expect(projectIngressAccessFacts(decision)).toMatchObject({
      group: {
        policy: "allowlist",
        senderAllowed: true,
        requireMention: true,
      },
      mentions: {
        shouldSkip: true,
      },
    });
  });

  it("mirrors QQBot unauthorized control command precedence before mention skip", async () => {
    const state = await resolveChannelIngressState(
      input({
        channelId: "qqbot",
        adapter: qqbotAdapter,
        subject: subject("INTRUDER"),
        conversation: {
          kind: "group",
          id: "group-1",
        },
        mentionFacts: {
          canDetectMention: true,
          wasMentioned: false,
          hasAnyMention: false,
        },
        allowlists: {
          group: ["*"],
        },
      }),
    );

    const decision = decideChannelIngress(state, {
      ...basePolicy,
      groupPolicy: "open",
      command: {
        useAccessGroups: true,
        allowTextCommands: true,
        hasControlCommand: true,
      },
      activation: {
        requireMention: true,
        allowTextCommands: true,
      },
    });

    expect(decision).toMatchObject({
      admission: "drop",
      decision: "block",
      reasonCode: "control_command_unauthorized",
    });
  });
});
