import { describe, expect, it } from "vitest";
import {
  decideChannelIngress,
  findChannelIngressSenderGate,
  projectIngressAccessFacts,
  resolveChannelIngressState,
  type ChannelIngressPolicyInput,
  type ChannelIngressStateInput,
  type InternalChannelIngressAdapter,
  type InternalChannelIngressSubject,
} from "./index.js";

const subject = (value: string): InternalChannelIngressSubject => ({
  identifiers: [
    {
      opaqueId: "subject-1",
      kind: "stable-id",
      value,
    },
  ],
});

const adapter: InternalChannelIngressAdapter = {
  normalizeEntries({ entries }) {
    return {
      matchable: entries.map((entry, index) => ({
        opaqueEntryId: `entry-${index + 1}`,
        kind: "stable-id",
        value: entry,
      })),
      invalid: [],
      disabled: [],
    };
  },
  matchSubject({ subject, entries }) {
    const values = new Set(subject.identifiers.map((identifier) => identifier.value));
    const matchedEntryIds = entries
      .filter((entry) => entry.value === "*" || values.has(entry.value))
      .map((entry) => entry.opaqueEntryId);
    return {
      matched: matchedEntryIds.length > 0,
      matchedEntryIds,
    };
  },
};

const dangerousAdapter: InternalChannelIngressAdapter = {
  normalizeEntries({ entries }) {
    return {
      matchable: entries.map((entry, index) => ({
        opaqueEntryId: `entry-${index + 1}`,
        kind: "username",
        dangerous: entry.startsWith("display:"),
        value: entry,
      })),
      invalid: [],
      disabled: [],
    };
  },
  matchSubject: adapter.matchSubject,
};

const lowerCaseAdapter: InternalChannelIngressAdapter = {
  normalizeEntries({ entries }) {
    return {
      matchable: entries.map((entry, index) => ({
        opaqueEntryId: `entry-${index + 1}`,
        kind: "stable-id",
        value: entry.toLowerCase(),
      })),
      invalid: [],
      disabled: [],
    };
  },
  matchSubject({ subject, entries }) {
    const values = new Set(subject.identifiers.map((identifier) => identifier.value.toLowerCase()));
    const matchedEntryIds = entries
      .filter((entry) => entry.kind === "stable-id" && values.has(entry.value))
      .map((entry) => entry.opaqueEntryId);
    return {
      matched: matchedEntryIds.length > 0,
      matchedEntryIds,
    };
  },
};

function baseInput(overrides: Partial<ChannelIngressStateInput> = {}): ChannelIngressStateInput {
  return {
    channelId: "test",
    accountId: "default",
    subject: subject("sender-1"),
    conversation: {
      kind: "direct",
      id: "dm-1",
    },
    adapter,
    event: {
      kind: "message",
      authMode: "inbound",
      mayPair: true,
    },
    allowlists: {},
    ...overrides,
  };
}

const basePolicy: ChannelIngressPolicyInput = {
  dmPolicy: "pairing",
  groupPolicy: "allowlist",
};

describe("channel message access ingress", () => {
  it("keeps pairing-store entries DM-policy scoped", async () => {
    const input = baseInput({
      subject: subject("paired-sender"),
      allowlists: {
        pairingStore: ["paired-sender"],
      },
    });

    const openState = await resolveChannelIngressState(input);
    const openDecision = decideChannelIngress(openState, {
      ...basePolicy,
      dmPolicy: "open",
    });
    expect(openDecision).toMatchObject({
      admission: "drop",
      reasonCode: "dm_policy_not_allowlisted",
    });

    const pairingDecision = decideChannelIngress(openState, {
      ...basePolicy,
      dmPolicy: "pairing",
    });
    expect(pairingDecision).toMatchObject({
      admission: "dispatch",
      decision: "allow",
    });
  });

  it("keeps missing access groups gate-local when another entry matches", async () => {
    const state = await resolveChannelIngressState(
      baseInput({
        subject: subject("allowed-sender"),
        conversation: {
          kind: "group",
          id: "room-1",
        },
        allowlists: {
          group: ["accessGroup:missing", "allowed-sender"],
        },
      }),
    );

    expect(state.allowlists.group.accessGroups.missing).toEqual(["missing"]);
    const decision = decideChannelIngress(state, {
      ...basePolicy,
      groupPolicy: "allowlist",
    });
    expect(decision).toMatchObject({
      admission: "dispatch",
      decision: "allow",
    });
    expect(projectIngressAccessFacts(decision)).toMatchObject({
      group: {
        allowlist: {
          configured: true,
          matched: true,
          matchedEntryIds: ["entry-1"],
          invalidEntryCount: 0,
          disabledEntryCount: 0,
          accessGroups: {
            referenced: ["missing"],
            missing: ["missing"],
          },
        },
      },
    });
  });

  it("blocks matched routes with deny-when-empty sender policy", async () => {
    const state = await resolveChannelIngressState(
      baseInput({
        routeFacts: [
          {
            id: "space-1",
            kind: "route",
            gate: "matched",
            effect: "allow",
            precedence: 0,
            senderPolicy: "deny-when-empty",
            senderAllowFrom: [],
          },
        ],
        allowlists: {
          dm: ["sender-1"],
        },
      }),
    );

    const decision = decideChannelIngress(state, basePolicy);
    expect(decision).toMatchObject({
      admission: "drop",
      reasonCode: "route_sender_empty",
    });
    expect(state.routeFacts[0]).not.toHaveProperty("senderAllowFrom");
  });

  it("uses matched route sender allowlists with replace policy", async () => {
    const rawRouteSender = "route-sender@example.test";
    const state = await resolveChannelIngressState(
      baseInput({
        subject: subject(rawRouteSender),
        conversation: {
          kind: "group",
          id: "room-1",
        },
        routeFacts: [
          {
            id: "space-1",
            kind: "route",
            gate: "matched",
            effect: "allow",
            precedence: 0,
            senderPolicy: "replace",
            senderAllowFrom: [rawRouteSender],
          },
        ],
        allowlists: {
          group: ["group-sender"],
        },
      }),
    );

    const decision = decideChannelIngress(state, {
      ...basePolicy,
      groupPolicy: "allowlist",
    });

    expect(state.routeFacts[0]?.senderAllowlist).toMatchObject({
      hasConfiguredEntries: true,
      match: { matched: true },
    });
    expect(decision).toMatchObject({
      admission: "dispatch",
      decision: "allow",
    });
    expect(JSON.stringify(state)).not.toContain(rawRouteSender);
    expect(JSON.stringify(decision)).not.toContain(rawRouteSender);
  });

  it("augments group sender allowlists with matched route inherit policy", async () => {
    const state = await resolveChannelIngressState(
      baseInput({
        subject: subject("route-sender"),
        conversation: {
          kind: "group",
          id: "room-1",
        },
        routeFacts: [
          {
            id: "space-1",
            kind: "route",
            gate: "matched",
            effect: "allow",
            precedence: 0,
            senderPolicy: "inherit",
            senderAllowFrom: ["route-sender"],
          },
        ],
        allowlists: {
          group: ["group-sender"],
        },
      }),
    );

    const decision = decideChannelIngress(state, {
      ...basePolicy,
      groupPolicy: "allowlist",
    });

    expect(decision).toMatchObject({
      admission: "dispatch",
      decision: "allow",
    });
  });

  it("requires explicit policy for group sender fallback to DM allowlists", async () => {
    const state = await resolveChannelIngressState(
      baseInput({
        conversation: {
          kind: "group",
          id: "room-1",
        },
        allowlists: {
          dm: ["sender-1"],
        },
      }),
    );

    expect(decideChannelIngress(state, basePolicy)).toMatchObject({
      admission: "drop",
      reasonCode: "group_policy_empty_allowlist",
    });
    expect(
      decideChannelIngress(state, {
        ...basePolicy,
        groupAllowFromFallbackToAllowFrom: true,
      }),
    ).toMatchObject({
      admission: "dispatch",
      decision: "allow",
    });
  });

  it("requires explicit policy before dangerous identifiers can authorize senders", async () => {
    const state = await resolveChannelIngressState(
      baseInput({
        adapter: dangerousAdapter,
        subject: subject("display:sender-1"),
        allowlists: {
          dm: ["display:sender-1"],
        },
      }),
    );

    expect(
      decideChannelIngress(state, {
        ...basePolicy,
        dmPolicy: "allowlist",
      }),
    ).toMatchObject({
      admission: "drop",
      reasonCode: "dm_policy_not_allowlisted",
    });
    expect(
      decideChannelIngress(state, {
        ...basePolicy,
        dmPolicy: "allowlist",
        mutableIdentifierMatching: "enabled",
      }),
    ).toMatchObject({
      admission: "dispatch",
      decision: "allow",
    });
  });

  it("does not require inbound sender authorization for origin-subject events", async () => {
    const state = await resolveChannelIngressState(
      baseInput({
        event: {
          kind: "reaction",
          authMode: "origin-subject",
          mayPair: false,
          originSubject: subject("sender-1"),
        },
        allowlists: {},
      }),
    );

    const decision = decideChannelIngress(state, basePolicy);

    expect(decision).toMatchObject({
      admission: "dispatch",
      decision: "allow",
    });
    expect(findChannelIngressSenderGate(decision, { isGroup: false })).toMatchObject({
      effect: "ignore",
      reasonCode: "sender_not_required",
    });
  });

  it("does not authorize origin-subject events by default opaque identifier slots", async () => {
    const state = await resolveChannelIngressState(
      baseInput({
        event: {
          kind: "reaction",
          authMode: "origin-subject",
          mayPair: false,
          originSubject: subject("different-sender"),
        },
        allowlists: {},
      }),
    );

    const decision = decideChannelIngress(state, basePolicy);

    expect(state.event.originSubjectMatched).toBe(false);
    expect(decision).toMatchObject({
      admission: "drop",
      decision: "block",
      reasonCode: "origin_subject_not_matched",
    });
  });

  it("matches origin-subject events through adapter-normalized identity values", async () => {
    const state = await resolveChannelIngressState(
      baseInput({
        adapter: lowerCaseAdapter,
        subject: subject("Sender-1"),
        event: {
          kind: "reaction",
          authMode: "origin-subject",
          mayPair: false,
          originSubject: subject("sender-1"),
        },
        allowlists: {},
      }),
    );

    const decision = decideChannelIngress(state, basePolicy);

    expect(state.event.originSubjectMatched).toBe(true);
    expect(decision).toMatchObject({
      admission: "dispatch",
      decision: "allow",
    });
  });

  it("does not treat origin-subject values as allowlist wildcards", async () => {
    const state = await resolveChannelIngressState(
      baseInput({
        event: {
          kind: "reaction",
          authMode: "origin-subject",
          mayPair: false,
          originSubject: subject("*"),
        },
        allowlists: {},
      }),
    );

    const decision = decideChannelIngress(state, basePolicy);

    expect(state.event.originSubjectMatched).toBe(false);
    expect(decision).toMatchObject({
      admission: "drop",
      decision: "block",
      reasonCode: "origin_subject_not_matched",
    });
  });
});
