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

describe("channel message access projection", () => {
  it("projects mention skip facts and maps skip side effects", async () => {
    const state = await resolveChannelIngressState(
      baseInput({
        conversation: {
          kind: "group",
          id: "room-1",
        },
        mentionFacts: {
          canDetectMention: true,
          wasMentioned: false,
        },
        allowlists: {
          group: ["sender-1"],
        },
      }),
    );
    const decision = decideChannelIngress(state, {
      ...basePolicy,
      activation: {
        requireMention: true,
        allowTextCommands: false,
      },
    });

    expect(decision).toMatchObject({
      admission: "skip",
      reasonCode: "activation_skipped",
    });
    expect(mapChannelIngressDecisionToTurnAdmission(decision, { kind: "none" })).toMatchObject({
      kind: "drop",
    });
    expect(
      mapChannelIngressDecisionToTurnAdmission(decision, { kind: "pending-history-recorded" }),
    ).toMatchObject({
      kind: "handled",
    });
    expect(projectIngressAccessFacts(decision)).toMatchObject({
      group: { requireMention: true },
      mentions: {
        canDetectMention: true,
        wasMentioned: false,
        requireMention: true,
        effectiveWasMentioned: false,
        shouldSkip: true,
      },
    });
  });

  it("projects evaluated group policy instead of a placeholder", async () => {
    const state = await resolveChannelIngressState(
      baseInput({
        conversation: {
          kind: "group",
          id: "room-1",
        },
        allowlists: {},
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
        senderAllowed: true,
      },
    });
  });

  it("projects final command authorization and omits raw allowlist material", async () => {
    const rawSender = "secret-sender@example.test";
    const state = await resolveChannelIngressState(
      baseInput({
        subject: subject(rawSender),
        allowlists: {
          dm: [rawSender],
          commandOwner: ["other-sender"],
        },
      }),
    );
    const decision = decideChannelIngress(state, {
      ...basePolicy,
      command: {
        useAccessGroups: true,
        allowTextCommands: true,
        hasControlCommand: true,
      },
    });
    const facts = projectIngressAccessFacts(decision);

    expect(facts.commands).toMatchObject({
      authorized: false,
      shouldBlockControlCommand: true,
      reasonCode: "control_command_unauthorized",
    });
    expect(facts).toMatchObject({
      dm: {
        decision: "allow",
        allowlist: {
          configured: true,
          matched: true,
          matchedEntryIds: ["entry-1"],
        },
      },
      group: { requireMention: false },
    });
    expect(JSON.stringify(state)).not.toContain(rawSender);
    expect(JSON.stringify(decision)).not.toContain(rawSender);
    expect(JSON.stringify(facts)).not.toContain(rawSender);
  });

  it("projects gates by phase and kind rather than diagnostic ids", async () => {
    const state = await resolveChannelIngressState(
      baseInput({
        allowlists: {
          dm: ["sender-1"],
          commandOwner: ["sender-1"],
        },
      }),
    );
    const decision = decideChannelIngress(state, {
      ...basePolicy,
      command: {
        useAccessGroups: true,
        allowTextCommands: true,
        hasControlCommand: true,
      },
    });
    const renamedDiagnosticIds = {
      ...decision,
      graph: {
        gates: decision.graph.gates.map((gate, index) =>
          Object.assign({}, gate, { id: `diagnostic-${index + 1}` }),
        ),
      },
    };

    expect(projectIngressAccessFacts(renamedDiagnosticIds)).toMatchObject({
      dm: {
        decision: "allow",
        reason: "dm_policy_allowlisted",
      },
      commands: {
        authorized: true,
        reasonCode: "command_authorized",
      },
      event: {
        authorized: true,
        reasonCode: "event_authorized",
      },
    });
  });

  it("projects origin-subject event auth without retaining raw origin material", async () => {
    const rawSender = "origin-sender@example.test";
    const state = await resolveChannelIngressState(
      baseInput({
        subject: subject(rawSender),
        event: {
          kind: "button",
          authMode: "origin-subject",
          mayPair: false,
          originSubject: subject(rawSender),
        },
        allowlists: {
          dm: [rawSender],
        },
      }),
    );

    const decision = decideChannelIngress(state, basePolicy);

    expect(state.event).toMatchObject({
      hasOriginSubject: true,
      originSubjectMatched: true,
    });
    expect(decision).toMatchObject({
      admission: "dispatch",
      decision: "allow",
    });
    expect(projectIngressAccessFacts(decision)).toMatchObject({
      event: {
        kind: "button",
        authMode: "origin-subject",
        mayPair: false,
        authorized: true,
        reasonCode: "event_authorized",
        hasOriginSubject: true,
        originSubjectMatched: true,
      },
    });
    expect(JSON.stringify(state)).not.toContain(rawSender);
  });
});
