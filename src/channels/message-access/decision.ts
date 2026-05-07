import { resolveCommandAuthorizedFromAuthorizers } from "../command-gating.js";
import { resolveInboundMentionDecision } from "../mention-gating.js";
import { applyMutableIdentifierPolicy, redactedAllowlistDiagnostics } from "./allowlist.js";
import {
  applyEventAuthModeToSenderGate,
  senderGateForDirect,
  senderGateForGroup,
} from "./sender-gates.js";
import type {
  AccessGraphGate,
  ChannelIngressDecision,
  ChannelIngressPolicyInput,
  ChannelIngressState,
  RedactedIngressMatch,
} from "./types.js";

function gate(params: AccessGraphGate): AccessGraphGate {
  return params;
}

function decisiveDecision(params: {
  admission: ChannelIngressDecision["admission"];
  decision: ChannelIngressDecision["decision"];
  gate: AccessGraphGate;
  gates: AccessGraphGate[];
}): ChannelIngressDecision {
  return {
    admission: params.admission,
    decision: params.decision,
    decisiveGateId: params.gate.id,
    reasonCode: params.gate.reasonCode,
    graph: { gates: params.gates },
    diagnostics: {
      decisiveGateId: params.gate.id,
      reasonCode: params.gate.reasonCode,
    },
  };
}

function routeGates(state: ChannelIngressState): AccessGraphGate[] {
  return state.routeFacts.map((route) =>
    gate({
      id: route.id,
      phase: "route",
      kind: route.kind,
      effect: route.effect,
      allowed: route.effect !== "block-dispatch",
      reasonCode: route.effect === "block-dispatch" ? "route_blocked" : "allowed",
      match: route.match,
    }),
  );
}

function routeSenderEmptyGate(state: ChannelIngressState): AccessGraphGate | null {
  const route = state.routeFacts.find(
    (fact) =>
      fact.senderPolicy === "deny-when-empty" &&
      fact.gate === "matched" &&
      fact.senderAllowlist?.hasConfiguredEntries !== true,
  );
  if (!route) {
    return null;
  }
  const reasonCode = "route_sender_empty";
  return gate({
    id: `${route.id}:sender`,
    phase: "route",
    kind: "routeSender",
    effect: "block-dispatch",
    allowed: false,
    reasonCode,
    match: route.match,
    allowlist: route.senderAllowlist
      ? redactedAllowlistDiagnostics(route.senderAllowlist, reasonCode)
      : undefined,
  });
}

function commandGate(params: {
  state: ChannelIngressState;
  policy: ChannelIngressPolicyInput;
}): AccessGraphGate {
  const command = params.policy.command;
  if (!command) {
    return gate({
      id: "command",
      phase: "command",
      kind: "command",
      effect: "allow",
      allowed: true,
      reasonCode: "command_authorized",
    });
  }
  const useAccessGroups = command.useAccessGroups ?? true;
  const owner = applyMutableIdentifierPolicy(params.state.allowlists.commandOwner, params.policy);
  const group = applyMutableIdentifierPolicy(params.state.allowlists.commandGroup, params.policy);
  const authorized = resolveCommandAuthorizedFromAuthorizers({
    useAccessGroups,
    modeWhenAccessGroupsOff: command.modeWhenAccessGroupsOff,
    authorizers: [
      { configured: owner.hasConfiguredEntries, allowed: owner.match.matched },
      { configured: group.hasConfiguredEntries, allowed: group.match.matched },
    ],
  });
  const shouldBlock = command.allowTextCommands && command.hasControlCommand && !authorized;
  return gate({
    id: "command",
    phase: "command",
    kind: "command",
    effect: shouldBlock ? "block-command" : "allow",
    allowed: authorized,
    reasonCode: shouldBlock ? "control_command_unauthorized" : "command_authorized",
    match: mergeCommandMatch(owner.match, group.match),
    command: {
      useAccessGroups,
      allowTextCommands: command.allowTextCommands,
      modeWhenAccessGroupsOff: command.modeWhenAccessGroupsOff,
      shouldBlockControlCommand: shouldBlock,
    },
  });
}

function mergeCommandMatch(
  owner: RedactedIngressMatch,
  group: RedactedIngressMatch,
): RedactedIngressMatch {
  const matchedEntryIds = Array.from(new Set([...owner.matchedEntryIds, ...group.matchedEntryIds]));
  return {
    matched: owner.matched || group.matched || matchedEntryIds.length > 0,
    matchedEntryIds,
  };
}

function subjectMatchesOrigin(state: ChannelIngressState): boolean {
  if (!state.event.hasOriginSubject) {
    return false;
  }
  return state.event.originSubjectMatched;
}

function eventGate(params: {
  state: ChannelIngressState;
  senderGate: AccessGraphGate;
  commandGate: AccessGraphGate;
}): AccessGraphGate {
  const authMode = params.state.event.authMode;
  const event = params.state.event;
  if (authMode === "none" || authMode === "route-only") {
    return gate({
      id: "event",
      phase: "event",
      kind: "event",
      effect: "allow",
      allowed: true,
      reasonCode: "event_authorized",
      event,
    });
  }
  if (authMode === "command") {
    return gate({
      id: "event",
      phase: "event",
      kind: "event",
      effect: params.commandGate.allowed ? "allow" : "block-dispatch",
      allowed: params.commandGate.allowed,
      reasonCode: params.commandGate.allowed ? "event_authorized" : "event_unauthorized",
      event,
    });
  }
  if (authMode === "origin-subject") {
    if (!params.state.event.hasOriginSubject) {
      return gate({
        id: "event",
        phase: "event",
        kind: "event",
        effect: "block-dispatch",
        allowed: false,
        reasonCode: "origin_subject_missing",
        event,
      });
    }
    const matched = subjectMatchesOrigin(params.state);
    return gate({
      id: "event",
      phase: "event",
      kind: "event",
      effect: matched ? "allow" : "block-dispatch",
      allowed: matched,
      reasonCode: matched ? "event_authorized" : "origin_subject_not_matched",
      event,
    });
  }
  return gate({
    id: "event",
    phase: "event",
    kind: "event",
    effect: params.senderGate.allowed ? "allow" : "block-dispatch",
    allowed: params.senderGate.allowed,
    reasonCode: params.senderGate.allowed ? "event_authorized" : "event_unauthorized",
    event,
  });
}

function activationMetadata(params: {
  activation?: ChannelIngressPolicyInput["activation"];
  mentionFacts: ChannelIngressState["mentionFacts"];
  shouldSkip: boolean;
  effectiveWasMentioned?: boolean;
}) {
  const mentionFacts = params.mentionFacts;
  return {
    hasMentionFacts: mentionFacts != null,
    requireMention: params.activation?.requireMention ?? false,
    allowTextCommands: params.activation?.allowTextCommands ?? false,
    shouldSkip: params.shouldSkip,
    canDetectMention: mentionFacts?.canDetectMention,
    wasMentioned: mentionFacts?.wasMentioned,
    hasAnyMention: mentionFacts?.hasAnyMention,
    implicitMentionKinds: mentionFacts?.implicitMentionKinds,
    effectiveWasMentioned: params.effectiveWasMentioned,
  };
}

function activationGate(params: {
  state: ChannelIngressState;
  policy: ChannelIngressPolicyInput;
  commandGate: AccessGraphGate;
}): AccessGraphGate {
  const activation = params.policy.activation;
  const mentionFacts = params.state.mentionFacts;
  if (!activation || !mentionFacts) {
    return gate({
      id: "activation",
      phase: "activation",
      kind: "mention",
      effect: "allow",
      allowed: true,
      reasonCode: "activation_allowed",
      activation: activationMetadata({
        activation,
        mentionFacts,
        shouldSkip: false,
        effectiveWasMentioned:
          mentionFacts &&
          (mentionFacts.wasMentioned || Boolean(mentionFacts.implicitMentionKinds?.length)),
      }),
    });
  }
  const result = resolveInboundMentionDecision({
    facts: mentionFacts,
    policy: {
      isGroup: params.state.conversationKind !== "direct",
      requireMention: activation.requireMention,
      allowTextCommands: activation.allowTextCommands,
      hasControlCommand: params.policy.command?.hasControlCommand ?? false,
      commandAuthorized: params.commandGate.allowed,
    },
  });
  return gate({
    id: "activation",
    phase: "activation",
    kind: "mention",
    effect: result.shouldSkip ? "skip" : "allow",
    allowed: !result.shouldSkip,
    reasonCode: result.shouldSkip ? "activation_skipped" : "activation_allowed",
    activation: activationMetadata({
      activation,
      mentionFacts,
      shouldSkip: result.shouldSkip,
      effectiveWasMentioned: result.effectiveWasMentioned,
    }),
  });
}

export function decideChannelIngress(
  state: ChannelIngressState,
  policy: ChannelIngressPolicyInput,
): ChannelIngressDecision {
  const gates: AccessGraphGate[] = routeGates(state);
  const emptyRouteSenderGate = routeSenderEmptyGate(state);
  if (emptyRouteSenderGate) {
    gates.push(emptyRouteSenderGate);
  }
  const routeBlock = gates.find((entry) => entry.effect === "block-dispatch");
  if (routeBlock) {
    return decisiveDecision({ admission: "drop", decision: "block", gate: routeBlock, gates });
  }

  const sender =
    state.conversationKind === "direct"
      ? senderGateForDirect({ state, policy })
      : senderGateForGroup({ state, policy });
  const eventModeSender = applyEventAuthModeToSenderGate({ state, senderGate: sender });
  gates.push(eventModeSender);
  if (!eventModeSender.allowed) {
    const admission =
      eventModeSender.reasonCode === "dm_policy_pairing_required" ? "pairing-required" : "drop";
    const decision =
      eventModeSender.reasonCode === "dm_policy_pairing_required" ? "pairing" : "block";
    return decisiveDecision({ admission, decision, gate: eventModeSender, gates });
  }

  const command = commandGate({ state, policy });
  gates.push(command);
  if (command.effect === "block-command") {
    return decisiveDecision({ admission: "drop", decision: "block", gate: command, gates });
  }

  const event = eventGate({ state, senderGate: eventModeSender, commandGate: command });
  gates.push(event);
  if (!event.allowed) {
    return decisiveDecision({ admission: "drop", decision: "block", gate: event, gates });
  }

  const activation = activationGate({ state, policy, commandGate: command });
  gates.push(activation);
  if (activation.effect === "skip") {
    return decisiveDecision({ admission: "skip", decision: "allow", gate: activation, gates });
  }
  if (activation.effect === "observe") {
    return decisiveDecision({ admission: "observe", decision: "allow", gate: activation, gates });
  }
  return decisiveDecision({ admission: "dispatch", decision: "allow", gate: activation, gates });
}

export type ChannelIngressDecisionBundle = {
  dm: ChannelIngressDecision;
  group: ChannelIngressDecision;
  dmCommand: ChannelIngressDecision;
  groupCommand: ChannelIngressDecision;
};

export function decideChannelIngressBundle(params: {
  directState: ChannelIngressState;
  groupState: ChannelIngressState;
  basePolicy: ChannelIngressPolicyInput;
  commandPolicy: ChannelIngressPolicyInput;
}): ChannelIngressDecisionBundle {
  return {
    dm: decideChannelIngress(params.directState, params.basePolicy),
    group: decideChannelIngress(params.groupState, params.basePolicy),
    dmCommand: decideChannelIngress(params.directState, params.commandPolicy),
    groupCommand: decideChannelIngress(params.groupState, params.commandPolicy),
  };
}
