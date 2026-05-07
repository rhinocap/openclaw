import type { AccessFacts, ChannelTurnAdmission } from "../turn/types.js";
import { redactedAllowlistDiagnostics as projectAllowlist } from "./allowlist.js";
import { CHANNEL_INGRESS_GATE_SELECTORS, findChannelIngressGate } from "./gates.js";
import type {
  AccessGraphGate,
  ChannelIngressDecision,
  ChannelIngressSideEffectResult,
  ResolvedIngressAllowlist,
} from "./types.js";

function projectGroupPolicy(
  gate: AccessGraphGate | undefined,
): NonNullable<AccessFacts["group"]>["policy"] {
  const policy = gate?.sender?.policy;
  return policy === "open" || policy === "disabled" ? policy : "allowlist";
}

function projectMentionFacts(
  gate: AccessGraphGate | undefined,
): AccessFacts["mentions"] | undefined {
  const activation = gate?.activation;
  if (!activation?.hasMentionFacts) {
    return undefined;
  }
  return {
    canDetectMention: activation.canDetectMention ?? false,
    wasMentioned: activation.wasMentioned ?? false,
    hasAnyMention: activation.hasAnyMention,
    implicitMentionKinds: activation.implicitMentionKinds
      ? [...activation.implicitMentionKinds]
      : undefined,
    requireMention: activation.requireMention,
    effectiveWasMentioned: activation.effectiveWasMentioned,
    shouldSkip: activation.shouldSkip,
  };
}

function projectDmDecision(
  decision: ChannelIngressDecision,
  dmSender: AccessGraphGate | undefined,
): NonNullable<AccessFacts["dm"]>["decision"] {
  if (decision.decision === "pairing") {
    return "pairing";
  }
  if (dmSender) {
    return dmSender.allowed ? "allow" : "deny";
  }
  return decision.admission === "drop" ? "deny" : "allow";
}

export function projectIngressAccessFacts(decision: ChannelIngressDecision): AccessFacts {
  const command = findChannelIngressGate(decision, CHANNEL_INGRESS_GATE_SELECTORS.command);
  const activation = findChannelIngressGate(decision, CHANNEL_INGRESS_GATE_SELECTORS.activation);
  const dmSender = findChannelIngressGate(decision, CHANNEL_INGRESS_GATE_SELECTORS.dmSender);
  const groupSender = findChannelIngressGate(decision, CHANNEL_INGRESS_GATE_SELECTORS.groupSender);
  const event = findChannelIngressGate(decision, CHANNEL_INGRESS_GATE_SELECTORS.event);
  return {
    dm: {
      decision: projectDmDecision(decision, dmSender),
      reason: dmSender?.reasonCode ?? decision.reasonCode,
      allowFrom: [],
      allowlist: dmSender?.allowlist,
    },
    group: {
      policy: projectGroupPolicy(groupSender),
      routeAllowed: !decision.graph.gates.some(
        (gate) => gate.phase === "route" && gate.effect === "block-dispatch",
      ),
      senderAllowed: groupSender?.allowed ?? dmSender?.allowed ?? false,
      allowFrom: [],
      requireMention: activation?.activation?.requireMention ?? false,
      allowlist: groupSender?.allowlist,
    },
    commands: command
      ? {
          authorized: command.allowed,
          shouldBlockControlCommand:
            command.command?.shouldBlockControlCommand ?? command.effect === "block-command",
          reasonCode: command.reasonCode,
          useAccessGroups: command.command?.useAccessGroups ?? true,
          allowTextCommands: command.command?.allowTextCommands ?? true,
          modeWhenAccessGroupsOff: command.command?.modeWhenAccessGroupsOff,
          authorizers: [],
        }
      : undefined,
    event: event?.event
      ? {
          ...event.event,
          authorized: event.allowed,
          reasonCode: event.reasonCode,
        }
      : undefined,
    mentions: projectMentionFacts(activation),
  };
}

export function projectIngressAllowlistDiagnosticsForTest(allowlist: ResolvedIngressAllowlist) {
  return projectAllowlist(allowlist, "allowed");
}

export function mapChannelIngressDecisionToTurnAdmission(
  decision: ChannelIngressDecision,
  sideEffect: ChannelIngressSideEffectResult,
): ChannelTurnAdmission {
  if (decision.admission === "dispatch") {
    return { kind: "dispatch", reason: decision.reasonCode };
  }
  if (decision.admission === "observe") {
    return { kind: "observeOnly", reason: decision.reasonCode };
  }
  if (decision.admission === "pairing-required") {
    return sideEffect.kind === "pairing-reply-sent"
      ? { kind: "handled", reason: decision.reasonCode }
      : { kind: "drop", reason: decision.reasonCode };
  }
  if (decision.admission === "skip") {
    return sideEffect.kind === "pending-history-recorded" ||
      sideEffect.kind === "local-event-handled" ||
      sideEffect.kind === "command-reply-sent"
      ? { kind: "handled", reason: decision.reasonCode }
      : { kind: "drop", reason: decision.reasonCode, recordHistory: false };
  }
  return sideEffect.kind === "local-event-handled" || sideEffect.kind === "command-reply-sent"
    ? { kind: "handled", reason: decision.reasonCode }
    : { kind: "drop", reason: decision.reasonCode };
}
