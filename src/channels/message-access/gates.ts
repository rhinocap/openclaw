import type {
  AccessGraphGate,
  ChannelIngressDecision,
  IngressGateKind,
  IngressGatePhase,
} from "./types.js";

export type ChannelIngressGateSelector = {
  phase: IngressGatePhase;
  kind: IngressGateKind;
};

export const CHANNEL_INGRESS_GATE_SELECTORS = {
  command: { phase: "command", kind: "command" },
  activation: { phase: "activation", kind: "mention" },
  dmSender: { phase: "sender", kind: "dmSender" },
  groupSender: { phase: "sender", kind: "groupSender" },
  event: { phase: "event", kind: "event" },
} as const satisfies Record<string, ChannelIngressGateSelector>;

export function findChannelIngressGate(
  decision: ChannelIngressDecision,
  selector: ChannelIngressGateSelector,
): AccessGraphGate | undefined {
  return decision.graph.gates.find(
    (gate) => gate.phase === selector.phase && gate.kind === selector.kind,
  );
}

export function findChannelIngressSenderGate(
  decision: ChannelIngressDecision,
  params: { isGroup: boolean },
): AccessGraphGate | undefined {
  return findChannelIngressGate(
    decision,
    params.isGroup
      ? CHANNEL_INGRESS_GATE_SELECTORS.groupSender
      : CHANNEL_INGRESS_GATE_SELECTORS.dmSender,
  );
}

export function findChannelIngressCommandGate(
  decision: ChannelIngressDecision,
): AccessGraphGate | undefined {
  return findChannelIngressGate(decision, CHANNEL_INGRESS_GATE_SELECTORS.command);
}
