export { decideChannelIngress, decideChannelIngressBundle } from "./decision.js";
export {
  CHANNEL_INGRESS_GATE_SELECTORS,
  findChannelIngressCommandGate,
  findChannelIngressGate,
  findChannelIngressSenderGate,
} from "./gates.js";
export type { ChannelIngressDecisionBundle } from "./decision.js";
export type { ChannelIngressGateSelector } from "./gates.js";
export {
  mapChannelIngressDecisionToTurnAdmission,
  projectIngressAccessFacts,
} from "./projection.js";
export { resolveChannelIngressState } from "./state.js";
export type * from "./types.js";
