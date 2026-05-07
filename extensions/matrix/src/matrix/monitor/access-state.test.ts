import { describe, expect, it } from "vitest";
import {
  resolveMatrixMonitorAccessState,
  resolveMatrixMonitorCommandAccess,
} from "./access-state.js";

describe("resolveMatrixMonitorAccessState", () => {
  it("normalizes effective allowlists once and exposes reusable matches", async () => {
    const state = await resolveMatrixMonitorAccessState({
      allowFrom: ["matrix:@Alice:Example.org"],
      storeAllowFrom: ["user:@bob:example.org"],
      groupAllowFrom: ["@Carol:Example.org"],
      roomUsers: ["user:@Dana:Example.org"],
      senderId: "@dana:example.org",
      isRoom: true,
      groupPolicy: "allowlist",
    });

    expect(state.effectiveAllowFrom).toEqual([
      "matrix:@alice:example.org",
      "user:@bob:example.org",
    ]);
    expect(state.effectiveGroupAllowFrom).toEqual(["@carol:example.org"]);
    expect(state.effectiveRoomUsers).toEqual(["user:@dana:example.org"]);
    expect(state.directAllowMatch.allowed).toBe(false);
    expect(state.roomUserMatch?.allowed).toBe(true);
    expect(state.groupAllowMatch?.allowed).toBe(false);
    expect(state.commandAuthorizers).toEqual([
      { configured: false, allowed: false },
      { configured: true, allowed: true },
      { configured: true, allowed: false },
    ]);
    expect(state.ingressDecision.decision).toBe("allow");
  });

  it("does not let DM pairing-store entries authorize room control commands", async () => {
    const state = await resolveMatrixMonitorAccessState({
      allowFrom: [],
      storeAllowFrom: ["@attacker:example.org"],
      groupAllowFrom: [],
      roomUsers: [],
      senderId: "@attacker:example.org",
      isRoom: true,
    });

    expect(state.effectiveAllowFrom).toEqual(["@attacker:example.org"]);
    expect(state.directAllowMatch.allowed).toBe(true);
    expect(state.commandAuthorizers).toEqual([
      { configured: false, allowed: false },
      { configured: false, allowed: false },
      { configured: false, allowed: false },
    ]);
  });

  it("does not let pairing-store entries authorize open DMs without wildcard", async () => {
    const state = await resolveMatrixMonitorAccessState({
      allowFrom: [],
      storeAllowFrom: ["@alice:example.org"],
      dmPolicy: "open",
      groupAllowFrom: [],
      roomUsers: [],
      senderId: "@alice:example.org",
      isRoom: false,
    });

    expect(state.effectiveAllowFrom).toEqual([]);
    expect(state.directAllowMatch.allowed).toBe(false);
    expect(state.ingressDecision.reasonCode).toBe("dm_policy_not_allowlisted");
  });

  it("does not let configured DM allowFrom authorize room control commands", async () => {
    const state = await resolveMatrixMonitorAccessState({
      allowFrom: ["@owner:example.org"],
      storeAllowFrom: [],
      groupAllowFrom: ["@admin:example.org"],
      roomUsers: [],
      senderId: "@owner:example.org",
      isRoom: true,
    });

    expect(state.directAllowMatch.allowed).toBe(true);
    expect(state.commandAuthorizers).toEqual([
      { configured: false, allowed: false },
      { configured: false, allowed: false },
      { configured: true, allowed: false },
    ]);
    expect(
      resolveMatrixMonitorCommandAccess(state, {
        useAccessGroups: true,
        allowTextCommands: true,
        hasControlCommand: true,
      }),
    ).toEqual({
      commandAuthorized: false,
      shouldBlockControlCommand: true,
    });
  });

  it("authorizes room control commands through the shared ingress command gate", async () => {
    const state = await resolveMatrixMonitorAccessState({
      allowFrom: [],
      storeAllowFrom: [],
      groupAllowFrom: ["@admin:example.org"],
      roomUsers: [],
      senderId: "@admin:example.org",
      isRoom: true,
    });

    expect(
      resolveMatrixMonitorCommandAccess(state, {
        useAccessGroups: true,
        allowTextCommands: true,
        hasControlCommand: true,
      }),
    ).toEqual({
      commandAuthorized: true,
      shouldBlockControlCommand: false,
    });
  });

  it("keeps command allow mode when access groups are disabled", async () => {
    const state = await resolveMatrixMonitorAccessState({
      allowFrom: [],
      storeAllowFrom: [],
      groupAllowFrom: [],
      roomUsers: [],
      senderId: "@admin:example.org",
      isRoom: true,
    });

    expect(
      resolveMatrixMonitorCommandAccess(state, {
        useAccessGroups: false,
        allowTextCommands: true,
        hasControlCommand: true,
      }),
    ).toEqual({
      commandAuthorized: true,
      shouldBlockControlCommand: false,
    });
  });

  it("keeps room-user matching disabled for dm traffic", async () => {
    const state = await resolveMatrixMonitorAccessState({
      allowFrom: [],
      storeAllowFrom: [],
      groupAllowFrom: ["@carol:example.org"],
      roomUsers: ["@dana:example.org"],
      senderId: "@dana:example.org",
      isRoom: false,
    });

    expect(state.roomUserMatch).toBeNull();
    expect(state.commandAuthorizers[1]).toEqual({ configured: true, allowed: false });
    expect(state.commandAuthorizers[2]).toEqual({ configured: true, allowed: false });
  });

  it("uses the shared ingress decision for room user sender gates", async () => {
    const blocked = await resolveMatrixMonitorAccessState({
      allowFrom: [],
      storeAllowFrom: [],
      groupAllowFrom: [],
      roomUsers: ["@allowed:example.org"],
      senderId: "@blocked:example.org",
      isRoom: true,
      groupPolicy: "open",
    });
    const allowed = await resolveMatrixMonitorAccessState({
      allowFrom: [],
      storeAllowFrom: [],
      groupAllowFrom: [],
      roomUsers: ["@allowed:example.org"],
      senderId: "@allowed:example.org",
      isRoom: true,
      groupPolicy: "open",
    });

    expect(blocked.ingressDecision.reasonCode).toBe("group_policy_not_allowlisted");
    expect(allowed.ingressDecision.decision).toBe("allow");
  });

  it("keeps route-only room allowlists open when no sender allowlist exists", async () => {
    const state = await resolveMatrixMonitorAccessState({
      allowFrom: [],
      storeAllowFrom: [],
      groupAllowFrom: [],
      roomUsers: [],
      senderId: "@sender:example.org",
      isRoom: true,
      groupPolicy: "allowlist",
    });

    expect(state.ingressDecision.decision).toBe("allow");
    expect(state.ingressDecision.reasonCode).toBe("activation_allowed");
  });
});
