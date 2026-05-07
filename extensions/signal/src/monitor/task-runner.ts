import type { RuntimeEnv } from "openclaw/plugin-sdk/runtime-env";

export function createSignalMonitorTaskRunner(runtime: RuntimeEnv) {
  const inFlight = new Set<Promise<void>>();

  const runEventTask = (task: () => Promise<void>): void => {
    let trackedTask!: Promise<void>;
    trackedTask = Promise.resolve()
      .then(task)
      .catch((err) => {
        runtime.error?.(`event handler failed: ${String(err)}`);
      })
      .finally(() => {
        inFlight.delete(trackedTask);
      });
    inFlight.add(trackedTask);
  };

  const waitForIdle = async (): Promise<void> => {
    while (inFlight.size > 0) {
      await Promise.allSettled(Array.from(inFlight));
    }
  };

  return {
    runEventTask,
    waitForIdle,
  };
}
