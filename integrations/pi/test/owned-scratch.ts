// Test-only ownership: never enumerate or remove live runtime descriptors.
import { after } from "node:test";
import { chmod, mkdir, mkdtemp, rm, statfs } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";

const owned = new Set<string>();
after(async () => {
  for (const directory of owned) {
    await rm(directory, { recursive: true, force: true });
    owned.delete(directory);
  }
});

export async function fixtureDirectory(prefix: string): Promise<string> {
  const parent = process.env.HERDR_A2A_TEST_SCRATCH_ROOT
    ?? join(homedir(), ".cache", "herdr-a2a", "test-scratch");
  await mkdir(parent, { recursive: true, mode: 0o700 });
  if (process.platform === "linux") {
    const filesystem = await statfs(parent);
    if (filesystem.type === 0x01021994 || filesystem.type === 0x858458f6) {
      throw new Error("test scratch must be disk-backed");
    }
  }
  const directory = await mkdtemp(join(parent, prefix));
  owned.add(directory); // Register before any subsequent fixture setup can fail.
  await chmod(directory, 0o700);
  return directory;
}
