import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { fixtureDirectory } from "./owned-scratch.ts";

for (const fail of [false, true]) {
  test(`owned fixture cleanup after ${fail ? "failure" : "success"}`, async () => {
    const root = await fixtureDirectory("cleanup-test-");
    const neighbor = join(root, "neighbor-descriptor");
    await writeFile(neighbor, "not owned by nested harness");
    const note = join(root, "created-path");
    const childScratch = join(root, "child-scratch");
    await mkdir(childScratch);
    const script = join(root, "fixture.test.mjs");
    await writeFile(script, `
      import test from "node:test";
      import { writeFile } from "node:fs/promises";
      import { fixtureDirectory } from ${JSON.stringify(new URL("./owned-scratch.ts", import.meta.url).href)};
      test("fixture", async () => {
        const path = await fixtureDirectory("owned-child-");
        await writeFile(${JSON.stringify(note)}, path);
        ${fail ? 'throw new Error("intentional safe fixture failure");' : ''}
      });
    `);
    const env: NodeJS.ProcessEnv = { ...process.env, HERDR_A2A_TEST_SCRATCH_ROOT: childScratch };
    delete env.NODE_TEST_CONTEXT; // This is a separate test invocation, not recursion.
    const child = spawnSync(process.execPath, ["--test", script], {
      env,
      timeout: 10000,
      maxBuffer: 1024 * 1024,
      encoding: "utf8",
    });
    // Retain the deliberate child failure and both streams in the outer test log.
    console.log(child.stdout);
    console.error(child.stderr);
    assert.equal(child.error, undefined);
    assert.equal(child.status, fail ? 1 : 0);
    const owned = await readFile(note, "utf8");
    await assert.rejects(access(owned), { code: "ENOENT" });
    assert.equal(await readFile(neighbor, "utf8"), "not owned by nested harness");
  });
}
