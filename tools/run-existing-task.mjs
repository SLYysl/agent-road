// Compatibility entry point; canonical command: agent-road base-exec.
import { run } from '../src/work/base-exec.mjs';
process.exitCode = await run(process.argv.slice(2));
