// Compatibility entry point; canonical command: agent-road measure-exec.
import { run } from '../src/work/measure-exec.mjs';
process.exitCode = await run(process.argv.slice(2));
