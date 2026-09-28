// Compatibility entry point; canonical command: agent-road base-inspect.
import { run } from '../src/work/base-inspect.mjs';
process.exitCode = await run(process.argv.slice(2));
