// Compatibility entry point; canonical command: agent-road session.
import { run } from '../src/work/session.mjs';
process.exitCode = await run(process.argv.slice(2));
