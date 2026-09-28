// Compatibility entry point; canonical command: agent-road job.
import { run } from '../src/work/job.mjs';
process.exitCode = await run(process.argv.slice(2));
