import { retainEmptyStage } from '../src/runtime/empty-stage-retention.mjs';
try {
  if (process.argv.length !== 4) throw new Error('RUNTIME_INPUT_INVALID');
  console.log(JSON.stringify(await retainEmptyStage(process.argv[2], process.argv[3])));
} catch (error) {
  const code = error?.code;
  console.error(typeof code === 'string' && /^RUNTIME_[A-Z_]+$/u.test(code) ? code : 'RUNTIME_STATE_UNSUPPORTED');
  process.exitCode = 2;
}
