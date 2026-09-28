import { isProxy } from 'node:util/types';

const POLICY_FIELDS = Object.freeze(['timeoutMs', 'maxRedirects']);

export const RUNTIME_ACQUISITION_POLICY = Object.freeze({
  timeoutMs: 30 * 60 * 1_000,
  maxRedirects: 5,
});

export function isRuntimeAcquisitionPolicy(input) {
  if (
    input === null
    || typeof input !== 'object'
    || isProxy(input)
    || Array.isArray(input)
    || Object.getPrototypeOf(input) !== Object.prototype
    || Object.getOwnPropertySymbols(input).length !== 0
  ) return false;
  const names = Object.getOwnPropertyNames(input);
  if (names.length !== POLICY_FIELDS.length || !POLICY_FIELDS.every((field) => names.includes(field))) {
    return false;
  }
  for (const field of POLICY_FIELDS) {
    const descriptor = Object.getOwnPropertyDescriptor(input, field);
    if (
      !descriptor
      || !Object.hasOwn(descriptor, 'value')
      || descriptor.enumerable !== true
      || descriptor.value !== RUNTIME_ACQUISITION_POLICY[field]
    ) return false;
  }
  return true;
}
