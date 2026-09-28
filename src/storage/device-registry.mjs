import { validateDeviceRecord } from '../core/device-model.mjs';
import { withFileLock } from './file-lock.mjs';
import { readJson, writeJsonAtomic } from './json-file.mjs';

function cloneDevice(device) {
  return structuredClone(device);
}


export class DeviceRegistry {
  constructor(path) {
    this.path = path;
  }

  async list() {
    const { devices } = await readJson(this.path, { devices: [] });
    return devices.map((device) => cloneDevice(validateDeviceRecord(device)));
  }

  async get(id) {
    const devices = await this.list();
    return devices.find((device) => device.id === id) ?? null;
  }

  async add(input) {
    const snapshot = structuredClone(input);
    validateDeviceRecord(snapshot);

    return withFileLock(this.path, async () => {
      const devices = await this.list();

      if (devices.some(({ id }) => id === snapshot.id)) {
        throw new Error(`device already exists: ${snapshot.id}`);
      }

      const device = validateDeviceRecord(snapshot);
      await writeJsonAtomic(this.path, { devices: [...devices, device] });
      return cloneDevice(device);
    }, { name: 'device registry' });
  }

  async updateStatus(id, status, updatedAt) {
    return withFileLock(this.path, async () => {
      const devices = await this.list();
      const index = devices.findIndex((device) => device.id === id);

      if (index === -1) {
        throw new Error(`device not found: ${id}`);
      }

      const device = validateDeviceRecord({ ...devices[index], status, updatedAt });
      devices[index] = device;
      await writeJsonAtomic(this.path, { devices });
      return cloneDevice(device);
    }, { name: 'device registry' });
  }

  async replace(input) {
    const snapshot = structuredClone(input);
    validateDeviceRecord(snapshot);

    return withFileLock(this.path, async () => {
      const devices = await this.list();
      const index = devices.findIndex((device) => device.id === snapshot.id);

      if (index === -1) {
        throw new Error(`device not found: ${snapshot.id}`);
      }

      const device = validateDeviceRecord(snapshot);
      devices[index] = device;
      await writeJsonAtomic(this.path, { devices });
      return cloneDevice(device);
    }, { name: 'device registry' });
  }
}
