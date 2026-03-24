import bcrypt from 'bcrypt';
import { env } from '@/env.js';

let dummyHash: string | null = null;

export async function getDummyHash(): Promise<string> {
  if (!dummyHash) {
    dummyHash = await bcrypt.hash('dummy', env.BCRYPT_ROUNDS);
  }
  return dummyHash;
}
