import { Injectable, Logger } from '@nestjs/common';
import * as crypto from 'crypto';
import {
  KeyProvider,
  KeyProviderContext,
} from '../interfaces/encryption.interface';
import { EncryptionService } from '../services/encryption.service';

const KEY_LENGTH = 32;
const PBKDF2_ITERATIONS = 100000;
const PBKDF2_DIGEST = 'sha512';

@Injectable()
export class ManagedKeyProvider implements KeyProvider {
  private readonly logger = new Logger(ManagedKeyProvider.name);

  constructor(private readonly encryptionService: EncryptionService) {}

  // eslint-disable-next-line @typescript-eslint/require-await
  async wrap(orgKey: Buffer, context: KeyProviderContext): Promise<string> {
    const masterKey = this.getMasterKey();
    const kek = this.deriveKey(masterKey, context.salt);
    const encrypted = this.encryptionService.encryptString(
      orgKey.toString('hex'),
      kek,
    );
    return JSON.stringify(encrypted);
  }

  // eslint-disable-next-line @typescript-eslint/require-await
  async unwrap(
    wrappedKey: string,
    context: KeyProviderContext,
  ): Promise<Buffer> {
    const masterKey = this.getMasterKey();
    const kek = this.deriveKey(masterKey, context.salt);
    const encrypted = JSON.parse(wrappedKey) as {
      value: string;
      iv: string;
      authTag: string;
    };
    const decryptedHex = this.encryptionService.decryptString(
      encrypted.value,
      encrypted.iv,
      encrypted.authTag,
      kek,
    );
    return Buffer.from(decryptedHex, 'hex');
  }

  private getMasterKey(): Buffer {
    const masterKeyHex = process.env.ENCRYPTION_MASTER_KEY;
    if (!masterKeyHex || masterKeyHex.length !== 64) {
      throw new Error('Encryption master key not configured or invalid');
    }
    return Buffer.from(masterKeyHex, 'hex');
  }

  private deriveKey(masterKey: Buffer, salt: Buffer): Buffer {
    return crypto.pbkdf2Sync(
      masterKey,
      salt,
      PBKDF2_ITERATIONS,
      KEY_LENGTH,
      PBKDF2_DIGEST,
    );
  }
}
