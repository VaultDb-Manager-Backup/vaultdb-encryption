import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import {
  EncryptedFileMetadata,
  EncryptFileResult,
} from '../interfaces/encryption.interface';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16; // 128 bits
const AUTH_TAG_LENGTH = 16; // 128 bits
const KEY_LENGTH = 32; // 256 bits

@Injectable()
export class EncryptionService {
  private readonly logger = new Logger(EncryptionService.name);

  constructor(private readonly _configService: ConfigService) {}

  /**
   * Encrypts a file using AES-256-GCM
   * @param inputPath Path to the file to encrypt
   * @param outputPath Path where encrypted file will be written
   * @param key 32-byte encryption key
   * @returns Encryption metadata including IV and auth tag
   */
  async encryptFile(
    inputPath: string,
    outputPath: string,
    key: Buffer,
  ): Promise<EncryptFileResult> {
    this.validateKey(key);

    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });

    // Calculate original file checksum
    const originalChecksum = await this.calculateFileChecksum(inputPath);

    return new Promise((resolve, reject) => {
      const inputStream = fs.createReadStream(inputPath);
      const outputStream = fs.createWriteStream(outputPath);

      inputStream.on('error', (err) => {
        this.logger.error(`Error reading input file: ${err.message}`);
        reject(err);
      });

      outputStream.on('error', (err) => {
        this.logger.error(`Error writing output file: ${err.message}`);
        reject(err);
      });

      outputStream.on('finish', () => {
        const authTag = cipher.getAuthTag();

        const metadata: EncryptedFileMetadata = {
          algorithm: ALGORITHM,
          iv: iv.toString('hex'),
          authTag: authTag.toString('hex'),
          originalChecksum,
          keyVersion: 1,
          encryptedAt: new Date(),
        };

        this.logger.log(
          `File encrypted successfully: ${path.basename(outputPath)}`,
        );

        resolve({
          outputPath,
          metadata,
        });
      });

      inputStream.pipe(cipher).pipe(outputStream);
    });
  }

  /**
   * Decrypts a file that was encrypted with AES-256-GCM
   * @param inputPath Path to the encrypted file
   * @param outputPath Path where decrypted file will be written
   * @param key 32-byte encryption key
   * @param metadata Encryption metadata containing IV and auth tag
   */
  async decryptFile(
    inputPath: string,
    outputPath: string,
    key: Buffer,
    metadata: EncryptedFileMetadata,
  ): Promise<void> {
    this.validateKey(key);

    const iv = Buffer.from(metadata.iv, 'hex');
    const authTag = Buffer.from(metadata.authTag, 'hex');

    const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });
    decipher.setAuthTag(authTag);

    return new Promise((resolve, reject) => {
      const inputStream = fs.createReadStream(inputPath);
      const outputStream = fs.createWriteStream(outputPath);

      inputStream.on('error', (err) => {
        this.logger.error(`Error reading encrypted file: ${err.message}`);
        reject(err);
      });

      outputStream.on('error', (err) => {
        this.logger.error(`Error writing decrypted file: ${err.message}`);
        reject(err);
      });

      decipher.on('error', (err) => {
        this.logger.error(
          `Decryption failed - authentication error: ${err.message}`,
        );
        reject(
          new Error('Decryption failed: file may be corrupted or tampered'),
        );
      });

      outputStream.on('finish', () => {
        this.calculateFileChecksum(outputPath)
          .then((decryptedChecksum) => {
            if (decryptedChecksum !== metadata.originalChecksum) {
              fs.unlinkSync(outputPath);
              reject(
                new Error(
                  'Checksum verification failed after decryption: file may be corrupted',
                ),
              );
              return;
            }

            this.logger.log(
              `File decrypted successfully: ${path.basename(outputPath)}`,
            );
            resolve();
          })
          .catch((err: unknown) => {
            const error = err instanceof Error ? err : new Error(String(err));
            reject(error);
          });
      });

      inputStream.pipe(decipher).pipe(outputStream);
    });
  }

  /**
   * Encrypts a string value (for field-level encryption)
   * @param value String to encrypt
   * @param key 32-byte encryption key
   * @returns Object with encrypted value, IV, and auth tag
   */
  encryptString(
    value: string,
    key: Buffer,
  ): { value: string; iv: string; authTag: string } {
    this.validateKey(key);

    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv, {
      authTagLength: AUTH_TAG_LENGTH,
    });

    let encrypted = cipher.update(value, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    const authTag = cipher.getAuthTag();

    return {
      value: encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
    };
  }

  /**
   * Decrypts a string value
   * @param encryptedValue Base64 encoded encrypted value
   * @param iv Hex encoded IV
   * @param authTag Hex encoded auth tag
   * @param key 32-byte encryption key
   * @returns Decrypted string
   */
  decryptString(
    encryptedValue: string,
    iv: string,
    authTag: string,
    key: Buffer,
  ): string {
    this.validateKey(key);

    const ivBuffer = Buffer.from(iv, 'hex');
    const authTagBuffer = Buffer.from(authTag, 'hex');

    const decipher = crypto.createDecipheriv(ALGORITHM, key, ivBuffer, {
      authTagLength: AUTH_TAG_LENGTH,
    });
    decipher.setAuthTag(authTagBuffer);

    let decrypted = decipher.update(encryptedValue, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  /**
   * Calculates MD5 checksum of a file
   */
  async calculateFileChecksum(filePath: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const hash = crypto.createHash('md5');
      const stream = fs.createReadStream(filePath);

      stream.on('data', (data) => hash.update(data));
      stream.on('end', () => resolve(hash.digest('hex')));
      stream.on('error', reject);
    });
  }

  /**
   * Generates a random encryption key
   */
  generateKey(): Buffer {
    return crypto.randomBytes(KEY_LENGTH);
  }

  /**
   * Generates a random IV
   */
  generateIV(): Buffer {
    return crypto.randomBytes(IV_LENGTH);
  }

  /**
   * Validates that the key is the correct length
   */
  private validateKey(key: Buffer): void {
    if (key.length !== KEY_LENGTH) {
      throw new Error(
        `Invalid key length: expected ${KEY_LENGTH} bytes, got ${key.length}`,
      );
    }
  }
}
