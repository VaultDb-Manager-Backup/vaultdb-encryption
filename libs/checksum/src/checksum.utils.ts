import * as crypto from 'crypto';
import * as fs from 'fs';

/**
 * Calculate MD5 checksum of a file using streaming
 * This is the standardized checksum calculation used across all VaultDB components
 * (API, Worker, Agent)
 *
 * @param filePath - Absolute path to the file
 * @returns Promise<string> - MD5 checksum in hexadecimal format
 */
export function calculateFileChecksum(filePath: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('md5');
    const stream = fs.createReadStream(filePath);

    stream.on('data', (data: Buffer | string) => hash.update(data));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', (err) => reject(err));
  });
}

/**
 * Verify if a file's checksum matches the expected value
 *
 * @param filePath - Absolute path to the file
 * @param expectedChecksum - Expected MD5 checksum
 * @returns Promise<{ valid: boolean; calculated: string }>
 */
export async function verifyFileChecksum(
  filePath: string,
  expectedChecksum: string,
): Promise<{ valid: boolean; calculated: string }> {
  const calculated = await calculateFileChecksum(filePath);
  return {
    valid: calculated === expectedChecksum,
    calculated,
  };
}
