import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { EncryptionService } from './encryption.service';

describe('EncryptionService', () => {
  let service: EncryptionService;
  let tmpDir: string;

  const mockConfigService = { get: jest.fn() };

  beforeAll(() => {
    service = new EncryptionService(mockConfigService as any);
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'encryption-test-'));
  });

  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  describe('generateKey', () => {
    it('should return a 32-byte Buffer', () => {
      const key = service.generateKey();

      expect(Buffer.isBuffer(key)).toBe(true);
      expect(key.length).toBe(32);
    });
  });

  describe('generateIV', () => {
    it('should return a 16-byte Buffer', () => {
      const iv = service.generateIV();

      expect(Buffer.isBuffer(iv)).toBe(true);
      expect(iv.length).toBe(16);
    });
  });

  describe('encryptString / decryptString', () => {
    it('should round-trip encrypt and decrypt a string', () => {
      const key = service.generateKey();
      const plaintext = 'mongodb://admin:s3cret@localhost:27017/backup-manager';

      const encrypted = service.encryptString(plaintext, key);

      expect(encrypted.value).toBeDefined();
      expect(encrypted.iv).toBeDefined();
      expect(encrypted.authTag).toBeDefined();
      expect(encrypted.value).not.toBe(plaintext);

      const decrypted = service.decryptString(
        encrypted.value,
        encrypted.iv,
        encrypted.authTag,
        key,
      );

      expect(decrypted).toBe(plaintext);
    });

    it('should throw on invalid key length for encryptString', () => {
      const shortKey = crypto.randomBytes(16);

      expect(() => service.encryptString('hello', shortKey)).toThrow(
        'Invalid key length: expected 32 bytes, got 16',
      );
    });

    it('should throw on invalid key length for decryptString', () => {
      const shortKey = crypto.randomBytes(24);

      expect(() =>
        service.decryptString('data', 'aabb', 'ccdd', shortKey),
      ).toThrow('Invalid key length: expected 32 bytes, got 24');
    });

    it('should reject decryption when authTag is tampered', () => {
      const key = service.generateKey();
      const encrypted = service.encryptString('sensitive data', key);

      // Flip one hex character in the authTag
      const tampered =
        encrypted.authTag[0] === 'a'
          ? 'b' + encrypted.authTag.slice(1)
          : 'a' + encrypted.authTag.slice(1);

      expect(() =>
        service.decryptString(encrypted.value, encrypted.iv, tampered, key),
      ).toThrow();
    });

    it('should produce different ciphertexts for the same plaintext with different keys', () => {
      const keyA = service.generateKey();
      const keyB = service.generateKey();
      const plaintext = 'identical-input';

      const encryptedA = service.encryptString(plaintext, keyA);
      const encryptedB = service.encryptString(plaintext, keyB);

      expect(encryptedA.value).not.toBe(encryptedB.value);
    });
  });

  describe('encryptFile / decryptFile', () => {
    it('should round-trip encrypt and decrypt a file', async () => {
      const key = service.generateKey();
      const originalContent = 'pg_dump output: CREATE TABLE backups ...';

      const originalPath = path.join(tmpDir, 'original.sql');
      const encryptedPath = path.join(tmpDir, 'original.sql.enc');
      const decryptedPath = path.join(tmpDir, 'original.sql.dec');

      fs.writeFileSync(originalPath, originalContent, 'utf8');

      const result = await service.encryptFile(
        originalPath,
        encryptedPath,
        key,
      );

      expect(result.outputPath).toBe(encryptedPath);
      expect(result.metadata.algorithm).toBe('aes-256-gcm');
      expect(result.metadata.iv).toBeDefined();
      expect(result.metadata.authTag).toBeDefined();
      expect(result.metadata.originalChecksum).toBeDefined();
      expect(result.metadata.keyVersion).toBe(1);
      expect(result.metadata.encryptedAt).toBeInstanceOf(Date);

      // Encrypted content must differ from original
      const encryptedContent = fs.readFileSync(encryptedPath);
      expect(encryptedContent.toString('utf8')).not.toBe(originalContent);

      await service.decryptFile(
        encryptedPath,
        decryptedPath,
        key,
        result.metadata,
      );

      const decryptedContent = fs.readFileSync(decryptedPath, 'utf8');
      expect(decryptedContent).toBe(originalContent);
    });

    it('should throw on invalid key length for encryptFile', async () => {
      const shortKey = crypto.randomBytes(10);
      const inputPath = path.join(tmpDir, 'dummy-enc-input.txt');
      fs.writeFileSync(inputPath, 'data');

      await expect(
        service.encryptFile(inputPath, path.join(tmpDir, 'out.enc'), shortKey),
      ).rejects.toThrow('Invalid key length: expected 32 bytes, got 10');
    });

    it('should throw on invalid key length for decryptFile', async () => {
      const shortKey = crypto.randomBytes(20);

      await expect(
        service.decryptFile(
          path.join(tmpDir, 'any.enc'),
          path.join(tmpDir, 'any.dec'),
          shortKey,
          {
            algorithm: 'aes-256-gcm',
            iv: 'aa'.repeat(16),
            authTag: 'bb'.repeat(16),
            originalChecksum: 'cc',
            keyVersion: 1,
            encryptedAt: new Date(),
          },
        ),
      ).rejects.toThrow('Invalid key length: expected 32 bytes, got 20');
    });
  });

  describe('calculateFileChecksum', () => {
    it('should return a consistent MD5 hex digest for the same content', async () => {
      const filePath = path.join(tmpDir, 'checksum-test.txt');
      const content = 'deterministic checksum content';
      fs.writeFileSync(filePath, content, 'utf8');

      const expected = crypto.createHash('md5').update(content).digest('hex');

      const checksum1 = await service.calculateFileChecksum(filePath);
      const checksum2 = await service.calculateFileChecksum(filePath);

      expect(checksum1).toBe(expected);
      expect(checksum2).toBe(expected);
    });
  });
});
