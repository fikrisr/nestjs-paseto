import { Test, TestingModule } from '@nestjs/testing';
import { PASETO_MODULE_OPTIONS } from '../src/constants';
import {
  PasetoAudienceMismatchException,
  PasetoConfigurationException,
  PasetoErrorCode,
  PasetoException,
  PasetoInvalidTokenException,
  PasetoIssuerMismatchException,
  PasetoTokenExpiredException,
  PasetoTokenTamperedWithException,
} from '../src/exceptions';
import { PasetoService } from '../src/paseto.service';

const MOCK_KEY = '12345678901234567890123456789012'; // 32 bytes

async function buildService(overrides: Record<string, any> = {}): Promise<PasetoService> {
  const module: TestingModule = await Test.createTestingModule({
    providers: [
      PasetoService,
      {
        provide: PASETO_MODULE_OPTIONS,
        useValue: {
          symmetricKey: MOCK_KEY,
          issuer: 'nestjs-paseto',
          audience: 'users',
          expiration: '1h',
          ...overrides,
        },
      },
    ],
  }).compile();
  return module.get<PasetoService>(PasetoService);
}

describe('PasetoService', () => {
  let service: PasetoService;

  beforeEach(async () => {
    service = await buildService();
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  // ---------------------------------------------------------------------------
  // Constructor / configuration
  // ---------------------------------------------------------------------------

  describe('constructor', () => {
    it('should throw PasetoConfigurationException when key is shorter than 32 bytes', async () => {
      await expect(
        Test.createTestingModule({
          providers: [
            PasetoService,
            { provide: PASETO_MODULE_OPTIONS, useValue: { symmetricKey: 'tooshort' } },
          ],
        }).compile(),
      ).rejects.toThrow(PasetoConfigurationException);
    });

    it('should throw PasetoConfigurationException when key is longer than 32 bytes', async () => {
      await expect(
        Test.createTestingModule({
          providers: [
            PasetoService,
            {
              provide: PASETO_MODULE_OPTIONS,
              useValue: { symmetricKey: '123456789012345678901234567890123' },
            },
          ],
        }).compile(),
      ).rejects.toThrow(PasetoConfigurationException);
    });

    it('should accept a 32-byte Buffer key', async () => {
      const svc = await buildService({ symmetricKey: Buffer.alloc(32, 'a') });
      expect(svc).toBeDefined();
    });
  });

  // ---------------------------------------------------------------------------
  // generateToken
  // ---------------------------------------------------------------------------

  describe('generateToken', () => {
    it('should return a string starting with v4.local.', async () => {
      const token = await service.generateToken({ userId: 1 });
      expect(token.startsWith('v4.local.')).toBe(true);
    });

    it('should embed iss, aud, and exp claims from module options', async () => {
      const token = await service.generateToken({ userId: 1 });
      const claims = await service.verifyToken<any>(token);
      expect(claims.iss).toBe('nestjs-paseto');
      expect(claims.aud).toBe('users');
      expect(claims.exp).toBeDefined();
    });

    it('should produce different ciphertext for the same payload (random nonce)', async () => {
      const token1 = await service.generateToken({ userId: 1 });
      const token2 = await service.generateToken({ userId: 1 });
      expect(token1).not.toBe(token2);
    });

    it('should not include iss/aud/exp when not configured', async () => {
      const svc = await buildService({
        issuer: undefined,
        audience: undefined,
        expiration: undefined,
      });
      const token = await svc.generateToken({ userId: 99 });
      const claims = await svc.verifyToken<any>(token);
      expect(claims.iss).toBeUndefined();
      expect(claims.aud).toBeUndefined();
      expect(claims.exp).toBeUndefined();
      expect(claims.userId).toBe(99);
    });
  });

  // ---------------------------------------------------------------------------
  // verifyToken — happy path
  // ---------------------------------------------------------------------------

  describe('verifyToken (valid tokens)', () => {
    it('should round-trip a payload correctly', async () => {
      const payload = { userId: 42, role: 'admin', nested: { flag: true } };
      const token = await service.generateToken(payload);
      const claims = await service.verifyToken<typeof payload>(token);
      expect(claims.userId).toBe(42);
      expect(claims.role).toBe('admin');
      expect(claims.nested.flag).toBe(true);
    });
  });

  // ---------------------------------------------------------------------------
  // verifyToken — PasetoInvalidTokenException
  // ---------------------------------------------------------------------------

  describe('verifyToken — invalid format', () => {
    it('should throw PasetoInvalidTokenException for wrong version prefix', async () => {
      await expect(service.verifyToken('v4.public.somedata')).rejects.toThrow(
        PasetoInvalidTokenException,
      );
    });

    it('should carry INVALID_FORMAT error code', async () => {
      await expect(service.verifyToken('not-a-token')).rejects.toMatchObject({
        code: PasetoErrorCode.INVALID_FORMAT,
      });
    });

    it('should throw PasetoInvalidTokenException for a too-short payload', async () => {
      // 'tooshort' base64url decodes to fewer than 29 bytes
      await expect(service.verifyToken('v4.local.dG9vc2hvcnQ')).rejects.toThrow(
        PasetoInvalidTokenException,
      );
    });

    it('should be instanceof PasetoException and UnauthorizedException', async () => {
      const { UnauthorizedException } = await import('@nestjs/common');
      await expect(service.verifyToken('v4.public.x')).rejects.toBeInstanceOf(PasetoException);
      await expect(service.verifyToken('v4.public.x')).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });
  });

  // ---------------------------------------------------------------------------
  // verifyToken — PasetoTokenTamperedWithException
  // ---------------------------------------------------------------------------

  describe('verifyToken — tampered token', () => {
    it('should throw PasetoTokenTamperedWithException', async () => {
      const token = await service.generateToken({ userId: 1 });
      const tampered = token.slice(0, -5) + 'XXXXX';
      await expect(service.verifyToken(tampered)).rejects.toThrow(PasetoTokenTamperedWithException);
    });

    it('should carry TOKEN_TAMPERED error code', async () => {
      const token = await service.generateToken({ userId: 1 });
      const tampered = token.slice(0, -5) + 'XXXXX';
      await expect(service.verifyToken(tampered)).rejects.toMatchObject({
        code: PasetoErrorCode.TOKEN_TAMPERED,
      });
    });
  });

  // ---------------------------------------------------------------------------
  // verifyToken — PasetoTokenExpiredException
  // ---------------------------------------------------------------------------

  describe('verifyToken — expired token', () => {
    it('should throw PasetoTokenExpiredException', async () => {
      // expiration: -1 → Date.now() - 1000 ms (already in the past)
      const svc = await buildService({ expiration: -1 });
      const token = await svc.generateToken({ userId: 1 });
      await expect(svc.verifyToken(token)).rejects.toThrow(PasetoTokenExpiredException);
    });

    it('should carry TOKEN_EXPIRED error code', async () => {
      const svc = await buildService({ expiration: -1 });
      const token = await svc.generateToken({ userId: 1 });
      await expect(svc.verifyToken(token)).rejects.toMatchObject({
        code: PasetoErrorCode.TOKEN_EXPIRED,
      });
    });
  });

  // ---------------------------------------------------------------------------
  // verifyToken — PasetoIssuerMismatchException
  // ---------------------------------------------------------------------------

  describe('verifyToken — issuer mismatch', () => {
    it('should throw PasetoIssuerMismatchException', async () => {
      const other = await buildService({ issuer: 'other-service' });
      const token = await other.generateToken({ userId: 1 });
      await expect(service.verifyToken(token)).rejects.toThrow(PasetoIssuerMismatchException);
    });

    it('should carry ISSUER_MISMATCH error code', async () => {
      const other = await buildService({ issuer: 'other-service' });
      const token = await other.generateToken({ userId: 1 });
      await expect(service.verifyToken(token)).rejects.toMatchObject({
        code: PasetoErrorCode.ISSUER_MISMATCH,
      });
    });
  });

  // ---------------------------------------------------------------------------
  // verifyToken — PasetoAudienceMismatchException
  // ---------------------------------------------------------------------------

  describe('verifyToken — audience mismatch', () => {
    it('should throw PasetoAudienceMismatchException', async () => {
      const other = await buildService({ audience: 'admins' });
      const token = await other.generateToken({ userId: 1 });
      await expect(service.verifyToken(token)).rejects.toThrow(PasetoAudienceMismatchException);
    });

    it('should carry AUDIENCE_MISMATCH error code', async () => {
      const other = await buildService({ audience: 'admins' });
      const token = await other.generateToken({ userId: 1 });
      await expect(service.verifyToken(token)).rejects.toMatchObject({
        code: PasetoErrorCode.AUDIENCE_MISMATCH,
      });
    });
  });

  // ---------------------------------------------------------------------------
  // parseExpiration formats
  // ---------------------------------------------------------------------------

  describe('parseExpiration formats', () => {
    const cases: Array<{ exp: string | number; label: string }> = [
      { exp: '30s', label: 'seconds (30s)' },
      { exp: '5m', label: 'minutes (5m)' },
      { exp: '2h', label: 'hours (2h)' },
      { exp: '7d', label: 'days (7d)' },
      { exp: 3600, label: 'numeric seconds (3600)' },
    ];

    for (const { exp, label } of cases) {
      it(`should handle ${label}`, async () => {
        const svc = await buildService({ expiration: exp });
        const token = await svc.generateToken({});
        const claims = await svc.verifyToken<any>(token);
        expect(claims.exp).toBeDefined();
        expect(new Date(claims.exp).getTime()).toBeGreaterThan(Date.now());
      });
    }

    it('should accept an ISO 8601 date string', async () => {
      const future = new Date(Date.now() + 60_000).toISOString();
      const svc = await buildService({ expiration: future });
      const token = await svc.generateToken({});
      const claims = await svc.verifyToken<any>(token);
      expect(claims.exp).toBeDefined();
    });

    it('should throw for an invalid expiration string', async () => {
      const svc = await buildService({ expiration: 'notvalid' });
      await expect(svc.generateToken({})).rejects.toThrow('Invalid expiration format');
    });
  });
});
