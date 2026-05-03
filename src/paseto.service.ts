import { Inject, Injectable } from '@nestjs/common';
import * as crypto from 'node:crypto';
import { PASETO_MODULE_OPTIONS } from './constants';
import {
  PasetoAudienceMismatchException,
  PasetoConfigurationException,
  PasetoInvalidTokenException,
  PasetoIssuerMismatchException,
  PasetoTokenExpiredException,
  PasetoTokenTamperedWithException,
} from './exceptions';
import { PasetoOptions } from './interfaces';

@Injectable()
export class PasetoService {
  private readonly header = 'v4.local.';
  private readonly key: Buffer;

  constructor(
    @Inject(PASETO_MODULE_OPTIONS)
    private readonly options: PasetoOptions,
  ) {
    this.key = Buffer.isBuffer(options.symmetricKey)
      ? options.symmetricKey
      : Buffer.from(options.symmetricKey, 'utf8');

    if (this.key.length !== 32) {
      throw new PasetoConfigurationException(
        'Symmetric key must be exactly 32 bytes for PASETO v4 local encryption',
      );
    }
  }

  /**
   * Parses expiration string to an absolute Date.
   * Supports: {n}s, {n}m, {n}h, {n}d, numeric seconds, or ISO 8601 date string.
   */
  private parseExpiration(exp: string | number): Date {
    if (typeof exp === 'number') {
      return new Date(Date.now() + exp * 1000);
    }

    const match = exp.match(/^(\d+)([smhd])$/);
    if (!match) {
      const d = new Date(exp);
      if (isNaN(d.getTime())) {
        throw new Error('Invalid expiration format');
      }
      return d;
    }

    const val = parseInt(match[1], 10);
    const multipliers: Record<string, number> = {
      s: 1_000,
      m: 60 * 1_000,
      h: 60 * 60 * 1_000,
      d: 24 * 60 * 60 * 1_000,
    };

    return new Date(Date.now() + val * multipliers[match[2]]);
  }

  /**
   * Generates a PASETO v4-like local token using ChaCha20-Poly1305.
   * The configured iss, aud, and exp claims are merged into the payload automatically.
   *
   * Note: Node.js chacha20-poly1305 uses a 12-byte nonce; the official PASETO v4
   * spec uses XChaCha20-Poly1305 with a 24-byte nonce. Encryption guarantees are
   * equivalent but the output is not spec-compliant.
   */
  async generateToken(payload: Record<string, any>): Promise<string> {
    try {
      const claims = { ...payload };

      if (this.options.issuer) claims.iss = this.options.issuer;
      if (this.options.audience) claims.aud = this.options.audience;
      if (this.options.expiration) {
        claims.exp = this.parseExpiration(this.options.expiration).toISOString();
      }

      const plaintext = Buffer.from(JSON.stringify(claims), 'utf8');
      const nonce = crypto.randomBytes(12);

      const cipher = crypto.createCipheriv('chacha20-poly1305', this.key, nonce, {
        authTagLength: 16,
      });

      const headerBuffer = Buffer.from(this.header, 'utf8');
      cipher.setAAD(headerBuffer, { plaintextLength: plaintext.length });

      const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
      const authTag = cipher.getAuthTag();

      const payloadBuffer = Buffer.concat([nonce, ciphertext, authTag]);
      const base64Url = payloadBuffer
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');

      return `${this.header}${base64Url}`;
    } catch (error) {
      throw new Error(`Failed to generate token: ${(error as Error).message}`);
    }
  }

  async verifyToken<T = Record<string, any>>(token: string): Promise<T> {
    if (!token.startsWith(this.header)) {
      throw new PasetoInvalidTokenException('invalid version or format prefix');
    }

    const base64Url = token.slice(this.header.length);
    let base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4) base64 += '=';

    const payloadBuffer = Buffer.from(base64, 'base64');

    // nonce (12) + at least 1 byte ciphertext + authTag (16) = minimum 29 bytes
    if (payloadBuffer.length < 29) {
      throw new PasetoInvalidTokenException('token payload too short');
    }

    const nonce = payloadBuffer.subarray(0, 12);
    const authTag = payloadBuffer.subarray(payloadBuffer.length - 16);
    const ciphertext = payloadBuffer.subarray(12, payloadBuffer.length - 16);

    let plaintext: Buffer;
    try {
      const decipher = crypto.createDecipheriv('chacha20-poly1305', this.key, nonce, {
        authTagLength: 16,
      });
      const headerBuffer = Buffer.from(this.header, 'utf8');
      decipher.setAAD(headerBuffer, { plaintextLength: ciphertext.length });
      decipher.setAuthTag(authTag);
      plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    } catch {
      throw new PasetoTokenTamperedWithException();
    }

    let claims: Record<string, any>;
    try {
      claims = JSON.parse(plaintext.toString('utf8'));
    } catch {
      throw new PasetoInvalidTokenException('token payload is not valid JSON');
    }

    if (this.options.issuer && claims.iss !== this.options.issuer) {
      throw new PasetoIssuerMismatchException();
    }
    if (this.options.audience && claims.aud !== this.options.audience) {
      throw new PasetoAudienceMismatchException();
    }
    if (claims.exp && new Date(claims.exp).getTime() < Date.now()) {
      throw new PasetoTokenExpiredException();
    }

    return claims as T;
  }
}
