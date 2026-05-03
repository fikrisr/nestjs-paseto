import { UnauthorizedException } from '@nestjs/common';

export enum PasetoErrorCode {
  INVALID_FORMAT = 'PASETO_INVALID_FORMAT',
  TOKEN_EXPIRED = 'PASETO_TOKEN_EXPIRED',
  TOKEN_TAMPERED = 'PASETO_TOKEN_TAMPERED',
  ISSUER_MISMATCH = 'PASETO_ISSUER_MISMATCH',
  AUDIENCE_MISMATCH = 'PASETO_AUDIENCE_MISMATCH',
}

/**
 * Base class for all PASETO token verification errors.
 * Extends UnauthorizedException so NestJS HTTP context automatically
 * returns a 401 response without additional exception filters.
 */
export class PasetoException extends UnauthorizedException {
  readonly code: PasetoErrorCode;

  constructor(code: PasetoErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = this.constructor.name;
  }
}

/** Token does not start with `v4.local.`, is too short, or its payload cannot be parsed. */
export class PasetoInvalidTokenException extends PasetoException {
  constructor(detail?: string) {
    super(
      PasetoErrorCode.INVALID_FORMAT,
      detail ? `Invalid token: ${detail}` : 'Invalid token format or version',
    );
  }
}

/** The `exp` claim is present and its date is in the past. */
export class PasetoTokenExpiredException extends PasetoException {
  constructor() {
    super(PasetoErrorCode.TOKEN_EXPIRED, 'Token has expired');
  }
}

/** Authentication tag verification failed — the token has been tampered with. */
export class PasetoTokenTamperedWithException extends PasetoException {
  constructor() {
    super(PasetoErrorCode.TOKEN_TAMPERED, 'Token integrity check failed');
  }
}

/** The `iss` claim does not match the configured issuer. */
export class PasetoIssuerMismatchException extends PasetoException {
  constructor() {
    super(PasetoErrorCode.ISSUER_MISMATCH, 'Token issuer does not match');
  }
}

/** The `aud` claim does not match the configured audience. */
export class PasetoAudienceMismatchException extends PasetoException {
  constructor() {
    super(PasetoErrorCode.AUDIENCE_MISMATCH, 'Token audience does not match');
  }
}

/**
 * Thrown during module setup when the symmetric key is not exactly 32 bytes.
 * This is a programming/configuration error, not a token verification error,
 * so it extends Error rather than UnauthorizedException.
 */
export class PasetoConfigurationException extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'PasetoConfigurationException';
  }
}
