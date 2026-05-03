# nestjs-paseto

A lightweight, zero-dependency Platform-Agnostic Security Tokens (PASETO) V4-like module for NestJS, built entirely on Node.js native `crypto` (ChaCha20-Poly1305).

## Features

- **Zero cryptographic dependencies** — uses Node.js native `crypto` exclusively
- **Authenticated encryption** — ChaCha20-Poly1305 AEAD with built-in tamper detection
- **NestJS dynamic module** — full async configuration (`useFactory`, `useClass`, `useExisting`)
- **Automatic claim validation** — issuer, audience, and expiration checked on every `verifyToken` call
- **Typed payload extraction** — TypeScript generic on `verifyToken<T>` for typed decoded claims

## Installation

```bash
npm install nestjs-paseto
```

## Quick Start

### 1. Register the module

Register `PasetoModule` in your root `AppModule`. The `symmetricKey` must be **exactly 32 bytes**.

```typescript
// app.module.ts
import { Module } from '@nestjs/common';
import { PasetoModule } from 'nestjs-paseto';

@Module({
  imports: [
    PasetoModule.registerAsync({
      useFactory: () => ({
        symmetricKey: process.env.PASETO_KEY!, // must be exactly 32 bytes
        issuer: 'my-auth-service',
        audience: 'my-web-clients',
        expiration: '2h',
      }),
    }),
  ],
})
export class AppModule {}
```

### 2. Inject and use the service

```typescript
import { Injectable } from '@nestjs/common';
import { PasetoService } from 'nestjs-paseto';

interface TokenPayload {
  userId: string;
  role: string;
}

@Injectable()
export class AuthService {
  constructor(private readonly paseto: PasetoService) {}

  async login(userId: string, role: string): Promise<string> {
    return this.paseto.generateToken({ userId, role });
  }

  async validate(token: string): Promise<TokenPayload> {
    // Throws UnauthorizedException on invalid, expired, or tampered tokens
    return this.paseto.verifyToken<TokenPayload>(token);
  }
}
```

## Configuration

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `symmetricKey` | `string \| Buffer` | **Yes** | 32-byte (256-bit) encryption key |
| `issuer` | `string` | No | Value for the `iss` claim; validated on every `verifyToken` call |
| `audience` | `string` | No | Value for the `aud` claim; validated on every `verifyToken` call |
| `expiration` | `string \| number` | No | Token lifetime — see formats below |

**Expiration formats**

| Format | Example | Description |
|--------|---------|-------------|
| `{n}s` | `'30s'` | Seconds |
| `{n}m` | `'15m'` | Minutes |
| `{n}h` | `'2h'` | Hours |
| `{n}d` | `'7d'` | Days |
| `number` | `3600` | Seconds as a plain number |
| ISO 8601 | `'2025-12-31T00:00:00Z'` | Absolute expiry date |

## Async Configuration Patterns

### With `@nestjs/config`

```typescript
import { ConfigModule, ConfigService } from '@nestjs/config';

PasetoModule.registerAsync({
  imports: [ConfigModule],
  inject: [ConfigService],
  useFactory: (config: ConfigService) => ({
    symmetricKey: config.getOrThrow('PASETO_KEY'),
    issuer: config.get('PASETO_ISSUER', 'my-service'),
    expiration: config.get('PASETO_TTL', '1h'),
  }),
});
```

### With `useClass`

```typescript
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PasetoModuleOptionsFactory, PasetoOptions } from 'nestjs-paseto';

@Injectable()
export class PasetoConfigFactory implements PasetoModuleOptionsFactory {
  constructor(private readonly config: ConfigService) {}

  createPasetoOptions(): PasetoOptions {
    return {
      symmetricKey: this.config.getOrThrow('PASETO_KEY'),
      issuer: 'my-service',
      expiration: '1h',
    };
  }
}

// In your feature module:
PasetoModule.registerAsync({
  imports: [ConfigModule],
  useClass: PasetoConfigFactory,
});
```

### With `useExisting`

```typescript
// Reuse an already-registered factory without instantiating a new one
PasetoModule.registerAsync({
  imports: [SharedConfigModule],
  useExisting: PasetoConfigFactory,
});
```

## API Reference

### `PasetoService`

#### `generateToken(payload: Record<string, any>): Promise<string>`

Encrypts `payload` using ChaCha20-Poly1305 and returns a `v4.local.*` token string.
The configured `iss`, `aud`, and `exp` claims are merged into the payload automatically.

```typescript
const token = await pasetoService.generateToken({ userId: '123', role: 'admin' });
// => 'v4.local.XXXXXX...'
```

#### `verifyToken<T = Record<string, any>>(token: string): Promise<T>`

Decrypts and validates the token. Returns the decoded claims typed as `T`.

```typescript
const claims = await pasetoService.verifyToken<{ userId: string; role: string }>(token);
console.log(claims.userId); // '123'
```

Throws a specific `PasetoException` subclass (each also extends `UnauthorizedException`) for each failure condition — see [Error Handling](#error-handling) below.

## Error Handling

All token verification errors extend `PasetoException`, which itself extends NestJS `UnauthorizedException`. This means any uncaught exception automatically produces an HTTP `401 Unauthorized` response in a NestJS HTTP context.

Each exception also carries a machine-readable `code` property from the `PasetoErrorCode` enum so you can branch on the failure reason programmatically.

### Exception types

| Exception class | `code` | Thrown when |
|---|---|---|
| `PasetoInvalidTokenException` | `PASETO_INVALID_FORMAT` | Token prefix is not `v4.local.`, payload is too short, or payload is not valid JSON |
| `PasetoTokenTamperedWithException` | `PASETO_TOKEN_TAMPERED` | Authentication tag verification fails (ciphertext was modified) |
| `PasetoTokenExpiredException` | `PASETO_TOKEN_EXPIRED` | The `exp` claim exists and its date is in the past |
| `PasetoIssuerMismatchException` | `PASETO_ISSUER_MISMATCH` | The `iss` claim does not match the configured `issuer` |
| `PasetoAudienceMismatchException` | `PASETO_AUDIENCE_MISMATCH` | The `aud` claim does not match the configured `audience` |

`PasetoConfigurationException` (extends `Error`, **not** `UnauthorizedException`) is thrown during module initialization when the symmetric key is not exactly 32 bytes. This is a programming error, not a request error.

### Catching specific exceptions

```typescript
import {
  PasetoException,
  PasetoErrorCode,
  PasetoTokenExpiredException,
  PasetoTokenTamperedWithException,
} from 'nestjs-paseto';

try {
  const claims = await pasetoService.verifyToken(token);
} catch (err) {
  if (err instanceof PasetoTokenExpiredException) {
    // prompt user to re-authenticate
  } else if (err instanceof PasetoTokenTamperedWithException) {
    // log security event
  } else if (err instanceof PasetoException) {
    // handle any other PASETO error by code
    console.error(err.code); // e.g. 'PASETO_INVALID_FORMAT'
  }
}
```

### Custom exception filter

```typescript
import { ExceptionFilter, Catch, ArgumentsHost } from '@nestjs/common';
import { PasetoException } from 'nestjs-paseto';

@Catch(PasetoException)
export class PasetoExceptionFilter implements ExceptionFilter {
  catch(exception: PasetoException, host: ArgumentsHost) {
    const response = host.switchToHttp().getResponse();
    response.status(401).json({
      statusCode: 401,
      error: exception.code,
      message: exception.message,
    });
  }
}
```

## Security Notes

> This module implements a PASETO V4-like construction using Node.js native `chacha20-poly1305`
> as a drop-in for XChaCha20-Poly1305 (12-byte nonce vs. 24-byte for XChaCha20). The
> authenticated encryption guarantees are equivalent, but this implementation is
> **not spec-compliant with the official PASETO V4 standard**.

## Contributing

Pull requests are welcome. For significant changes, please open an issue first to discuss what you would like to change.

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run tests with coverage
npm run test:cov

# Lint
npm run lint

# Format
npm run format
```

## License

[MIT](LICENSE)
