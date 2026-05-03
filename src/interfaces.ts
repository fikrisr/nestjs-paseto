import { ModuleMetadata, Type } from '@nestjs/common';

export interface PasetoOptions {
  /**
   * Symmetric key for local encryption.
   * Must be exactly 32 bytes long (256 bits).
   */
  symmetricKey: string | Buffer;

  /**
   * Issuer of the token (iss claim).
   */
  issuer?: string;

  /**
   * Audience of the token (aud claim).
   */
  audience?: string;

  /**
   * Expiration time of the token (exp claim).
   * E.g., '1h', '7d'. Since we are building from scratch,
   * we can accept seconds or a human readable string.
   */
  expiration?: string | number;
}

export interface PasetoModuleOptionsFactory {
  createPasetoOptions(): Promise<PasetoOptions> | PasetoOptions;
}

export interface PasetoModuleAsyncOptions extends Pick<ModuleMetadata, 'imports'> {
  inject?: any[];
  useExisting?: Type<PasetoModuleOptionsFactory>;
  useClass?: Type<PasetoModuleOptionsFactory>;
  useFactory?: (...args: any[]) => Promise<PasetoOptions> | PasetoOptions;
}
