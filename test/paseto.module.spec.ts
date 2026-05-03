import { Injectable, Module } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { PasetoModule } from '../src/paseto.module';
import { PasetoModuleOptionsFactory, PasetoOptions } from '../src/interfaces';
import { PasetoService } from '../src/paseto.service';

describe('PasetoModule', () => {
  const symmetricKey = '12345678901234567890123456789012'; // 32 bytes

  describe('registerAsync with useFactory', () => {
    it('should provide PasetoService', async () => {
      const module = await Test.createTestingModule({
        imports: [
          PasetoModule.registerAsync({
            useFactory: () => ({ symmetricKey }),
          }),
        ],
      }).compile();

      const service = module.get<PasetoService>(PasetoService);
      expect(service).toBeDefined();
    });

    it('should resolve factory with injected dependencies', async () => {
      const CONFIG_TOKEN = 'CONFIG_TOKEN';

      @Module({
        providers: [{ provide: CONFIG_TOKEN, useValue: { key: symmetricKey } }],
        exports: [CONFIG_TOKEN],
      })
      class ConfigModule {}

      const module = await Test.createTestingModule({
        imports: [
          PasetoModule.registerAsync({
            imports: [ConfigModule],
            inject: [CONFIG_TOKEN],
            useFactory: (config: { key: string }) => ({
              symmetricKey: config.key,
            }),
          }),
        ],
      }).compile();

      const service = module.get<PasetoService>(PasetoService);
      expect(service).toBeDefined();
    });

    it('should resolve async factory', async () => {
      const module = await Test.createTestingModule({
        imports: [
          PasetoModule.registerAsync({
            useFactory: async () => {
              await Promise.resolve();
              return { symmetricKey };
            },
          }),
        ],
      }).compile();

      const service = module.get<PasetoService>(PasetoService);
      expect(service).toBeDefined();
    });
  });

  describe('registerAsync with useClass', () => {
    it('should instantiate and call createPasetoOptions()', async () => {
      @Injectable()
      class TestOptionsFactory implements PasetoModuleOptionsFactory {
        createPasetoOptions(): PasetoOptions {
          return { symmetricKey };
        }
      }

      @Module({ providers: [TestOptionsFactory], exports: [TestOptionsFactory] })
      class TestModule {}

      const module = await Test.createTestingModule({
        imports: [
          PasetoModule.registerAsync({
            imports: [TestModule],
            useClass: TestOptionsFactory,
          }),
        ],
      }).compile();

      const service = module.get<PasetoService>(PasetoService);
      expect(service).toBeDefined();
    });
  });

  describe('registerAsync with useExisting', () => {
    it('should reuse an existing provider as options factory', async () => {
      @Injectable()
      class ExistingFactory implements PasetoModuleOptionsFactory {
        createPasetoOptions(): PasetoOptions {
          return { symmetricKey };
        }
      }

      @Module({ providers: [ExistingFactory], exports: [ExistingFactory] })
      class FactoryModule {}

      const module = await Test.createTestingModule({
        imports: [
          PasetoModule.registerAsync({
            imports: [FactoryModule],
            useExisting: ExistingFactory,
          }),
        ],
      }).compile();

      const service = module.get<PasetoService>(PasetoService);
      expect(service).toBeDefined();
    });
  });

  describe('registerAsync invalid options', () => {
    it('should throw if neither useFactory, useClass, nor useExisting is provided', () => {
      expect(() => {
        PasetoModule.registerAsync({});
      }).toThrow('Invalid PasetoModuleAsyncOptions');
    });
  });

  describe('PasetoModule exports', () => {
    it('should export PasetoService so it can be used in other modules', async () => {
      const appModule = await Test.createTestingModule({
        imports: [
          PasetoModule.registerAsync({
            useFactory: () => ({ symmetricKey, issuer: 'test', expiration: '1h' }),
          }),
        ],
      }).compile();

      const service = appModule.get<PasetoService>(PasetoService);
      const token = await service.generateToken({ sub: 'user-1' });
      expect(token.startsWith('v4.local.')).toBe(true);
    });
  });
});
