import { DynamicModule, Global, Module, Provider } from '@nestjs/common';
import { PASETO_MODULE_OPTIONS } from './constants';
import { PasetoModuleAsyncOptions } from './interfaces';
import { PasetoService } from './paseto.service';

@Global()
@Module({})
export class PasetoModule {
  static registerAsync(options: PasetoModuleAsyncOptions): DynamicModule {
    return {
      module: PasetoModule,
      imports: options.imports || [],
      providers: [this.createAsyncOptionsProvider(options), PasetoService],
      exports: [PasetoService],
    };
  }

  private static createAsyncOptionsProvider(options: PasetoModuleAsyncOptions): Provider {
    if (options.useFactory) {
      return {
        provide: PASETO_MODULE_OPTIONS,
        useFactory: options.useFactory,
        inject: options.inject || [],
      };
    }

    const inject = options.useClass || options.useExisting;
    if (!inject) {
      throw new Error(
        'Invalid PasetoModuleAsyncOptions: you must provide useFactory, useClass, or useExisting',
      );
    }

    return {
      provide: PASETO_MODULE_OPTIONS,
      useFactory: async (optionsFactory: any) => await optionsFactory.createPasetoOptions(),
      inject: [inject],
    };
  }
}
