import { defineConfig } from 'tsup'

export default defineConfig([
  {
    entry: ['src/index.ts'],
    format: ['esm', 'cjs'],
    dts: true,
    sourcemap: true,
    clean: true,
    target: 'es2019',
    platform: 'browser',
  },
  {
    // IIFE que o scripts/umd.mjs embrulha em UMD (AMD, CommonJS e global CatalisaBiometrics)
    entry: { 'biometrics-web.iife': 'src/index.ts' },
    format: ['iife'],
    globalName: 'CatalisaBiometrics',
    minify: true,
    sourcemap: false,
    target: 'es2019',
    platform: 'browser',
    outExtension: () => ({ js: '.js' }),
  },
])
