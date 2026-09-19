// Embrulha o IIFE do tsup (`var CatalisaBiometrics=(()=>{...})();`) num UMD de verdade.
import { readFileSync, writeFileSync, rmSync } from 'node:fs'

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'))
const iife = readFileSync(new URL('../dist/biometrics-web.iife.js', import.meta.url), 'utf8')
const banner = `/*! ${pkg.name} v${pkg.version} | ${pkg.license} | https://www.npmjs.com/package/${pkg.name} */`
const umd = `${banner}
(function (root, factory) {
  if (typeof define === 'function' && define.amd) define([], factory);
  else if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.CatalisaBiometrics = factory();
})(typeof self !== 'undefined' ? self : this, function () {
${iife.trim()}
return CatalisaBiometrics;
});
`
writeFileSync(new URL('../dist/biometrics-web.umd.js', import.meta.url), umd)
rmSync(new URL('../dist/biometrics-web.iife.js', import.meta.url))
console.log('UMD: dist/biometrics-web.umd.js', umd.length, 'bytes')
