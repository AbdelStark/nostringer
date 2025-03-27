// Test ESM imports
import { sign, verify, generateKeyPair } from './dist/esm/src/index.js';

console.log('ESM import successful');
console.log('sign exists:', typeof sign === 'function');
console.log('verify exists:', typeof verify === 'function');
console.log('generateKeyPair exists:', typeof generateKeyPair === 'function'); 