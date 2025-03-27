// Test CommonJS imports
const { sign, verify, generateKeyPair } = require('./dist/cjs/src/index.cjs');

console.log('CommonJS import successful');
console.log('sign exists:', typeof sign === 'function');
console.log('verify exists:', typeof verify === 'function');
console.log('generateKeyPair exists:', typeof generateKeyPair === 'function'); 