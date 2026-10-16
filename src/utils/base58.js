/** Base58btc (Bitcoin alphabet) as used by multibase prefix 'z'. */

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE = BigInt(ALPHABET.length);
const INDEX = new Map([...ALPHABET].map((char, index) => [char, BigInt(index)]));

export function base58Encode(bytes) {
  const input = Buffer.isBuffer(bytes) ? bytes : Buffer.from(bytes);
  if (input.length === 0) return '';

  let value = BigInt(`0x${input.toString('hex')}`);
  let encoded = '';
  while (value > 0n) {
    const remainder = value % BASE;
    value /= BASE;
    encoded = ALPHABET[Number(remainder)] + encoded;
  }

  let leadingZeros = 0;
  for (const byte of input) {
    if (byte !== 0) break;
    leadingZeros += 1;
  }

  return '1'.repeat(leadingZeros) + encoded;
}

export function base58Decode(text) {
  if (typeof text !== 'string') throw new TypeError('base58Decode expects a string');
  if (text.length === 0) return Buffer.alloc(0);

  let value = 0n;
  for (const char of text) {
    const digit = INDEX.get(char);
    if (digit === undefined) throw new TypeError(`base58Decode: invalid character "${char}"`);
    value = value * BASE + digit;
  }

  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  const body = value === 0n ? Buffer.alloc(0) : Buffer.from(hex, 'hex');

  let leadingOnes = 0;
  for (const char of text) {
    if (char !== '1') break;
    leadingOnes += 1;
  }

  return Buffer.concat([Buffer.alloc(leadingOnes), body]);
}

export function multibaseEncodeBase58btc(bytes) {
  return `z${base58Encode(bytes)}`;
}

export function multibaseDecodeBase58btc(text) {
  if (typeof text !== 'string' || text[0] !== 'z') {
    throw new TypeError('expected a multibase base58btc string starting with "z"');
  }
  return base58Decode(text.slice(1));
}
