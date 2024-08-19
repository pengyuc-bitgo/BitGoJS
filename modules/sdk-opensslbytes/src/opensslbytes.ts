export function loadWebAssembly(): { buffer: Uint8Array } {
  const wasm = toUint8Array(
  );

  const mod = {
    buffer: wasm,
  };

  return mod;
}

function toUint8Array(s) {
  if (typeof atob === 'function') return new Uint8Array(atob(s).split('').map(charCodeAt));
  return require('buf' + 'fer').Buffer.from(s, 'base64');
}

function charCodeAt(c) {
  return c.charCodeAt(0);
}