import { test } from "node:test";
import assert from "node:assert/strict";
import { erroreDecifratura, chiaveMancante } from "../../dist/credenziali/windows-native.js";
import {
  ChiaveHelloMancanteError,
  SbloccoAnnullatoError,
  VaultIllegibileError,
} from "../../dist/credenziali/tipi.js";

test("NTE_NO_KEY, NTE_NOT_FOUND e NTE_BAD_KEYSET indicano una chiave mancante", () => {
  for (const hr of [0x8009000d, 0x80090011, 0x80090016]) assert.equal(chiaveMancante(hr), true, hr.toString(16));
  // I codici arrivano come int32 con segno.
  assert.equal(chiaveMancante(0x80090016 | 0), true);
  assert.equal(chiaveMancante(0x80090027), false);
  assert.equal(chiaveMancante(0), false);
});

test("esiti della decifratura: successo, annullamento, chiave mancante, altro", () => {
  assert.equal(erroreDecifratura(0), null);
  assert.ok(erroreDecifratura(0x80090036 | 0) instanceof SbloccoAnnullatoError);
  assert.ok(erroreDecifratura(0x8010006e | 0) instanceof SbloccoAnnullatoError);
  assert.ok(erroreDecifratura(0x80090016 | 0) instanceof ChiaveHelloMancanteError);
  const altro = erroreDecifratura(0x80090005 | 0);
  assert.ok(altro instanceof VaultIllegibileError);
  assert.match(altro.message, /--reset-windows-hello/);
  assert.match(altro.message, /0x80090005/);
});
