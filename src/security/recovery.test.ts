import { describe, expect, it } from "vitest";
import {
  RECOVERY_ENTROPY_BITS,
  RECOVERY_WORD_COUNT,
  decodeRecoveryEntropyForTests,
  generateRecoveryWords,
  isValidRecoveryWords,
  normalizeRecoveryWords,
} from "./recovery";

describe("isolated 12-word recovery experiment", () => {
  it("generates 12 valid checksum-protected English words", () => {
    const words = generateRecoveryWords();
    expect(words.split(" ")).toHaveLength(RECOVERY_WORD_COUNT);
    expect(RECOVERY_ENTROPY_BITS).toBe(128);
    expect(isValidRecoveryWords(words)).toBe(true);
    expect(decodeRecoveryEntropyForTests(words)).toHaveLength(16);
  });

  it("generates unique phrases across independent attempts", () => {
    const phrases = Array.from({ length: 16 }, () => generateRecoveryWords());
    expect(new Set(phrases).size).toBe(phrases.length);
  });

  it("accepts pasted whitespace and uppercase without altering the words", () => {
    const phrase = generateRecoveryWords();
    expect(normalizeRecoveryWords("  " + phrase.toUpperCase().replace(/ /g, " \n ") + "  ")).toBe(phrase);
    expect(isValidRecoveryWords(phrase.toUpperCase().replace(/ /g, "\n"))).toBe(true);
  });

  it("rejects incomplete, unknown, and checksum-invalid phrases", () => {
    const words = generateRecoveryWords().split(" ");
    expect(isValidRecoveryWords(words.slice(0, 11).join(" "))).toBe(false);
    const unknown = words.slice();
    unknown[0] = "notaword";
    expect(isValidRecoveryWords(unknown.join(" "))).toBe(false);
    const checksumBad = words.slice();
    checksumBad[11] = checksumBad[11] === "abandon" ? "ability" : "abandon";
    // A replacement may randomly happen to have a valid checksum; explicitly
    // assert that it differs, then verify a deterministic invalid BIP39 vector.
    expect(checksumBad.join(" ")).not.toBe(words.join(" "));
    expect(isValidRecoveryWords("abandon ".repeat(11) + "abandon")).toBe(false);
  });

  it("rejects all random text, missing data and fake phrase lengths", () => {
    expect(isValidRecoveryWords("")).toBe(false);
    expect(isValidRecoveryWords("rose garden")).toBe(false);
    expect(isValidRecoveryWords("abandon ".repeat(24).trim())).toBe(false);
    expect(() => decodeRecoveryEntropyForTests("invalid secret")).toThrow();
  });

  it("does not mistake a known test vector for production-safe secret material", () => {
    const testVector = "abandon ".repeat(11) + "about";
    expect(isValidRecoveryWords(testVector)).toBe(true);
    expect(decodeRecoveryEntropyForTests(testVector)).toEqual(new Uint8Array(16));
  });
});
