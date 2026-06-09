---
name: tdd-cycle
description: Drive one strict red→green→refactor TDD cycle for the srtrust SRT library. Use when implementing or extending any srt-protocol module, type, codec, or state-machine behavior. Enforces the project's test-first discipline, idiom rules, and clippy/fmt gates from CLAUDE.md.
---

# TDD cycle for srtrust

Run exactly one feature/behavior through red → green → refactor. Keep the unit of
work small (one type, one method, one packet's codec, one state transition).

Always `source "$HOME/.cargo/env"` first in a fresh shell so `cargo` is on PATH.

## 0. Orient

- Re-read the relevant CLAUDE.md sections (architecture, type idioms, TDD).
- For wire/protocol behavior, open `docs/spec/draft-sharabayko-srt-01.txt` and
  find the governing section; you will cite it in the code.
- State the smallest next behavior in one sentence before writing anything.

## 1. RED — write the failing test first

- Write the test before the implementation. Unit tests go in
  `#[cfg(test)] mod tests { use super::*; }` (can see private items); public-API
  or integration behavior goes in `tests/`.
- Cover the boundary/wrap/error cases explicitly (this codebase is full of
  31-bit wraparound and malformed-input edge cases).
- Stub the implementation with `todo!()` (bare — `todo!("msg")` is rejected
  inside `const fn`). It must compile but fail.
- Run `cargo test -p srt-protocol` and **confirm the test fails for the intended
  reason** (assertion/panic from the stub, not a compile error you didn't expect).

## 2. GREEN — minimal implementation

- Write the least code that makes the test pass. Resist gold-plating.
- Follow the type idioms: newtype wire values, no `Ord` on circular types,
  `thiserror` for errors, `Result` not panic for peer/parse failures, `const fn`
  where possible, cite the spec section in a comment.
- Run `cargo test -p srt-protocol` until green.

## 3. PROPTEST — for any codec or invariant-bearing type

- Round-trip: `decode(encode(x)) == x`, and re-encode is byte-stable.
- No-panic: arbitrary `&[u8]` into `decode` returns `Err`, never panics.
- Add these alongside the example-based tests; they are mandatory for codecs.

## 4. REFACTOR — clean under green

- Improve names/structure with tests staying green.
- Gates (all must pass; this is the definition of done):
  - `cargo test -p srt-protocol`
  - `cargo clippy --all-targets -- -D warnings`
  - `cargo fmt`
- Update the relevant TaskUpdate status; note any spec deviation discovered.

## Anti-patterns to reject

- Implementation written before its test.
- `Instant::now()`/`SystemTime::now()` anywhere in `srt-protocol` (breaks
  determinism — time must be passed in).
- `unwrap()` in non-test code; `unsafe`; deriving `Ord`/`PartialOrd` on circular
  sequence/timestamp newtypes.
- Mimicking a reference implementation's quirk without checking it against the spec.
