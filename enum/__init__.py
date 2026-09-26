"""Stage 2 — enum. Stage 2 of the pipeline: turn raw rows into a test queue.

Splits the harvested pool into price-of-test tiers so the 900-wide tester never
spends budget on a dead port when there is a live one to find, and generates the
variant set (scheme/port/case permutations) for the retry pass.
"""
