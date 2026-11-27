"""SealFrame — 15-line Python Quickstart over libsealframe.so."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "bindings" / "python"))
import sealframe as sf

v1 = b"A" * 200_000 + b"v1-state"
v2 = b"A" * 200_000 + b"v2-state"

with sf.MorphContext() as m:
    wire = m.encode(v2, kind=sf.MORPH_DELTA, ref=v1)
    restored, verified_dna = m.materialize(wire, ref=v1)

assert restored == v2 and verified_dna == sf.dna(v2)
print(f"[Python Quickstart] OK! dna={verified_dna[:16]}... canonical={len(v2)} B delta_wire={len(wire)} B")
