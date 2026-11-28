"""Run paired transfers on Linux. The fixture must reside on the work filesystem."""
import argparse
import hashlib
import json
import os
import signal
from pathlib import Path
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path, help="2 GiB file named by its SealFrame DNA")
    parser.add_argument("a", type=Path)
    parser.add_argument("b", type=Path)
    parser.add_argument("--pairs", type=int, default=1)
    parser.add_argument("--protocol", choices=["tcp", "udp"], action="append")
    args = parser.parse_args()
    fixture = args.fixture.resolve()
    if fixture.stat().st_size != 2 << 30 or args.pairs < 1:
        parser.error("requires a 2 GiB fixture and a positive pair count")
    binaries = [args.a.resolve(), args.b.resolve()]
    hashes = [hashlib.sha256(binary.read_bytes()).hexdigest() for binary in binaries]
    for pair in range(args.pairs):
        for protocol in args.protocol or ["tcp", "udp"]:
            for side in ([0, 1] if pair % 2 == 0 else [1, 0]):
                with tempfile.TemporaryDirectory(dir=fixture.parent) as directory:
                    root = Path(directory)
                    objects = root / "server" / "objects"
                    objects.mkdir(parents=True)
                    os.link(fixture, objects / fixture.name)
                    index = objects / (fixture.name + ".fpm")
                    for state in ("absent", "present"):
                        assert index.exists() == (state == "present")
                        client = root / state
                        client.mkdir()
                        command = [binaries[side], protocol, objects.parent, client, fixture.name]
                        with subprocess.Popen(command, stdout=subprocess.PIPE, text=True,
                                              start_new_session=True) as process:
                            try:
                                output, _ = process.communicate(timeout=600)
                            finally:
                                # A failed client may leave the server waiting for another packet.
                                try:
                                    os.killpg(process.pid, signal.SIGKILL)
                                except ProcessLookupError:
                                    pass
                            if process.returncode:
                                raise subprocess.CalledProcessError(process.returncode, command)
                        row = json.loads(output)
                        assert row["dna"] == fixture.name and index.stat().st_size > 0
                        print(json.dumps(dict(pair=pair, side="AB"[side], protocol=protocol,
                                              index_state=state, binary=hashes[side], **row)), flush=True)
                        (client / "objects" / fixture.name).unlink()


if __name__ == "__main__":
    main()
