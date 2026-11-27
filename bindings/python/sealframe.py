"""Minimal zero-dependency Python binding for SealFrame (libsealframe.so)."""
import ctypes as ct
import os
from pathlib import Path

MORPH_RAW = 0
MORPH_ZSTD = 1
MORPH_DELTA = 2
MORPH_REF = 3
MORPH_COMPUTE = 4

DTYPE_FP32 = 1
DTYPE_FP16 = 2
DTYPE_INT8 = 3
DTYPE_UINT8 = 4
DTYPE_INT32 = 5


class _DNA(ct.Structure):
    _fields_ = [("bytes", ct.c_uint8 * 32)]


class _Keypair(ct.Structure):
    _fields_ = [("pk", ct.c_uint8 * 32), ("sk", ct.c_uint8 * 64)]


class _TensorMeta(ct.Structure):
    _fields_ = [
        ("dtype", ct.c_int),
        ("ndim", ct.c_uint8),
        ("flags", ct.c_uint8),
        ("dims", ct.c_uint32 * 4),
        ("seq_id", ct.c_uint64),
    ]


class _CDCStats(ct.Structure):
    _fields_ = [
        ("dna", _DNA),
        ("canonical_size", ct.c_uint64),
        ("total_chunks", ct.c_uint64),
        ("new_chunks", ct.c_uint64),
        ("dedup_chunks", ct.c_uint64),
        ("stored_bytes", ct.c_uint64),
        ("reused_bytes", ct.c_uint64),
        ("elapsed_ns", ct.c_uint64),
    ]


def _load_lib():
    override = os.environ.get("SF_LIB_PATH")
    build_dir = Path(__file__).resolve().parents[2] / "build"
    candidates = [override] if override else [
        str(build_dir / "libsealframe.so"),
        "libsealframe.so.1",
        "libsealframe.so",
    ]
    for path in candidates:
        if path and (Path(path).exists() or "/" not in path):
            try:
                lib = ct.CDLL(path)
                break
            except OSError:
                continue
    else:
        raise RuntimeError("libsealframe.so not found; run `make` first or set SF_LIB_PATH")

    lib.fp_init.restype = ct.c_int
    lib.fp_strerror.argtypes = [ct.c_int]
    lib.fp_strerror.restype = ct.c_char_p
    lib.fp_dna_compute.argtypes = [ct.c_char_p, ct.c_size_t, ct.POINTER(_DNA)]
    lib.fp_dna_compute.restype = ct.c_int
    lib.fp_morph_ctx_new.restype = ct.c_void_p
    lib.fp_morph_ctx_free.argtypes = [ct.c_void_p]
    lib.fp_morph_encode.argtypes = [
        ct.c_void_p, ct.c_int, ct.c_char_p, ct.c_size_t,
        ct.c_char_p, ct.c_size_t, ct.c_int,
        ct.POINTER(ct.c_void_p), ct.POINTER(ct.c_size_t),
    ]
    lib.fp_morph_encode.restype = ct.c_int
    lib.fp_morph_materialize.argtypes = [
        ct.c_void_p, ct.c_char_p, ct.c_size_t,
        ct.c_char_p, ct.c_size_t, ct.c_size_t,
        ct.POINTER(ct.c_void_p), ct.POINTER(ct.c_size_t), ct.POINTER(_DNA),
    ]
    lib.fp_morph_materialize.restype = ct.c_int
    lib.fp_cdc_ingest_file.argtypes = [ct.c_char_p, ct.c_char_p, ct.POINTER(_CDCStats)]
    lib.fp_cdc_ingest_file.restype = ct.c_int
    lib.fp_cdc_reconstruct_file.argtypes = [
        ct.c_char_p, ct.POINTER(_DNA), ct.c_char_p, ct.POINTER(ct.c_uint64),
    ]
    lib.fp_cdc_reconstruct_file.restype = ct.c_int

    lib.fp_session_connect.argtypes = [
        ct.c_char_p, ct.c_uint16, ct.POINTER(_Keypair), ct.c_char_p,
        ct.c_int, ct.POINTER(ct.c_void_p),
    ]
    lib.fp_session_connect.restype = ct.c_int
    lib.fp_session_send_verified.argtypes = [
        ct.c_void_p, ct.c_uint8, ct.c_char_p, ct.c_size_t, ct.POINTER(_DNA),
    ]
    lib.fp_session_send_verified.restype = ct.c_int
    lib.fp_session_recv_verified.argtypes = [
        ct.c_void_p, ct.c_size_t, ct.POINTER(ct.c_uint8),
        ct.POINTER(ct.c_void_p), ct.POINTER(ct.c_size_t), ct.POINTER(_DNA),
    ]
    lib.fp_session_recv_verified.restype = ct.c_int
    lib.fp_session_stats.argtypes = [
        ct.c_void_p, ct.POINTER(ct.c_uint64), ct.POINTER(ct.c_uint64),
    ]
    lib.fp_session_close.argtypes = [ct.c_void_p]
    lib.fp_session_send_tensor.argtypes = [
        ct.c_void_p, ct.c_uint8, ct.POINTER(_TensorMeta),
        ct.c_char_p, ct.c_size_t, ct.c_int, ct.POINTER(_DNA),
    ]
    lib.fp_session_send_tensor.restype = ct.c_int
    lib.fp_session_recv_tensor.argtypes = [
        ct.c_void_p, ct.c_size_t, ct.c_int, ct.POINTER(ct.c_uint8),
        ct.POINTER(_TensorMeta), ct.POINTER(ct.c_void_p), ct.POINTER(ct.c_size_t),
        ct.POINTER(_DNA),
    ]
    lib.fp_session_recv_tensor.restype = ct.c_int

    libc = ct.CDLL(None)
    libc.free.argtypes = [ct.c_void_p]
    lib._free = libc.free

    if lib.fp_init() != 0:
        raise RuntimeError("fp_init failed")
    return lib


_LIB = _load_lib()


def _check(rc: int) -> None:
    if rc != 0:
        raise ValueError(_LIB.fp_strerror(rc).decode("utf-8", errors="replace"))


def dna(data: bytes) -> str:
    """Compute canonical 32-byte BLAKE3 16 KiB Merkle DNA (hex)."""
    out = _DNA()
    _check(_LIB.fp_dna_compute(data, len(data), ct.byref(out)))
    return bytes(out.bytes).hex()


class MorphContext:
    """Reusable zero-waste Zstd/Delta Morph context."""

    def __init__(self):
        self._ctx = _LIB.fp_morph_ctx_new()
        if not self._ctx:
            raise MemoryError("fp_morph_ctx_new")

    def close(self):
        if self._ctx:
            _LIB.fp_morph_ctx_free(self._ctx)
            self._ctx = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __del__(self):
        self.close()

    def encode(self, data: bytes, kind: int = MORPH_ZSTD, ref: bytes | None = None, level: int = 3) -> bytes:
        ptr = ct.c_void_p()
        sz = ct.c_size_t()
        rc = _LIB.fp_morph_encode(
            self._ctx, kind, data, len(data),
            ref, len(ref) if ref is not None else 0, level,
            ct.byref(ptr), ct.byref(sz),
        )
        _check(rc)
        try:
            return ct.string_at(ptr.value, sz.value)
        finally:
            _LIB._free(ptr)

    def materialize(self, wire: bytes, ref: bytes | None = None, max_output: int = 128 << 20) -> tuple[bytes, str]:
        ptr = ct.c_void_p()
        sz = ct.c_size_t()
        out_dna = _DNA()
        rc = _LIB.fp_morph_materialize(
            self._ctx, wire, len(wire),
            ref, len(ref) if ref is not None else 0, max_output,
            ct.byref(ptr), ct.byref(sz), ct.byref(out_dna),
        )
        _check(rc)
        try:
            return ct.string_at(ptr.value, sz.value), bytes(out_dna.bytes).hex()
        finally:
            _LIB._free(ptr)


def cdc_ingest(store_dir: str, file_path: str) -> dict:
    """Stream file into FastCDC Content Pool in O(1) RAM."""
    st = _CDCStats()
    _check(_LIB.fp_cdc_ingest_file(store_dir.encode(), file_path.encode(), ct.byref(st)))
    return {
        "dna": bytes(st.dna.bytes).hex(),
        "canonical_size": st.canonical_size,
        "total_chunks": st.total_chunks,
        "new_chunks": st.new_chunks,
        "dedup_chunks": st.dedup_chunks,
        "stored_bytes": st.stored_bytes,
        "reused_bytes": st.reused_bytes,
        "elapsed_ms": st.elapsed_ns / 1e6,
    }


def cdc_reconstruct(store_dir: str, dna_hex: str, out_path: str) -> int:
    """Reconstruct verified file from FastCDC Pool in O(1) RAM."""
    d = _DNA()
    raw = bytes.fromhex(dna_hex)
    if len(raw) != 32:
        raise ValueError("DNA must be 64 hex chars")
    ct.memmove(d.bytes, raw, 32)
    written = ct.c_uint64()
    _check(_LIB.fp_cdc_reconstruct_file(store_dir.encode(), ct.byref(d), out_path.encode(), ct.byref(written)))
    return written.value


class Session:
    """Persistent 1-RTT X25519+Ed25519+XChaCha20-Poly1305+BLAKE3 streaming session."""

    def __init__(self, host: str, port: int, sk_bytes: bytes, peer_pk_bytes: bytes, timeout_ms: int = 10000):
        if len(sk_bytes) != 64 or len(peer_pk_bytes) != 32:
            raise ValueError("sk must be 64 B and peer_pk must be 32 B")
        kp = _Keypair()
        ct.memmove(kp.sk, sk_bytes, 64)
        ct.memmove(kp.pk, sk_bytes[32:64], 32)
        sess = ct.c_void_p()
        _check(_LIB.fp_session_connect(host.encode(), int(port), ct.byref(kp), peer_pk_bytes, int(timeout_ms), ct.byref(sess)))
        self._sess = sess

    def send(self, tag: int, data: bytes) -> str:
        out_dna = _DNA()
        _check(_LIB.fp_session_send_verified(self._sess, int(tag), data, len(data), ct.byref(out_dna)))
        return bytes(out_dna.bytes).hex()

    def recv(self, max_bytes: int = 64 << 20) -> tuple[int, bytes, str]:
        tag = ct.c_uint8()
        ptr = ct.c_void_p()
        sz = ct.c_size_t()
        out_dna = _DNA()
        _check(_LIB.fp_session_recv_verified(
            self._sess, int(max_bytes), ct.byref(tag), ct.byref(ptr), ct.byref(sz), ct.byref(out_dna)
        ))
        try:
            payload = ct.string_at(ptr.value, sz.value)
        finally:
            _LIB._free(ptr)
        return int(tag.value), payload, bytes(out_dna.bytes).hex()

    def stats(self) -> tuple[int, int]:
        tx = ct.c_uint64()
        rx = ct.c_uint64()
        _LIB.fp_session_stats(self._sess, ct.byref(tx), ct.byref(rx))
        return int(tx.value), int(rx.value)

    def send_tensor(self, tag: int, data: bytes, dims: tuple[int, ...],
                    dtype: int = DTYPE_FP32, seq_id: int = 0, wire_fp16: bool = False) -> str:
        if not (1 <= len(dims) <= 4):
            raise ValueError("dims must have 1..4 entries")
        meta = _TensorMeta()
        meta.dtype = int(dtype)
        meta.ndim = len(dims)
        meta.flags = 0
        for i, d in enumerate(dims):
            meta.dims[i] = int(d)
        meta.seq_id = int(seq_id)
        out_dna = _DNA()
        _check(_LIB.fp_session_send_tensor(
            self._sess, int(tag), ct.byref(meta), data, len(data),
            1 if wire_fp16 else 0, ct.byref(out_dna),
        ))
        return bytes(out_dna.bytes).hex()

    def recv_tensor(self, max_bytes: int = 64 << 20, upcast_fp16: bool = True) -> dict:
        tag = ct.c_uint8()
        meta = _TensorMeta()
        ptr = ct.c_void_p()
        sz = ct.c_size_t()
        out_dna = _DNA()
        _check(_LIB.fp_session_recv_tensor(
            self._sess, int(max_bytes), 1 if upcast_fp16 else 0,
            ct.byref(tag), ct.byref(meta), ct.byref(ptr), ct.byref(sz), ct.byref(out_dna),
        ))
        try:
            payload = ct.string_at(ptr.value, sz.value)
        finally:
            _LIB._free(ptr)
        return {
            "tag": int(tag.value),
            "dtype": int(meta.dtype),
            "dims": tuple(int(meta.dims[i]) for i in range(meta.ndim)),
            "flags": int(meta.flags),
            "seq_id": int(meta.seq_id),
            "data": payload,
            "dna": bytes(out_dna.bytes).hex(),
        }

    def close(self):
        if getattr(self, "_sess", None):
            _LIB.fp_session_close(self._sess)
            self._sess = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def __del__(self):
        self.close()
