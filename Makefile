CC                 ?= gcc
PREFIX             ?= /usr/local
SF_VERSION         := 0.6.0
FP_VERSION         := $(SF_VERSION)
USE_SYSTEM_BLAKE3  ?= 0

HARDEN_CFLAGS  := -fstack-protector-strong -D_FORTIFY_SOURCE=3
HARDEN_LDFLAGS := -Wl,-z,relro,-z,now -Wl,-z,noexecstack

ifeq ($(USE_SYSTEM_BLAKE3),auto)
  HAS_SYS_BLAKE3 := $(shell pkg-config --exists libblake3 && echo 1 || echo 0)
else
  HAS_SYS_BLAKE3 := $(USE_SYSTEM_BLAKE3)
endif

BASE_PKGS := libsodium libzstd sqlite3
ifeq ($(HAS_SYS_BLAKE3),1)
  BLAKE3_CFLAGS := $(shell pkg-config --cflags libblake3)
  BLAKE3_LIBS   := $(shell pkg-config --libs libblake3)
  BLAKE3_SRCS   :=
  BLAKE3_OBJS   :=
  PC_REQ_PRIV   := libblake3 libsodium libzstd sqlite3
else
  BLAKE3_CFLAGS := -Ithird_party/blake3 -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512 -DBLAKE3_USE_NEON=0
  BLAKE3_LIBS   :=
  BLAKE3_SRCS   := third_party/blake3/blake3.c third_party/blake3/blake3_dispatch.c third_party/blake3/blake3_portable.c
  BLAKE3_OBJS   := build/b3_blake3.o build/b3_blake3_dispatch.o build/b3_blake3_portable.o
  PC_REQ_PRIV   := libsodium libzstd sqlite3
endif

PKG_CFLAGS     := $(BLAKE3_CFLAGS) $(shell pkg-config --cflags $(BASE_PKGS))
PKG_LIBS       := $(BLAKE3_LIBS) $(shell pkg-config --libs $(BASE_PKGS))
CFLAGS         := -std=c11 -O3 -fPIC $(HARDEN_CFLAGS) -Wall -Wextra -Werror -pedantic -Iinclude $(PKG_CFLAGS)
THIRD_CFLAGS   := -std=c11 -O3 -fPIC $(HARDEN_CFLAGS) -Ithird_party/blake3 $(BLAKE3_CFLAGS)
LDFLAGS        := $(HARDEN_LDFLAGS) $(PKG_LIBS) -lpthread -lm

LIB_SRCS := src/dna.c src/morph.c src/lineage.c src/store.c src/anchor.c src/net.c src/cdc.c src/bundle.c src/trust.c src/swarm.c src/udp.c src/http.c src/agent.c src/tensor.c src/chain_adapters.c src/split_shim.c
LIB_OBJS := $(patsubst src/%.c,build/%.o,$(LIB_SRCS)) $(BLAKE3_OBJS)
TESTS    := test_particle test_net test_cdc test_bundle test_trust test_swarm test_chaos test_agent test_chain_adapters test_split_shim test_redteam test_model_checker

.PHONY: all examples examples-py test test-asan test-clang fuzz libfuzzer bench compare security-check sbom lint deb physical-kit install uninstall clean

all: build/libsealframe.a build/libsealframe.so build/libsealframe.pc bin/sf bin/sf-agent bin/sf-cp bin/sf-llama-bridge

build bin:
	mkdir -p $@

build/%.o: src/%.c include/fp.h include/fp_agent.h include/sealframe.h include/sealframe_agent.h include/sealframe_chain.h include/sealframe_split.h | build
	$(CC) $(CFLAGS) -c $< -o $@

build/b3_%.o: third_party/blake3/%.c | build
	$(CC) $(THIRD_CFLAGS) -c $< -o $@

build/libsealframe.a: $(LIB_OBJS)
	ar rcs $@ $^

build/libsealframe.so: $(LIB_OBJS)
	$(CC) -shared -Wl,-soname,libsealframe.so.1 $(LIB_OBJS) $(LDFLAGS) -o $@
	ln -sf libsealframe.so build/libsealframe.so.1

build/libsealframe.pc: Makefile | build
	@printf '%s\n' \
	  "prefix=$(PREFIX)" \
	  'exec_prefix=$${prefix}' \
	  'libdir=$${exec_prefix}/lib' \
	  'includedir=$${prefix}/include' \
	  '' \
	  'Name: libsealframe' \
	  'Description: SealFrame — Pure-C11 Verified Content, Delta, Swarm, Bundle, Tensor & Control Plane' \
	  'Version: $(SF_VERSION)' \
	  'Requires.private: $(PC_REQ_PRIV)' \
	  'Libs: -L$${libdir} -lsealframe -lpthread' \
	  'Cflags: -I$${includedir}' > $@

bin/sf: src/main.c build/libsealframe.a | bin
	$(CC) $(CFLAGS) -fPIE -pie src/main.c build/libsealframe.a $(LDFLAGS) -o $@

bin/sf-agent: src/agent_main.c build/libsealframe.a | bin
	$(CC) $(CFLAGS) -fPIE -pie src/agent_main.c build/libsealframe.a $(LDFLAGS) -o $@

bin/sf-cp: src/cp_main.c build/libsealframe.a | bin
	$(CC) $(CFLAGS) -fPIE -pie src/cp_main.c build/libsealframe.a $(LDFLAGS) -o $@

bin/sf-llama-bridge: integrations/llama_cpp/sf_llama_bridge.c build/libsealframe.a | bin
	$(CC) $(CFLAGS) -fPIE -pie integrations/llama_cpp/sf_llama_bridge.c build/libsealframe.a $(LDFLAGS) -o $@

build/c_quickstart: examples/c_quickstart.c build/libsealframe.so | build
	$(CC) $(CFLAGS) -fPIE -pie examples/c_quickstart.c -Lbuild -Wl,-rpath,'$$ORIGIN' -lsealframe $(HARDEN_LDFLAGS) -o $@

examples: build/c_quickstart build/libsealframe.so
	./build/c_quickstart

examples-py: build/libsealframe.so
	SF_LIB_PATH=$(CURDIR)/build/libsealframe.so python3 examples/py_quickstart.py

build/test_%: tests/test_%.c build/libsealframe.a | build
	$(CC) $(CFLAGS) $< build/libsealframe.a $(LDFLAGS) -o $@

build/fuzz_parsers: tests/fuzz_parsers.c build/libsealframe.a | build
	$(CC) $(CFLAGS) $< build/libsealframe.a $(LDFLAGS) -o $@

test: all $(addprefix build/,$(TESTS))
	@for t in $(TESTS); do ./build/$$t || exit 1; done

fuzz: build/fuzz_parsers
	./build/fuzz_parsers 1000000

FUZZ_SECS ?= 15
libfuzzer: | build
	mkdir -p build/fuzz_corpus
	clang -std=c11 -O1 -g -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer \
	      -Wall -Wextra -Werror -pedantic -Iinclude $(PKG_CFLAGS) \
	      $(LIB_SRCS) $(BLAKE3_SRCS) tests/libfuzzer_all.c $(PKG_LIBS) -lpthread \
	      -o build/libfuzzer_all
	./build/libfuzzer_all build/fuzz_corpus -max_total_time=$(FUZZ_SECS) -max_len=4096 -print_final_stats=1

test-asan: all | build
	@for t in $(TESTS); do \
	  $(CC) -std=c11 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
	        -Wall -Wextra -Werror -pedantic -Iinclude $(PKG_CFLAGS) \
	        $(LIB_SRCS) $(BLAKE3_SRCS) tests/$$t.c $(PKG_LIBS) -lpthread -lm -o build/$${t}_asan && \
	  ./build/$${t}_asan || exit 1; \
	done
	$(CC) -std=c11 -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer \
	      -Wall -Wextra -Werror -pedantic -Iinclude $(PKG_CFLAGS) \
	      $(LIB_SRCS) $(BLAKE3_SRCS) tests/fuzz_parsers.c $(PKG_LIBS) -lpthread -lm -o build/fuzz_parsers_asan
	./build/fuzz_parsers_asan 100000

test-clang:
	$(MAKE) clean
	$(MAKE) CC=clang USE_SYSTEM_BLAKE3=$(USE_SYSTEM_BLAKE3) all test examples security-check

build/bench_%: bench/bench_%.c build/libsealframe.a | build
	$(CC) $(CFLAGS) $< build/libsealframe.a $(LDFLAGS) -o $@

build/mixed_infer_client: bench/mixed_infer_client.c build/libsealframe.a | build
	$(CC) $(CFLAGS) $< build/libsealframe.a $(LDFLAGS) -o $@

build/infer_node: bench/infer_node.c build/libsealframe.a | build
	$(CC) $(CFLAGS) $< build/libsealframe.a $(LDFLAGS) -o $@

build/infer_3node_suite: bench/infer_3node_suite.c build/libsealframe.a | build
	$(CC) $(CFLAGS) $< build/libsealframe.a $(LDFLAGS) -o $@

build/bench_wan_split: bench/bench_wan_split.c build/libsealframe.a | build
	$(CC) $(CFLAGS) $< build/libsealframe.a $(LDFLAGS) -o $@

build/keryx_sealframe_accel: bench/keryx_sealframe_accel.c build/libsealframe.a | build
	$(CC) $(CFLAGS) $< build/libsealframe.a $(LDFLAGS) -o $@

build/sf_llama_split_demo: examples/llama_split_shim_demo.c build/libsealframe.a | build
	$(CC) $(CFLAGS) $< build/libsealframe.a $(LDFLAGS) -o $@

build/sf_qwen_gguf_profiler: bench/sf_qwen_gguf_profiler.c build/libsealframe.a | build
	$(CC) $(CFLAGS) $< build/libsealframe.a $(LDFLAGS) -o $@

bench: build/bench_particle build/bench_net build/bench_cdc build/bench_bundle build/bench_swarm
	./build/bench_particle
	./build/bench_net
	./build/bench_cdc
	./build/bench_bundle
	./build/bench_swarm

compare: bin/sf
	bash bench/compare_real.sh

security-check: all
	@echo "=== SealFrame Binary Security Hardening Check (ELF) [BLAKE3 system=$(HAS_SYS_BLAKE3)] ==="
	@for bin in bin/sf bin/sf-agent bin/sf-cp bin/sf-llama-bridge build/libsealframe.so; do \
	  echo "Checking $$bin:"; \
	  LC_ALL=C readelf -h "$$bin" | grep -q 'Type:[[:space:]]*DYN' || { echo "FAIL: $$bin is not PIE/DYN"; exit 1; }; \
	  LC_ALL=C readelf -lW "$$bin" | grep -q 'GNU_RELRO' || { echo "FAIL: $$bin missing GNU_RELRO"; exit 1; }; \
	  LC_ALL=C readelf -d "$$bin" | grep -q 'BIND_NOW' || { echo "FAIL: $$bin missing BIND_NOW (Full RELRO)"; exit 1; }; \
	  LC_ALL=C readelf -lW "$$bin" | awk '/GNU_STACK/{if ($$0 ~ /RWE/) exit 1}' || { echo "FAIL: $$bin has executable stack"; exit 1; }; \
	  LC_ALL=C readelf -sW "$$bin" | grep -q '__stack_chk_fail' || { echo "FAIL: $$bin missing stack protector canary"; exit 1; }; \
	  echo "  [PASS] $$bin: PIE/DYN + Full RELRO (GNU_RELRO + BIND_NOW) + NX Stack + Stack Canary"; \
	done

sbom: all
	SF_SYSTEM_BLAKE3=$(HAS_SYS_BLAKE3) FP_SYSTEM_BLAKE3=$(HAS_SYS_BLAKE3) bash scripts/generate_sbom.sh

lint:
	@command -v clang-tidy >/dev/null 2>&1 || { echo "clang-tidy not installed"; exit 1; }
	clang-tidy $(LIB_SRCS) src/main.c src/agent_main.c src/cp_main.c -- -std=c11 -Iinclude $(PKG_CFLAGS)

deb: all security-check sbom
	bash scripts/build_deb.sh

physical-kit:
	bash scripts/package_physical_kit.sh

install: all
	install -d $(DESTDIR)$(PREFIX)/bin $(DESTDIR)$(PREFIX)/lib/pkgconfig $(DESTDIR)$(PREFIX)/include
	install -m 755 bin/sf $(DESTDIR)$(PREFIX)/bin/sf
	install -m 755 bin/sf-agent $(DESTDIR)$(PREFIX)/bin/sf-agent
	install -m 755 bin/sf-cp $(DESTDIR)$(PREFIX)/bin/sf-cp
	install -m 755 bin/sf-llama-bridge $(DESTDIR)$(PREFIX)/bin/sf-llama-bridge
	install -m 644 build/libsealframe.a $(DESTDIR)$(PREFIX)/lib/libsealframe.a
	install -m 755 build/libsealframe.so $(DESTDIR)$(PREFIX)/lib/libsealframe.so.$(SF_VERSION)
	ln -sf libsealframe.so.$(SF_VERSION) $(DESTDIR)$(PREFIX)/lib/libsealframe.so.1
	ln -sf libsealframe.so.1 $(DESTDIR)$(PREFIX)/lib/libsealframe.so
	install -m 644 include/sealframe.h $(DESTDIR)$(PREFIX)/include/sealframe.h
	install -m 644 include/sealframe_agent.h $(DESTDIR)$(PREFIX)/include/sealframe_agent.h
	install -m 644 include/sealframe_chain.h $(DESTDIR)$(PREFIX)/include/sealframe_chain.h
	install -m 644 include/sealframe_split.h $(DESTDIR)$(PREFIX)/include/sealframe_split.h
	install -m 644 include/fp.h $(DESTDIR)$(PREFIX)/include/fp.h
	install -m 644 include/fp_agent.h $(DESTDIR)$(PREFIX)/include/fp_agent.h
	install -m 644 build/libsealframe.pc $(DESTDIR)$(PREFIX)/lib/pkgconfig/libsealframe.pc

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/sf $(DESTDIR)$(PREFIX)/bin/sf-agent $(DESTDIR)$(PREFIX)/bin/sf-cp $(DESTDIR)$(PREFIX)/bin/sf-llama-bridge \
	      $(DESTDIR)$(PREFIX)/include/sealframe.h $(DESTDIR)$(PREFIX)/include/sealframe_agent.h \
	      $(DESTDIR)$(PREFIX)/include/sealframe_chain.h $(DESTDIR)$(PREFIX)/include/sealframe_split.h \
	      $(DESTDIR)$(PREFIX)/include/fp.h $(DESTDIR)$(PREFIX)/include/fp_agent.h \
	      $(DESTDIR)$(PREFIX)/lib/libsealframe.a $(DESTDIR)$(PREFIX)/lib/libsealframe.so* \
	      $(DESTDIR)$(PREFIX)/lib/pkgconfig/libsealframe.pc

clean:
	rm -rf build bin
