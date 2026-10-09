# sudo apt install libgtest-dev (tests); Botan 3 from the system (libbotan-3-dev) or built from third_party/botan
CXX = g++
MAKEFLAGS += -j$(shell nproc)
CXXFLAGS = -std=c++20 -Wall -Wextra -pedantic -fPIC -fstack-protector-all
DEPFLAGS = -MMD -MP                                         # emit .d files so header edits rebuild every dependent object
PREFIX ?= /usr/local
VERSION = 0.1.0
SOVERSION = 0

BOTAN ?= $(if $(shell pkg-config --exists botan-3 && echo yes),system,bundled)
ifeq ($(BOTAN),system)
  BOTAN_CFLAGS := $(shell pkg-config --cflags botan-3)
  BOTAN_LIBS := $(shell pkg-config --libs botan-3)
  BOTAN_DEP :=
else
  BOTAN_DIR := $(CURDIR)/third_party/botan
  BOTAN_CFLAGS := -I$(BOTAN_DIR)/build/include/public
  BOTAN_LIBS := $(BOTAN_DIR)/libbotan-3.a
  BOTAN_DEP := $(BOTAN_DIR)/libbotan-3.a
endif
LDFLAGS = $(BOTAN_LIBS)

ifdef TSAN
  CXXFLAGS += -g -fsanitize=thread
  LDFLAGS += -fsanitize=thread
endif

STATIC_LIB = libmeshlink.a
SHARED_LIB = libmeshlink.so.$(VERSION)
INCLUDE = -I./include $(BOTAN_CFLAGS)
SOURCES = $(wildcard src/*.cpp) $(wildcard libs/*.cpp)
OBJECTS = $(SOURCES:.cpp=.o)
TEST_SOURCES = $(wildcard tests/*.cpp)
TEST_OBJECTS = $(TEST_SOURCES:.cpp=.o)
TEST_BINARY = run_test

# No -flto: libmeshlink.a holds plain machine code, so any compiler (or version) can link it
all: CXXFLAGS += -O2
all: $(STATIC_LIB) $(SHARED_LIB)

dev: CXXFLAGS += -g -fsanitize=thread -fsanitize=undefined
dev: LDFLAGS += -fsanitize=thread -fsanitize=undefined
dev: $(STATIC_LIB) $(SHARED_LIB)

ifeq ($(BOTAN),bundled)
$(BOTAN_DIR)/libbotan-3.a:
	@test -f $(BOTAN_DIR)/configure.py || { echo "Botan not found: install libbotan-3-dev or run git submodule update --init"; exit 1; }
	scripts/build-botan.sh
endif

# Botan headers must exist before anything that includes them is compiled
$(OBJECTS) $(TEST_OBJECTS) bench/bench_connection.o: | $(BOTAN_DEP)

$(STATIC_LIB): $(OBJECTS)
	ar rcs $@ $^

$(SHARED_LIB): $(OBJECTS)
	$(CXX) -shared -Wl,-soname,libmeshlink.so.$(SOVERSION) -o $@ $^ $(LDFLAGS)

tests: $(TEST_OBJECTS) $(STATIC_LIB)
	$(CXX) $(CXXFLAGS) -o $(TEST_BINARY) $(TEST_OBJECTS) $(STATIC_LIB) $(LDFLAGS) -lgtest_main -lgtest -lpthread

test: tests
	./$(TEST_BINARY) --gtest_brief=1

# Race checks: TSAN alone (combined with UBSan it reports false data races)
tsan:
	$(MAKE) clean && $(MAKE) TSAN=1 tests && ./$(TEST_BINARY) --gtest_brief=1; status=$$?; $(MAKE) clean; exit $$status

%.o: %.cpp
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) $(INCLUDE) -c $< -o $@

tests/%.o: tests/%.cpp
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) $(INCLUDE) -c $< -o $@

# Frame throughput benchmark (optimized build of the library)
bench: CXXFLAGS += -O2
bench: bench/bench_connection.o $(STATIC_LIB)
	$(CXX) $(CXXFLAGS) -o run_bench bench/bench_connection.o $(STATIC_LIB) $(LDFLAGS) -lpthread

bench/%.o: bench/%.cpp
	$(CXX) $(CXXFLAGS) $(DEPFLAGS) $(INCLUDE) -c $< -o $@

# A minimal node; built in CI so the README's example keeps compiling
examples: examples/hello_mesh
examples/hello_mesh: examples/hello_mesh.cpp $(STATIC_LIB)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -o $@ $< $(STATIC_LIB) $(LDFLAGS) -pthread

install: all
	install -d $(DESTDIR)$(PREFIX)/include/meshlink $(DESTDIR)$(PREFIX)/include/transport $(DESTDIR)$(PREFIX)/lib/pkgconfig
	cp -r include/meshlink/. $(DESTDIR)$(PREFIX)/include/meshlink/
	cp -r include/transport/. $(DESTDIR)$(PREFIX)/include/transport/
	install -m 644 $(STATIC_LIB) $(DESTDIR)$(PREFIX)/lib/
	install -m 755 $(SHARED_LIB) $(DESTDIR)$(PREFIX)/lib/
	ln -sf $(SHARED_LIB) $(DESTDIR)$(PREFIX)/lib/libmeshlink.so.$(SOVERSION)
	ln -sf $(SHARED_LIB) $(DESTDIR)$(PREFIX)/lib/libmeshlink.so
ifeq ($(BOTAN),bundled)
	# The bundled Botan is minimized to what libmeshlink needs: kept in a private directory, never in the way of a full Botan
	install -d $(DESTDIR)$(PREFIX)/lib/meshlink $(DESTDIR)$(PREFIX)/include/meshlink/botan-3
	install -m 644 $(BOTAN_DIR)/libbotan-3.a $(DESTDIR)$(PREFIX)/lib/meshlink/
	cp -r $(BOTAN_DIR)/build/include/public/botan $(DESTDIR)$(PREFIX)/include/meshlink/botan-3/
	sed -e 's|@PREFIX@|$(PREFIX)|' -e 's|@VERSION@|$(VERSION)|' -e 's|@REQUIRES@||' \
	    -e 's|@LIBS_PRIVATE@|$${libdir}/meshlink/libbotan-3.a|' -e 's|@CFLAGS_EXTRA@|-I$${includedir}/meshlink/botan-3|' meshlink.pc.in > $(DESTDIR)$(PREFIX)/lib/pkgconfig/meshlink.pc
else
	sed -e 's|@PREFIX@|$(PREFIX)|' -e 's|@VERSION@|$(VERSION)|' -e 's|@REQUIRES@|botan-3|' \
	    -e 's|@LIBS_PRIVATE@||' -e 's|@CFLAGS_EXTRA@||' meshlink.pc.in > $(DESTDIR)$(PREFIX)/lib/pkgconfig/meshlink.pc
endif

# Used by meshlink's Makefile when it builds against a libmeshlink checkout instead of an installed copy
print-botan-cflags:
	@echo $(BOTAN_CFLAGS)
print-botan-libs:
	@echo $(BOTAN_LIBS)

.PHONY: all dev test tests tsan bench examples install clean print-botan-cflags print-botan-libs

clean:
	rm -f $(OBJECTS) $(STATIC_LIB) libmeshlink.so* $(TEST_OBJECTS) $(TEST_BINARY) run_test_tsan bench/*.o bench/*.d run_bench examples/hello_mesh $(OBJECTS:.o=.d) $(TEST_OBJECTS:.o=.d)

-include $(OBJECTS:.o=.d) $(TEST_OBJECTS:.o=.d)
