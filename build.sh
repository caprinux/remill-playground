#!/bin/bash
set -e

REMILL_INSTALL=/home/user/test/remill-install
DEPS_INSTALL=/home/user/test/remill/dependencies/install

cmake -B build -S . \
    -DCMAKE_BUILD_TYPE=Release \
    "-DCMAKE_PREFIX_PATH=${REMILL_INSTALL};${DEPS_INSTALL}"

cmake --build build -- -j$(nproc)

# Generate a run wrapper that injects the correct semantics path
cat > build/run.sh << EOF
#!/bin/bash
REMILL_SEMANTICS_DIR="${REMILL_INSTALL}/share/remill/17/semantics" \
  "\$(dirname "\$0")/remill-workdir" "\$@"
EOF
chmod +x build/run.sh
echo "Build done. Run with: ./build/run.sh"
