#!/bin/bash
set -e

if [ $# -ne 1 ]; then
    echo "Usage: $0 <build-path>"
    echo ""
    echo "  build-path: directory containing remill and llvm build"
    echo "  Expected layout:"
    echo "    <build-path>/remill-install/"
    echo "    <build-path>/remill/dependencies/install/"
    exit 1
fi

BUILD_PATH=$1
REMILL_INSTALL=${BUILD_PATH}/remill-install
DEPS_INSTALL=${BUILD_PATH}/remill/dependencies/install

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
