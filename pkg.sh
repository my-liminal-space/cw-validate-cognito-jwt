#!/bin/bash
set -e

MLS_PKG_DIR="../pkg"

if [ -d "${MLS_PKG_DIR}" ]; then
    rm -Rf ${MLS_PKG_DIR}
fi

mkdir -p ${MLS_PKG_DIR}


cp ./README.md ${MLS_PKG_DIR}/
cp ./pkg-config/package.json ${MLS_PKG_DIR}/
cp ./src/check-jwt.js ${MLS_PKG_DIR}/index.js


npm publish ${MLS_PKG_DIR} --access public

