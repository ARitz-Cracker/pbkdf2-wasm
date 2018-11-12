#!/bin/bash
if [ "$(expr substr $(uname -s) 1 10)" == "MINGW64_NT" ]; then
  # This is for when I'm on my Windows box.
  # I keep saying that I'll switch back to linux, but I never got around to it.
  source /e/emsdk/emsdk_env.sh
fi

emcc pbkdf2.c \
  -O3 \
  -s WASM=1 \
  -s "BINARYEN_METHOD='native-wasm'" \
  -s NO_EXIT_RUNTIME=1 \
  -s DETERMINISTIC=1 \
  -s EXPORTED_FUNCTIONS='[
  "_malloc",
  "_free",
  "_sha512_ptr_set",
  "_xorstr",
  "_xorstrs",
  "_hmac_sha512",
  "_pbkdf2_sha512"
  ]' \
  -s RESERVED_FUNCTION_POINTERS=1\
  -o pbkdf2.js &&
rm pbkdf2.js && # For some reason specifying this output was needed to make the .wasm file
mv pbkdf2.wasm ../bin/pbkdf2.wasm;