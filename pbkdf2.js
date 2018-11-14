const {instantiatePbkdf2WasmBytes} = require("./pbkdf2Wasm.js");
class pbkdf2 {
	constructor(pbkdf2Wasm, sha512){
		this._heapU8 = pbkdf2Wasm.heapU8;
		pbkdf2Wasm.setSha512Callback((resultPtr, dataPtr, dataLen) => {
			this._heapU8.set(
				sha512.hash(
					this._heapU8.subarray(dataPtr,dataPtr + dataLen)
				),
				resultPtr
			);
		});
		this._malloc = pbkdf2Wasm.malloc;
		this._free = pbkdf2Wasm.free;
		this._pbkdf2Wasm = pbkdf2Wasm;

		this._resultPtr = pbkdf2Wasm.malloc(64);
		this._arg1Ptr = 0;
		this._arg1Len = 0;
		this._arg2Ptr = 0;
		this._arg2Len = 0;
	}
	_setArg1 (buffer) {
		if (this._arg1Len != buffer.length){
			this._free(this._arg1Ptr);
			this._arg1Ptr = this._malloc(buffer.length);
			this._arg1Len = buffer.length;
		}
		this._heapU8.set(buffer,this._arg1Ptr);
	}
	_setArg2(buffer) {
		if (this._arg2Len != buffer.length){
			this._free(this._arg2Ptr);
			this._arg2Ptr = this._malloc(buffer.length);
			this._arg2Len = buffer.length;
		}
		this._heapU8.set(buffer,this._arg2Ptr);
	}
	xorStr(buffer, val) {
		const len = buffer.length;
		this._setArg1(buffer);
		
		this._pbkdf2Wasm.xorStr(this._arg1Ptr, len, val);
		return this._heapU8.slice(this._arg1Ptr, this._arg1Ptr + len);
	}
	xorStrs(buffer1, buffer2) {
		const len = buffer1.length;
		if (len !== buffer2.length){
			throw new Error("Buffers must be the same length");
		}
		this._setArg1(buffer1);
		this._setArg2(buffer2);

		this._pbkdf2Wasm.xorStrs(this._arg1Ptr, this._arg2Ptr, len);
		return this._heapU8.slice(this._arg1Ptr, this._arg1Ptr + len);
	}
	hmacSha512(salt, data, paranoia = true){
		this._setArg1(salt);
		this._setArg2(data);

		this._pbkdf2Wasm.hmacSha512(this._resultPtr, this._arg1Ptr, salt.length, this._arg2Ptr, data.length);
		const result = this._heapU8.slice(this._resultPtr, this._resultPtr + 64);
		if (paranoia) {
			this.wipeInternalMemory();
		}
		return result;
	}
	pbkdf2Sha512(salt, data, iterations, paranoia = true) {
		this._setArg1(salt);
		this._setArg2(data);

		this._pbkdf2Wasm.pbkdf2Sha512(this._resultPtr, this._arg1Ptr, salt.length, this._arg2Ptr, data.length, iterations);
		const result = this._heapU8.slice(this._resultPtr, this._resultPtr + 64);

		if (paranoia) {
			this.wipeInternalMemory();
		}
		return result;
	}
	wipeInternalMemory() {
		this._heapU8.fill(0, this._arg1Ptr, this._arg1Ptr + this._arg1Len);
		this._heapU8.fill(0, this._arg2Ptr, this._arg2Ptr + this._arg2Len);
		this._heapU8.fill(0, this._resultPtr, this._resultPtr + 64);
	}
}

const instantiatePbkdf2Lib = async (bytes, sha512) => {
	if (sha512 instanceof Promise){
		sha512 = await sha512;
	}
	if (sha512 == null || (typeof sha512.hash) !== "function" ){
		throw new TypeError("instantiatePbkdf2Lib: Second argument must be an object with a \"hash\" method");
	}
	const pbkdf2Wasm = await instantiatePbkdf2WasmBytes(bytes);
	return new pbkdf2(pbkdf2Wasm, sha512);
}
module.exports = {instantiatePbkdf2Lib};
