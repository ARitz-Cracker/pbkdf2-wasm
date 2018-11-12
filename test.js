(async () => {
try{
	const crypto = require("crypto");
	const sha512 = await require("bitcoin-ts").instantiateSha512();
	const pbkdf2Wasm = await require("./pbkdf2Wasm.js").instantiatePbkdf2WasmNode();
	pbkdf2Wasm.setSha512Callback((resultPtr, dataPtr, dataLen) => {
		pbkdf2Wasm.heapU8.set(
			sha512.hash(
				pbkdf2Wasm.heapU8.subarray(dataPtr,dataPtr + dataLen)
			),
			resultPtr
		);
	});

	
	let salt = Buffer.from("a".repeat(200));
	let data = Buffer.from("Amazing Data");

	let resultHashPtr = pbkdf2Wasm.malloc(64);
	let saltPtr = pbkdf2Wasm.malloc(salt.length);
	pbkdf2Wasm.heapU8.set(salt,saltPtr);

	let dataPtr = pbkdf2Wasm.malloc(data.length);
	pbkdf2Wasm.heapU8.set(data,dataPtr);


	
	pbkdf2Wasm.hmacSha512(resultHashPtr, saltPtr, salt.length, dataPtr, data.length);
	const wasmBuf = Buffer.from(pbkdf2Wasm.heapU8.subarray(resultHashPtr, resultHashPtr + 64));

	const hmac = crypto.createHmac("sha512",salt);
	hmac.update(data);
	const nativeBuf = hmac.digest();
	
	console.log(wasmBuf);
	console.log(nativeBuf);
	for (let i = 0; i < 64; i+=1){
		if (wasmBuf[i] !== nativeBuf[i]){
			throw new Error("NOOOOOOOOOOOOOOOOOOOOO")
		}
	}
	



	
	const hash = crypto.createHash("sha512");
	hash.update(data);
	console.log(hash.digest());
	
	pbkdf2Wasm.testSha512(resultHashPtr, dataPtr, data.length);
	console.log(Buffer.from(pbkdf2Wasm.heapU8.subarray(resultHashPtr, resultHashPtr + 64)));
	


	console.log(crypto.pbkdf2Sync(data, salt, 10000, 64, "sha512"));
	pbkdf2Wasm.pbkdf2Sha512(resultHashPtr, saltPtr, salt.length, dataPtr, data.length, 10000);
	console.log(Buffer.from(pbkdf2Wasm.heapU8.subarray(resultHashPtr, resultHashPtr + 64)));
	//*/
}catch(ex){
	console.error(ex.stack);
}
})();