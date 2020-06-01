const {instantiatePbkdf2Lib} = require("./pbkdf2.js");
const instantiatePbkdf2 = async (sha512, bytes) => {
	if (bytes == null){
        const response = await fetch("./bin/pbkdf2.wasm");
        if (response.ok){
            return instantiatePbkdf2Lib(new Uint8Array(await response.arrayBuffer()), sha512);
        }else{
            throw new Error("Failed to load pbkdf2 binary: "+response.status+" "+response.statusText);
        }
	}else{
        return instantiatePbkdf2Lib(bytes, sha512);
    }
}
module.exports = {instantiatePbkdf2};
