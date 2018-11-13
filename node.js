const {instantiatePbkdf2Lib} = require("./pbkdf2.js");
const instantiatePbkdf2 = async (sha512, bytes) => {
	if (bytes == null){
        return new Promise((resolve,reject) =>{
            require("fs").readFile(__dirname+"/bin/pbkdf2.wasm",(err,data) => {
                if (err){
                    reject(err);
                }else{
                    resolve(instantiatePbkdf2Lib(data, sha512));
                }
            });
        });
	}else{
        return instantiatePbkdf2Lib(bytes, sha512);
    }
}
module.exports = {instantiatePbkdf2};