var ALGORITHM = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-1", publicExponent: new Uint8Array([3]), modulusLength: 1024 };
// var ALGORITHM = { name: "RSA-OAEP", hash: "SHA-1", publicExponent: new Uint8Array([1, 0, 1]), modulusLength: 2048 };
// var ALGORITHM = { name: "AES-CBC", length: 256, iv: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6]) };
// var ALGORITHM = { name: "ECDSA", hash: "SHA-256", namedCurve: "P-256" };

var DATA = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);

function ab2hex(buf) {
    var uintBuf = new Uint8Array(buf);

    var hex = "";
    for (var i = 0; i < uintBuf.length; i++) {
        var octet = uintBuf[i].toString(16);
        hex += octet.length === 1 ? "0" + octet : octet;
    }
    return hex;
}

function Copy(obj) {
    var copyObject = {};
    for (var key in obj) {
        copyObject[key] = obj[key];
    }
    return copyObject
}

function PrintAlgorithm(alg) {
    var copyAlg = Copy(alg)
    for (var key in copyAlg) {
        const prop = copyAlg[key];
        if (prop instanceof ArrayBuffer) {
            copyAlg[key] = ab2hex(prop);
        } else if (ArrayBuffer.isView(prop)) {
            copyAlg[key] = ab2hex(prop.buffer);
        }
    }
    console.log("Algorithm:", JSON.stringify(copyAlg, null, "  "));
}

function PrintKey(key) {
    return Promise.resolve()
        .then(function () {
            if (key.privateKey) {
                return crypto.subtle.exportKey("jwk", key.privateKey)
                    .then(function (jwk) {
                        console.log("Private key:", JSON.stringify(jwk, null, "  "));
                        return crypto.subtle.exportKey("jwk", key.publicKey);
                    })
                    .then(function (jwk) {
                        console.log("Public key:", JSON.stringify(jwk, null, "  "));
                    })
            } else {
                return crypto.subtle.exportKey("jwk", key)
                    .then(function (jwk) {
                        console.log("Secret key:", JSON.stringify(jwk, null, "  "));
                    })
            }
        });
}

function TestSigning() {
    return crypto.subtle.generateKey(ALGORITHM, true, ["sign", "verify"])
        .then(function (keys) {
            var signingKey = keys.privateKey || keys;
            var verifyingKey = keys.publicKey || keys;
            PrintAlgorithm(ALGORITHM);
            return PrintKey(keys)
                .then(function () {
                    return crypto.subtle.sign(ALGORITHM, signingKey, DATA);
                })
                .then(function (signature) {
                    console.log("Signed data:", ab2hex(DATA.buffer));
                    console.log("Signature:", ab2hex(signature));
                    return crypto.subtle.verify(ALGORITHM, verifyingKey, signature, DATA);
                })
                .then(function (ok) {
                    console.log("Verification:", ok);
                })
        })
}

function TestEncryption() {
    return crypto.subtle.generateKey(ALGORITHM, true, ["encrypt", "decrypt"])
        .then(function (keys) {
            var decKey = keys.privateKey || keys;
            var encKey = keys.publicKey || keys;
            PrintAlgorithm(ALGORITHM);
            return PrintKey(keys)
                .then(function () {
                    return crypto.subtle.encrypt(ALGORITHM, encKey, DATA);
                })
                .then(function (encryptedData) {
                    console.log("Data:", ab2hex(DATA.buffer));
                    console.log("Encrypted data:", ab2hex(encryptedData));
                    return crypto.subtle.decrypt(ALGORITHM, decKey, encryptedData);
                })
                .then(function (decData) {
                    console.log("Verification:", ab2hex(decData) === ab2hex(DATA.buffer));
                })
        })
}

TestSigning()
// TestEncryption()
    .then(function () {
        console.log("Test: success");
        alert("Success");
    })
    .catch(function (error) {
        console.log("Test: error");
        console.error(error);
        alert("Error");
    })