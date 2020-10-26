const nacl = require('libsodium-wrappers');

module.exports = async (key) => {
    await nacl.ready;

    if(!key) {
        throw 'no key';
    }

    return Object.freeze({
        encrypt: (msg) => {
            let nonce = nacl.randombytes_buf(nacl.crypto_secretbox_NONCEBYTES);
            return {
                nonce: nonce,
                ciphertext: nacl.crypto_secretbox_easy(msg, nonce, key)
            }
        }
    });
}