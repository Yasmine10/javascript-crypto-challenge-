const nacl = require('libsodium-wrappers');

module.exports = async (key) => {
    await nacl.ready;

    if(!key) {
        throw 'no key';
    }

    return Object.freeze({
        decrypt: (ciphertext, nonce) => {
            if(!ciphertext || !nonce) {
                throw 'either of the arguments is undefined';
            }
            return nacl.crypto_secretbox_open_easy(ciphertext, nonce, key);
        }
    });
}