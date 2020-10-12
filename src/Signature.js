const nacl = require('libsodium-wrappers');

module.exports = async (key) => {
    await nacl.ready;

    const {privateKey, publicKey} = nacl.crypto_sign_keypair();

    return Object.freeze({
        verifyingKey: publicKey,

        sign: (msg) => {
            return nacl.crypto_sign(msg, privateKey);
        }
    });
}