const nacl = require('libsodium-wrappers');
const Decryptor = require('./Decryptor.js');
const Encryptor = require('./Encryptor.js');

module.exports = async (peer) => {
    await nacl.ready;

    const keyPair = nacl.crypto_kx_keypair();

    let otherPeer, msg, rx, tx, encryptor, decryptor = undefined;

    let object = Object.freeze({
        publicKey: keyPair.publicKey,
        generateSharedKeys: async (otherPeer_) => {
            otherPeer = otherPeer_;      
            const serverKeys = nacl.crypto_kx_server_session_keys(keyPair.publicKey, keyPair.privateKey, otherPeer.publicKey);
            rx = serverKeys.sharedRx;
            tx = serverKeys.sharedTx;
            decryptor = await Decryptor(rx);
            encryptor = await Encryptor(tx);
        },
        encrypt: (msg) => {
            return encryptor.encrypt(msg);
        },
        decrypt: (ciphertext, nonce) => {
            return decryptor.decrypt(ciphertext, nonce);
        },
        setMessage: (msg_) => {
            msg = msg_;
        },
        send: (msg) => {
            otherPeer.setMessage(object.encrypt(msg));
        },
        receive: () => {
            return object.decrypt(msg.ciphertext, msg.nonce);
        }        
    });

    if (peer) {
        otherPeer = peer;
        const client_keys = nacl.crypto_kx_client_session_keys(keyPair.publicKey, keyPair.privateKey, otherPeer.publicKey);
        rx = client_keys.sharedRx;
        decryptor = await Decryptor(rx);
        tx = client_keys.sharedTx;
        encryptor = await Encryptor(tx);
        otherPeer.generateSharedKeys(object);
    }

    return object;

}