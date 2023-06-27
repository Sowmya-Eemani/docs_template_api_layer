<!DOCTYPE html>
<html class="staticrypt-html">
    <head>
        <meta charset="utf-8" />
        <title>Protected Page</title>
        <meta name="viewport" content="width=device-width, initial-scale=1" />

        <!-- do not cache this page -->
        <meta http-equiv="cache-control" content="max-age=0" />
        <meta http-equiv="cache-control" content="no-cache" />
        <meta http-equiv="expires" content="0" />
        <meta http-equiv="expires" content="Tue, 01 Jan 1980 1:00:00 GMT" />
        <meta http-equiv="pragma" content="no-cache" />

        <style>
            .staticrypt-hr {
                margin-top: 20px;
                margin-bottom: 20px;
                border: 0;
                border-top: 1px solid #eee;
            }

            .staticrypt-page {
                width: 360px;
                padding: 8% 0 0;
                margin: auto;
                box-sizing: border-box;
            }

            .staticrypt-form {
                position: relative;
                z-index: 1;
                background: #ffffff;
                max-width: 360px;
                margin: 0 auto 100px;
                padding: 45px;
                text-align: center;
                box-shadow: 0 0 20px 0 rgba(0, 0, 0, 0.2), 0 5px 5px 0 rgba(0, 0, 0, 0.24);
            }

            .staticrypt-form input[type="password"] {
                outline: 0;
                background: #f2f2f2;
                width: 100%;
                border: 0;
                margin: 0 0 15px;
                padding: 15px;
                box-sizing: border-box;
                font-size: 14px;
            }

            .staticrypt-form .staticrypt-decrypt-button {
                text-transform: uppercase;
                outline: 0;
                background: #4CAF50;
                width: 100%;
                border: 0;
                padding: 15px;
                color: #ffffff;
                font-size: 14px;
                cursor: pointer;
            }

            .staticrypt-form .staticrypt-decrypt-button:hover,
            .staticrypt-form .staticrypt-decrypt-button:active,
            .staticrypt-form .staticrypt-decrypt-button:focus {
                background: #4CAF50;
                filter: brightness(92%);
            }

            .staticrypt-html {
                height: 100%;
            }

            .staticrypt-body {
                height: 100%;
                margin: 0;
            }

            .staticrypt-content {
                height: 100%;
                margin-bottom: 1em;
                background: #76B852;
                font-family: "Arial", sans-serif;
                -webkit-font-smoothing: antialiased;
                -moz-osx-font-smoothing: grayscale;
            }

            .staticrypt-instructions {
                margin-top: -1em;
                margin-bottom: 1em;
            }

            .staticrypt-title {
                font-size: 1.5em;
            }

            label.staticrypt-remember {
                display: flex;
                align-items: center;
                margin-bottom: 1em;
            }

            .staticrypt-remember input[type="checkbox"] {
                transform: scale(1.5);
                margin-right: 1em;
            }

            .hidden {
                display: none !important;
            }

            .staticrypt-spinner-container {
                height: 100%;
                display: flex;
                align-items: center;
                justify-content: center;
            }

            .staticrypt-spinner {
                display: inline-block;
                width: 2rem;
                height: 2rem;
                vertical-align: text-bottom;
                border: 0.25em solid gray;
                border-right-color: transparent;
                border-radius: 50%;
                -webkit-animation: spinner-border 0.75s linear infinite;
                animation: spinner-border 0.75s linear infinite;
                animation-duration: 0.75s;
                animation-timing-function: linear;
                animation-delay: 0s;
                animation-iteration-count: infinite;
                animation-direction: normal;
                animation-fill-mode: none;
                animation-play-state: running;
                animation-name: spinner-border;
            }

            @keyframes spinner-border {
                100% {
                    transform: rotate(360deg);
                }
            }
        </style>
    </head>

    <body class="staticrypt-body">
        <div id="staticrypt_loading" class="staticrypt-spinner-container">
            <div class="staticrypt-spinner"></div>
        </div>

        <div id="staticrypt_content" class="staticrypt-content hidden">
            <div class="staticrypt-page">
                <div class="staticrypt-form">
                    <div class="staticrypt-instructions">
                        <p class="staticrypt-title">Protected Page</p>
                        <p></p>
                    </div>

                    <hr class="staticrypt-hr" />

                    <form id="staticrypt-form" action="#" method="post">
                        <input
                            id="staticrypt-password"
                            type="password"
                            name="password"
                            placeholder="Password"
                            autofocus
                        />

                        <label id="staticrypt-remember-label" class="staticrypt-remember hidden">
                            <input id="staticrypt-remember" type="checkbox" name="remember" />
                            Remember me
                        </label>

                        <input type="submit" class="staticrypt-decrypt-button" value="DECRYPT" />
                    </form>
                </div>
            </div>
        </div>

        <script>
            // these variables will be filled when generating the file - the template format is 'variable_name'
            const staticryptInitiator = ((function(){
  const exports = {};
  const cryptoEngine = ((function(){
  const exports = {};
  const { subtle } = crypto;

const IV_BITS = 16 * 8;
const HEX_BITS = 4;
const ENCRYPTION_ALGO = "AES-CBC";

/**
 * Translates between utf8 encoded hexadecimal strings
 * and Uint8Array bytes.
 */
const HexEncoder = {
    /**
     * hex string -> bytes
     * @param {string} hexString
     * @returns {Uint8Array}
     */
    parse: function (hexString) {
        if (hexString.length % 2 !== 0) throw "Invalid hexString";
        const arrayBuffer = new Uint8Array(hexString.length / 2);

        for (let i = 0; i < hexString.length; i += 2) {
            const byteValue = parseInt(hexString.substring(i, i + 2), 16);
            if (isNaN(byteValue)) {
                throw "Invalid hexString";
            }
            arrayBuffer[i / 2] = byteValue;
        }
        return arrayBuffer;
    },

    /**
     * bytes -> hex string
     * @param {Uint8Array} bytes
     * @returns {string}
     */
    stringify: function (bytes) {
        const hexBytes = [];

        for (let i = 0; i < bytes.length; ++i) {
            let byteString = bytes[i].toString(16);
            if (byteString.length < 2) {
                byteString = "0" + byteString;
            }
            hexBytes.push(byteString);
        }
        return hexBytes.join("");
    },
};

/**
 * Translates between utf8 strings and Uint8Array bytes.
 */
const UTF8Encoder = {
    parse: function (str) {
        return new TextEncoder().encode(str);
    },

    stringify: function (bytes) {
        return new TextDecoder().decode(bytes);
    },
};

/**
 * Salt and encrypt a msg with a password.
 */
async function encrypt(msg, hashedPassword) {
    // Must be 16 bytes, unpredictable, and preferably cryptographically random. However, it need not be secret.
    // https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt#parameters
    const iv = crypto.getRandomValues(new Uint8Array(IV_BITS / 8));

    const key = await subtle.importKey("raw", HexEncoder.parse(hashedPassword), ENCRYPTION_ALGO, false, ["encrypt"]);

    const encrypted = await subtle.encrypt(
        {
            name: ENCRYPTION_ALGO,
            iv: iv,
        },
        key,
        UTF8Encoder.parse(msg)
    );

    // iv will be 32 hex characters, we prepend it to the ciphertext for use in decryption
    return HexEncoder.stringify(iv) + HexEncoder.stringify(new Uint8Array(encrypted));
}
exports.encrypt = encrypt;

/**
 * Decrypt a salted msg using a password.
 *
 * @param {string} encryptedMsg
 * @param {string} hashedPassword
 * @returns {Promise<string>}
 */
async function decrypt(encryptedMsg, hashedPassword) {
    const ivLength = IV_BITS / HEX_BITS;
    const iv = HexEncoder.parse(encryptedMsg.substring(0, ivLength));
    const encrypted = encryptedMsg.substring(ivLength);

    const key = await subtle.importKey("raw", HexEncoder.parse(hashedPassword), ENCRYPTION_ALGO, false, ["decrypt"]);

    const outBuffer = await subtle.decrypt(
        {
            name: ENCRYPTION_ALGO,
            iv: iv,
        },
        key,
        HexEncoder.parse(encrypted)
    );

    return UTF8Encoder.stringify(new Uint8Array(outBuffer));
}
exports.decrypt = decrypt;

/**
 * Salt and hash the password so it can be stored in localStorage without opening a password reuse vulnerability.
 *
 * @param {string} password
 * @param {string} salt
 * @returns {Promise<string>}
 */
async function hashPassword(password, salt) {
    // we hash the password in multiple steps, each adding more iterations. This is because we used to allow less
    // iterations, so for backward compatibility reasons, we need to support going from that to more iterations.
    let hashedPassword = await hashLegacyRound(password, salt);

    hashedPassword = await hashSecondRound(hashedPassword, salt);

    return hashThirdRound(hashedPassword, salt);
}
exports.hashPassword = hashPassword;

/**
 * This hashes the password with 1k iterations. This is a low number, we need this function to support backwards
 * compatibility.
 *
 * @param {string} password
 * @param {string} salt
 * @returns {Promise<string>}
 */
function hashLegacyRound(password, salt) {
    return pbkdf2(password, salt, 1000, "SHA-1");
}
exports.hashLegacyRound = hashLegacyRound;

/**
 * Add a second round of iterations. This is because we used to use 1k, so for backwards compatibility with
 * remember-me/autodecrypt links, we need to support going from that to more iterations.
 *
 * @param hashedPassword
 * @param salt
 * @returns {Promise<string>}
 */
function hashSecondRound(hashedPassword, salt) {
    return pbkdf2(hashedPassword, salt, 14000, "SHA-256");
}
exports.hashSecondRound = hashSecondRound;

/**
 * Add a third round of iterations to bring total number to 600k. This is because we used to use 1k, then 15k, so for
 * backwards compatibility with remember-me/autodecrypt links, we need to support going from that to more iterations.
 *
 * @param hashedPassword
 * @param salt
 * @returns {Promise<string>}
 */
function hashThirdRound(hashedPassword, salt) {
    return pbkdf2(hashedPassword, salt, 585000, "SHA-256");
}
exports.hashThirdRound = hashThirdRound;

/**
 * Salt and hash the password so it can be stored in localStorage without opening a password reuse vulnerability.
 *
 * @param {string} password
 * @param {string} salt
 * @param {int} iterations
 * @param {string} hashAlgorithm
 * @returns {Promise<string>}
 */
async function pbkdf2(password, salt, iterations, hashAlgorithm) {
    const key = await subtle.importKey("raw", UTF8Encoder.parse(password), "PBKDF2", false, ["deriveBits"]);

    const keyBytes = await subtle.deriveBits(
        {
            name: "PBKDF2",
            hash: hashAlgorithm,
            iterations,
            salt: UTF8Encoder.parse(salt),
        },
        key,
        256
    );

    return HexEncoder.stringify(new Uint8Array(keyBytes));
}

function generateRandomSalt() {
    const bytes = crypto.getRandomValues(new Uint8Array(128 / 8));

    return HexEncoder.stringify(new Uint8Array(bytes));
}
exports.generateRandomSalt = generateRandomSalt;

async function signMessage(hashedPassword, message) {
    const key = await subtle.importKey(
        "raw",
        HexEncoder.parse(hashedPassword),
        {
            name: "HMAC",
            hash: "SHA-256",
        },
        false,
        ["sign"]
    );
    const signature = await subtle.sign("HMAC", key, UTF8Encoder.parse(message));

    return HexEncoder.stringify(new Uint8Array(signature));
}
exports.signMessage = signMessage;

function getRandomAlphanum() {
    const possibleCharacters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

    let byteArray;
    let parsedInt;

    // Keep generating new random bytes until we get a value that falls
    // within a range that can be evenly divided by possibleCharacters.length
    do {
        byteArray = crypto.getRandomValues(new Uint8Array(1));
        // extract the lowest byte to get an int from 0 to 255 (probably unnecessary, since we're only generating 1 byte)
        parsedInt = byteArray[0] & 0xff;
    } while (parsedInt >= 256 - (256 % possibleCharacters.length));

    // Take the modulo of the parsed integer to get a random number between 0 and totalLength - 1
    const randomIndex = parsedInt % possibleCharacters.length;

    return possibleCharacters[randomIndex];
}

/**
 * Generate a random string of a given length.
 *
 * @param {int} length
 * @returns {string}
 */
function generateRandomString(length) {
    let randomString = "";

    for (let i = 0; i < length; i++) {
        randomString += getRandomAlphanum();
    }

    return randomString;
}
exports.generateRandomString = generateRandomString;

  return exports;
})());
const codec = ((function(){
  const exports = {};
  /**
 * Initialize the codec with the provided cryptoEngine - this return functions to encode and decode messages.
 *
 * @param cryptoEngine - the engine to use for encryption / decryption
 */
function init(cryptoEngine) {
    const exports = {};

    /**
     * Top-level function for encoding a message.
     * Includes password hashing, encryption, and signing.
     *
     * @param {string} msg
     * @param {string} password
     * @param {string} salt
     *
     * @returns {string} The encoded text
     */
    async function encode(msg, password, salt) {
        const hashedPassword = await cryptoEngine.hashPassword(password, salt);

        const encrypted = await cryptoEngine.encrypt(msg, hashedPassword);

        // we use the hashed password in the HMAC because this is effectively what will be used a password (so we can store
        // it in localStorage safely, we don't use the clear text password)
        const hmac = await cryptoEngine.signMessage(hashedPassword, encrypted);

        return hmac + encrypted;
    }
    exports.encode = encode;

    /**
     * Encode using a password that has already been hashed. This is useful to encode multiple messages in a row, that way
     * we don't need to hash the password multiple times.
     *
     * @param {string} msg
     * @param {string} hashedPassword
     *
     * @returns {string} The encoded text
     */
    async function encodeWithHashedPassword(msg, hashedPassword) {
        const encrypted = await cryptoEngine.encrypt(msg, hashedPassword);

        // we use the hashed password in the HMAC because this is effectively what will be used a password (so we can store
        // it in localStorage safely, we don't use the clear text password)
        const hmac = await cryptoEngine.signMessage(hashedPassword, encrypted);

        return hmac + encrypted;
    }
    exports.encodeWithHashedPassword = encodeWithHashedPassword;

    /**
     * Top-level function for decoding a message.
     * Includes signature check and decryption.
     *
     * @param {string} signedMsg
     * @param {string} hashedPassword
     * @param {string} salt
     * @param {int} backwardCompatibleAttempt
     * @param {string} originalPassword
     *
     * @returns {Object} {success: true, decoded: string} | {success: false, message: string}
     */
    async function decode(signedMsg, hashedPassword, salt, backwardCompatibleAttempt = 0, originalPassword = "") {
        const encryptedHMAC = signedMsg.substring(0, 64);
        const encryptedMsg = signedMsg.substring(64);
        const decryptedHMAC = await cryptoEngine.signMessage(hashedPassword, encryptedMsg);

        if (decryptedHMAC !== encryptedHMAC) {
            // we have been raising the number of iterations in the hashing algorithm multiple times, so to support the old
            // remember-me/autodecrypt links we need to try bringing the old hashes up to speed.
            originalPassword = originalPassword || hashedPassword;
            if (backwardCompatibleAttempt === 0) {
                const updatedHashedPassword = await cryptoEngine.hashThirdRound(originalPassword, salt);

                return decode(signedMsg, updatedHashedPassword, salt, backwardCompatibleAttempt + 1, originalPassword);
            }
            if (backwardCompatibleAttempt === 1) {
                let updatedHashedPassword = await cryptoEngine.hashSecondRound(originalPassword, salt);
                updatedHashedPassword = await cryptoEngine.hashThirdRound(updatedHashedPassword, salt);

                return decode(signedMsg, updatedHashedPassword, salt, backwardCompatibleAttempt + 1, originalPassword);
            }

            return { success: false, message: "Signature mismatch" };
        }

        return {
            success: true,
            decoded: await cryptoEngine.decrypt(encryptedMsg, hashedPassword),
        };
    }
    exports.decode = decode;

    return exports;
}
exports.init = init;

  return exports;
})());
const decode = codec.init(cryptoEngine).decode;

/**
 * Initialize the staticrypt module, that exposes functions callbable by the password_template.
 *
 * @param {{
 *  staticryptEncryptedMsgUniqueVariableName: string,
 *  isRememberEnabled: boolean,
 *  rememberDurationInDays: number,
 *  staticryptSaltUniqueVariableName: string,
 * }} staticryptConfig - object of data that is stored on the password_template at encryption time.
 *
 * @param {{
 *  rememberExpirationKey: string,
 *  rememberPassphraseKey: string,
 *  replaceHtmlCallback: function,
 *  clearLocalStorageCallback: function,
 * }} templateConfig - object of data that can be configured by a custom password_template.
 */
function init(staticryptConfig, templateConfig) {
    const exports = {};

    /**
     * Decrypt our encrypted page, replace the whole HTML.
     *
     * @param {string} hashedPassword
     * @returns {Promise<boolean>}
     */
    async function decryptAndReplaceHtml(hashedPassword) {
        const { staticryptEncryptedMsgUniqueVariableName, staticryptSaltUniqueVariableName } = staticryptConfig;
        const { replaceHtmlCallback } = templateConfig;

        const result = await decode(
            staticryptEncryptedMsgUniqueVariableName,
            hashedPassword,
            staticryptSaltUniqueVariableName
        );
        if (!result.success) {
            return false;
        }
        const plainHTML = result.decoded;

        // if the user configured a callback call it, otherwise just replace the whole HTML
        if (typeof replaceHtmlCallback === "function") {
            replaceHtmlCallback(plainHTML);
        } else {
            document.write(plainHTML);
            document.close();
        }

        return true;
    }

    /**
     * Attempt to decrypt the page and replace the whole HTML.
     *
     * @param {string} password
     * @param {boolean} isRememberChecked
     *
     * @returns {Promise<{isSuccessful: boolean, hashedPassword?: string}>} - we return an object, so that if we want to
     *   expose more information in the future we can do it without breaking the password_template
     */
    async function handleDecryptionOfPage(password, isRememberChecked) {
        const { isRememberEnabled, rememberDurationInDays, staticryptSaltUniqueVariableName } = staticryptConfig;
        const { rememberExpirationKey, rememberPassphraseKey } = templateConfig;

        // decrypt and replace the whole page
        const hashedPassword = await cryptoEngine.hashPassword(password, staticryptSaltUniqueVariableName);

        const isDecryptionSuccessful = await decryptAndReplaceHtml(hashedPassword);

        if (!isDecryptionSuccessful) {
            return {
                isSuccessful: false,
                hashedPassword,
            };
        }

        // remember the hashedPassword and set its expiration if necessary
        if (isRememberEnabled && isRememberChecked) {
            window.localStorage.setItem(rememberPassphraseKey, hashedPassword);

            // set the expiration if the duration isn't 0 (meaning no expiration)
            if (rememberDurationInDays > 0) {
                window.localStorage.setItem(
                    rememberExpirationKey,
                    (new Date().getTime() + rememberDurationInDays * 24 * 60 * 60 * 1000).toString()
                );
            }
        }

        return {
            isSuccessful: true,
            hashedPassword,
        };
    }
    exports.handleDecryptionOfPage = handleDecryptionOfPage;

    /**
     * Clear localstorage from staticrypt related values
     */
    function clearLocalStorage() {
        const { clearLocalStorageCallback, rememberExpirationKey, rememberPassphraseKey } = templateConfig;

        if (typeof clearLocalStorageCallback === "function") {
            clearLocalStorageCallback();
        } else {
            localStorage.removeItem(rememberPassphraseKey);
            localStorage.removeItem(rememberExpirationKey);
        }
    }

    async function handleDecryptOnLoad() {
        let isSuccessful = await decryptOnLoadFromUrl();

        if (!isSuccessful) {
            isSuccessful = await decryptOnLoadFromRememberMe();
        }

        return { isSuccessful };
    }
    exports.handleDecryptOnLoad = handleDecryptOnLoad;

    /**
     * Clear storage if we are logging out
     *
     * @returns {boolean} - whether we logged out
     */
    function logoutIfNeeded() {
        const logoutKey = "staticrypt_logout";

        // handle logout through query param
        const queryParams = new URLSearchParams(window.location.search);
        if (queryParams.has(logoutKey)) {
            clearLocalStorage();
            return true;
        }

        // handle logout through URL fragment
        const hash = window.location.hash.substring(1);
        if (hash.includes(logoutKey)) {
            clearLocalStorage();
            return true;
        }

        return false;
    }

    /**
     * To be called on load: check if we want to try to decrypt and replace the HTML with the decrypted content, and
     * try to do it if needed.
     *
     * @returns {Promise<boolean>} true if we derypted and replaced the whole page, false otherwise
     */
    async function decryptOnLoadFromRememberMe() {
        const { rememberDurationInDays } = staticryptConfig;
        const { rememberExpirationKey, rememberPassphraseKey } = templateConfig;

        // if we are login out, terminate
        if (logoutIfNeeded()) {
            return false;
        }

        // if there is expiration configured, check if we're not beyond the expiration
        if (rememberDurationInDays && rememberDurationInDays > 0) {
            const expiration = localStorage.getItem(rememberExpirationKey),
                isExpired = expiration && new Date().getTime() > parseInt(expiration);

            if (isExpired) {
                clearLocalStorage();
                return false;
            }
        }

        const hashedPassword = localStorage.getItem(rememberPassphraseKey);

        if (hashedPassword) {
            // try to decrypt
            const isDecryptionSuccessful = await decryptAndReplaceHtml(hashedPassword);

            // if the decryption is unsuccessful the password might be wrong - silently clear the saved data and let
            // the user fill the password form again
            if (!isDecryptionSuccessful) {
                clearLocalStorage();
                return false;
            }

            return true;
        }

        return false;
    }

    function decryptOnLoadFromUrl() {
        const passwordKey = "staticrypt_pwd";

        // get the password from the query param
        const queryParams = new URLSearchParams(window.location.search);
        const hashedPasswordQuery = queryParams.get(passwordKey);

        // get the password from the url fragment
        const hashRegexMatch = window.location.hash.substring(1).match(new RegExp(passwordKey + "=(.*)"));
        const hashedPasswordFragment = hashRegexMatch ? hashRegexMatch[1] : null;

        const hashedPassword = hashedPasswordFragment || hashedPasswordQuery;

        if (hashedPassword) {
            return decryptAndReplaceHtml(hashedPassword);
        }

        return false;
    }

    return exports;
}
exports.init = init;

  return exports;
})());
            const templateError = "Bad password!",
                isRememberEnabled = true,
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"a7fddc6a48e6a54d0fa6a13bdaa61df4da20290cc2f4eec80c584d1d29f6459344f70bd055763f97a9b55de1f6e5b55bc04c43589a13fdc23e701e0ca161fda3f1648470ab2961548006667eb48a33533c268a80a409c614b283fbe59a4ca233af802930d7e10fcc00b2f166e274bbfee1115b311856b3fef95c139d99154f444c9f756c81605a4d76461d71514f6328ad3bedd4765d21c811866eb402f75c9a6e640e09fda7808cb86d30f6a3c963bbbc827d3e1594a14e1de49ce668cf129db39a2af80dca5094482ed2e563caf117f3e153e99ccf46f7973319440ee93710d954c0b7ffd83bec3115fe5919f9b841184609c0f90ef8212577efe3558ba6e115f51a3628ce6e1a28da8e3c1750ae835ddd013e2b4ade571d31df6e9cfcc8a510790240cefc5356cd246c8bde617799cd12c6d0cdb2c0dce5d30584cf1d9ef6e2086cc670f6916c897baaf62651045e3d7b2e90a44afd0ca9a4d7d55322d72723c114c29c6fe3f65ff2e7c7737d5e01203eb50b49ae959576cff4014899d38b181ed4a4dafefaca53a3cb0be21a2f9212c75cd6089455b38e4d4eadc991cbf3c69b64a6db99cbe86a6409b0a0e312d6b386d1e309f7d9a66aaa4bb17dd297849252805f7843a8990e396d7dc2ae07a29b2c45d2646eec2c7553921e62e9aeff9bce04d3b89a5a11a0562be30cfa0c73190de206811c2d07f040eabbfe41e2020aeb3449f3aa32e146fb9ab9e4210a7708beab1d3734ca36e446928a83d08ce9348dac38f78f1a2e947d707b8598cc165da05c9b55049292daa98c488951686c54bb0ba08be65fa0a733e2f8f23912371cabd76f9068fd01de09b0256b907ab59d7d6972f971fedd7883e3491588bcabcd63577f5929215c595118a5b0c532de4c429ace1428e16749d7dd5d868e0029319f2bf1591e96a9679ebe2c7e0a6224bd2c5489690d58df7685b5552740f6befb6589fb64ac7496a975bb0b82b128e262659721ca56c67d6d27b1a03dd1fa9f2403f95b3c6b1e413fc006cc782500a883faa6ef32505ce57b331ea31c2fc00a1c4e881f333981c8fed2b305e0b21629d496707e3a000f77ecae504d71f7ca99a20892d3d654188117f815fde2b3b9474e1891a7d7317cd755a5ae6b6538ee743158bc482efd5da96e7f09b88f411ec588d16d3d7a02cd55d47d1ea4b4ade35633a6bdaa12b5f41d73b6446e3b0e808629afc5c92f9bb9bf2e6173ca4ca8650d04d89dbebd660fc1088b06896cb6bfcd8c75f3dbcd7635c8003222c9404eb38743f7ec86adf1af06d65f5bb6abdadc588789581d7885990a3e3a5a03f83a3de4bffcaf2a57aeabf0ba6e7a656dc799793ba915c50548dff264ff92928132d803e2ed4b7649000cc174a53013e654e4957770fbda73b07ed0d3e481785a2e340537baefe97b95f4279a9779eea101e8acc12665dcca3a0100e2c022834e95fe2367fcfeb9492723a00f5b012e631da4a9a31a75c8fc0a712fcadbe8ef56c71dc82e1564d08e7c5e88063101ca261e495de5cac00e84aef0a061157107eb4c716a8828a33baaaa8f2c3f709179350415e74d90e6ef09bc31f7f22e23cccd008238fac894e2fc65daa7db5e14c5813b86c2ae377d4cf3e4aef4f69b5f984bfa077a7ce86a4670e919271e1674a4d58aec7391cc43acb701d32ea805768f66a99aa0050f4412bcbd98d0b9d31c94f4ff362c748ca9042dd8b4b519ade51140a1f76debedcde3cbc9e806f077fd013dc3b0751848f6e6a61fcf537e5cf970dd1db9df2824f2cd4f25287c12d6e5d66e2248423b28b7bc950e96a123c316ceef883ec858090548cebcfa28069f5b7b1ff13166e208bd18964d87c0aad8c2213014b08c137bf739aa85051d801b94242d605c80f70fa006cd4da1f315a63e61da23f4a9fab954e8c4803ef118545c3e2d447d45a75186047f26a51cd26fb7d865f720a701adba8e27c09f4d099c0ff82f294dbf066f9af8c80eb2e74fe494583d0c1d6e91cfb3c2b07503992567ed17d4db2fe8bfb0a79f67c36e43ebd9748ee1348eaec40bb4995872f15bfe668424e0abdc8d223de2847c5e955862014f7512774296e7f23961078fd5fc4bd62db4429a59e6b761768d0ef032daf3023ac14d5805cf3674930bd441f4178eefd7c3031b26b21452d17566d9e72b3a454cbfd160b38815a66cf96c6858866951ec25cc0e56f2bf2e7ed9e343e3c9b961229aa6d9d166a7c301bf73f3337b50843c8adc1f7706549d5b1bbca194525f180a6b7969f592e249aeb69dd07486b29f911bc185ee595f039a0905f90e7d815c20a83ded32e4417bbd3b5f5eda948908242e4e011ce379a33f3960b33cf2b96e324bbb074dcac2bf1d6b4c14e623cbc90f2baaccb8610eb57e5637dee4f8cae0c8aee9803a9630a48f95e22d079aad774697885dacb2889eb76ac0fd21fedd9d2869c63989fb17d8b2ecf566849fdd7343463df18a0598e154f84fc2c4d30e05457bfe9ff280aca120155be82d6379902824370cabb5ec1fad10778e493018410de76cee78bde6d7c4ba0d17f7847632dc288cc75d2983d9b93623d77ed49575b368924b63e40645267cd843398a359c77907f8bf915906423b23403ee82ad3794b8905794f4e01129fddef560a67dd3630748477c2d69d8496069c44fbc8e79aebf92266cf731d6baf0220d090d44e512a16f41dd4b06e9d18b870d4f2e7dcff98d1aba1a5c0c3964ef3ae90524e65c1d907be59875b65d5093050148d4a6dfa735a2ff266c5224e8b2d6a75300e4d0f36a897bd179e18938f740224716d9ba3c3391292a91c23e57fc941d72c7dfd8d7a1b3c50e00fc1f9e14f42ee486aa7eed8576360ce1972054826156696fd8c97f4ed11000a68486a2cc088a3dfa6c937a5d58dd7c007adaf5bcd911e7d39a6e813d17101db2ed0406c1227ebbc51906771856819aad81145e6143506c57784dac344467c46053f3c6f71f8c2a4c0485059f494125d984c958bc5551d7de2c592fbe7761b87d80a9f9303fbef0221243005056e28614d6b6354678c0b4a1db2f933e0ac3ffed4fd921816c604b30186187656fed88b0c82d6f3c6794a0ced6474504690bd6f8dd571ef1c75efdb391ea01191ad04394fa630fb878753b64142c601cedda7049a3286d0365c277c87a517bf4f94ec5e8440c0a833f1e24cb65fe72060ee78d2d04119686275097256422b78696d3837d933c49bed7cd585e8da167f983d4879d870b2e05fd2b3808603f7ea2e341b49886606904e67a638cb23707a25191ea9ce9c6ffe0dfe263469ee3835dab973584200ea0e176644613dc97253f4ed8763722e52937404029d63a412a1629b47d147423ae5907852f4f8d1379f44c04d233dff5ddc286157b7fb93a1b7b616dd6aaeeddbf52178127a6c7beec9788fd975dda0f0113ba00020a1a73f0230b51baa679b55ca70fdbfeb73e201de84e97dfc8b1c202f077f46cd31ff7e710e1928ad87d873535614f78767983383487c3f231c5ffeaecb9920ed037b71065b6c0c79ca8209c1a650a895c53618dbd8ed8c18153a3177d43722629e1802cebf0f3fe177acbd909ed8c2f8dfd85f5b25a46eb2206f4aa869edeb70398c2b93e3a506a65ac2289eb766ec0f0e92e55b42c97ba5ff9faa81d6b576f3d1c0820f50d6dd67be368121ece96cefcbea6a364a28f6a9bf21b67c3395d21ba586015ff361312f935ae678687caca75d42470f6f71a4892be8242ee317f30cd7d0f82397259a559ccadfe264e574c7cbd989b9da8f9a666454277b1ed4583c3d158b6c5fd19fb818232d6dc3c2b9c27ee2d51daef0ee82cc99fa8c0e4b27e7b778b601a004da80b4d764b63eac456ecbabc171a9d85476651ba8a31cf086f1251f36a510681c3d58a687c96c51e45fa4ece6188f8f7a0593b168db9b99dbdc5b616f44a077adc9774dd740b15ac282375dfa1ff503d276cef26bcec40da135de82ca5ccebb0c506e4f711ca82a6c1ffd32b54cd891b81cdd602fdd1112884b64fddee79f5116917e50c01198f17a081c68763ed32d91fa97f1f7f6235c0eabf1e959a2084bc720d0e97c312d9fc080bf46a0ccae28d5ac5c967f1c7e537d85ab225dd8b50e8ef8bd3ac7452be37f326c90452e4d25a2497b132729b9266def86e4d4e44d2d596a4856c48028d381266e72386f945d816ff92bfad11c088f69afca9c65f3dca47b3325eddeba2f62a3bda16c5475771328da51c9501def61f9f35ba3ba83f6385bfbbf0a4decbbd929080fe21330b137aca5f9697b2d6431b2ed004216a093a9e18df0dd8fd1e9cc2d7eeff9d73b319c8abd4c15cfa584279eff3633fb8ac081eba5352abb83a1714fdabd1cc3a4ce5c1903263a69c4826993881c4240fd86cbda0cc82023042b00a67adcb121862cb04aaa1ebc92ea48107791dba666acbd372f13b1d0e9c3a5b263796e840ffc5e32805ea4d889bab915fe6147a3c3f1916934d3962d708d87377b6893407ea80122b6ee152b465024151d0e62c65f36fcd8a13a0678ae18b0734d9fadfd1722be3c8bf7207c8dd6c2b0bbcb664adeeac728dd46a7206509e930767d59b1b934d49a5214057bd6e7e6eab95fe1edf6e9210b48e5624c6f0d71c6be2e2b77b46b4c990485ecea7cd903a6e62146f82d47e12de43829cebcdbbef6515b7a5ef4b4e0b327125e233ff0ca9b0229509163af6435e7543c1eb7dd10e39d32339657673f9ce126ab0519ee2b25485e2f4ec0bfa4080eb559ba3be21c237f641fe6c87b14c36b29c668dccebad2d075cad8ee7b9c824081aab12a316b509ca7eeb5faea96cccebdcf92e8a164ce9e4f4e2d170faa25202a66cce62fe8a8510ce14db27e6ecab26b6d7c9825940bc02c0a297472432ff018df29d93366be703ca7223cb3225c6ee405927de45c6167e9ee3f30ae3f0375d5c2341b292f6e59b3d6414a2fae72e69de01852428e80840a40e1714535654c7637edc26278e78851b289e6e4771ff1d136a9e7d5ceacfac4981a74e55ad518da2f3ba08841d70a0cc9c1d85924361800ecc1688613c06de974762af171406327c316df31c8f4dcab2878c21f32769ca03c451dda65bbaf5a7ff716507d50fb76f49a146c74bb018f2eee8cb67f79779866ca2b5629975066a801f594bc2248cfd57779fec72301faa591a96e2bc0d3b1c74379f5e14558e0496bfa5ce304c7dbe5bf34fa8c4d7355dbc72d0a7cf4d48aa3821b86195bd6ffcd7d2b5eee83da8ed81dd0a73081f08615dab7dc964b735a71ae96fb33bfc6ced33f38cb657a3148e8225f12ecdcd5c79bd30c9881974bf096b2d92006d1bf81ca9a808be2c0c8eaa55f5ee6582580f3c71b7ba782d8bf01b2b9d60625cc1c1c065e1248394deb1b7939e37beb073b1ff8a2ef4aaced6b68aebafdd5f73733df6945d69bdb39bdb47d939f3abccd4cabd88a85fdc5c94ab274d85133a66be2a26ede14abe53c356985d17b7c5c7955ef7dc0c39e631cd525ea2d6f8a1502008c992ca56c8d709dc0a2cff4b816dd61cfd569ce3358b8c781234eb5ab172ea21cdc191c22fe09d96d93431c4937236f2502c2913fcaaf8064c0de41ad3cb8274ef23249795f4b5ee8320831fa84c76e4d7d65de97e52d063263a8d212be8393bb57f8e39abaabf7e3bedbfeb9e2b2f350044bd262897c4ff5d5e33604e6dd9c39c8e38f156ea3cab0966320bb01cd001fc1f1bb9bc0f10b2fac83417f4923f758b62f43e6ea17d623e5828d588aba99632ab7c0cb2587f4b5b016f2831d432b0d5886abc4b185d6d11b95fa1dc4119b337f8251b84cfadc4c5de3db93fc26d0dee660d51a71fb2dda9adfe7adf29378480d365ad72e58b3ec8327421074846aa9747b710f735be8a271c0672b6fb59355cf93b730c447b8cd24b269b26f6b21a9014e24f8a42b10a37c92c40987374a5145533bea61d693207fc6c4589e6459d6d687420d5c06c7370780164739c9663f81f39fb896f95bd704e44746977f5b9d96f5e860b13edc5c962eac2c350ecb7051f87ca701ab3dcda23ac774a455ca4637cb925d27e8b9317342b115ce409d129f1ecd066748ca07d5c7cddaaecc874a413f247d1b6469d8e9dac7e34a3926a31a9a2aa22bd1a9c43c6fca7aa7716398314cb41f26d8c9afc28dcab978eebe741aef448a4a55b677b4c16e62c3532559027e4f591e477ea35b8accbace41d205fa787b2cc54ed763950b7e0f9ef2428a5521abc267490c9d89ef77fc9df47427698e96a5043e30c01b30bb0cb35a74284e152dbe71d40fe9130db50436405db79c47fd5c0bcddf3bfa16680b064f41d545db13d24a1440b6a7fc973929f6b521f1dbb21af6341803ba74f8f794c03e5e4c431676020deea6f5b9b11dc2f97106e640fbc15bb516d63d2df7430d1058a7dbc51a229dc344e150ce0229addc2dd7c42b08abe53daec23c9a666129f96a879d35bd57a476b9857a0fa5926bb28e77ad9c3c8434f16a47fa8a75b34fef8b0c2600f8c3c6d976e41563d33b4db6242c93220ac8414f133035d9ccf03b02284b6d1415f6f1965ef46b82bb554bbcde27fd0bcf9a512fcce5270f84d0a9257517bffc50bb7e220039d9a5378f903690ad264b9ef66bbc4500229ea9deb4ff1d46806b7ee024ba4e381673bbcc1301869d22f5c6d14a575da9817f22bd764d535de7815b3884d97bdfb1f87a6a24858c90844b330ec002d1b971459790e7230af991b2dfa549a362d8e7f310e433a97d07849e90070585ba7688892f16504135c3d6234d3aef8a82d9f74ff6d8e866627d8e25bc7fdcec05961a2eabf0391f941409e07e91aa97564f8ac6e8104e72527adbd1ebcd90cc8bfcda1d16b37e7e5bdd49b0b4e520c98d81d53f568d50ce5b1d60cdb6579443a55d98429b4e8918e115f322786d173c70f30a768ecfeae13d1e9460593b85dcef02a4e355cf0120300d6c889d8368536d31aeed395324af803d431d91764011fb1ffbe0bdbb97c1a56fcb29484de6f58db1351b2474f6f16c98263f228c4e87f4d531fb6bb198a4e59a8d55e2a84cde8f9984201061a8b2dc1154c9e38175a4415ed6843441bc7a9d4e9aee0f0360c45e18d74f70ff0f15ec1cf1d1aca4a9b3d9f7e7e7183d847f213de13841dfbd65c0f24841817d4e5e1c59f004bd5efb303e6a9d74db4893b31b8a30eb5601e2d2c7c2d703bc306b53475f32e2dd2a965a134a7a548294d24d3a1d29f6220b46c60f9589233e54ee9d22e8d1dace51c6aa4117b9767813945b06652625d118906430c12461af5bc7dabc04457bd8480d80aefafd45819e730515268fe860febf5807b3a0bbf58c044ef2cd26c503a32e87a9f1aa2e8d5a1f0afe3465d6053828ce62279165161564ca7d985cc38f4307e80b1c6f7b2068268d8783296301f1f0223394d824eab1d1746cd7770194047d9a2a137276084651cc574bc73c41ebd61a0d1b62194e405cdae75d5d936da89de5a7328a1b5fd443700b9c9c779be927f58f0997f1eed02b20be83393329e91c5ba5cbb7e6b7ff5b28b8629439cdd7cfc26244fe617c91c855f8d61c19cee6322e57f5c9ead9dd209aae4ff59bcb107eaf120477ecf31269444b5e0354ffc2564197e40b0a523ed8cdab95950ba458eed91ff7f623e19abdfbb6571cb5f774835c11daa5dbd4f18800f70cae7f56fc1b62864bf8b884cfd222a94b924adc839699cd475057ad5204f908393e038660f57ddd991ef5816b98b1f9e24ac506a0ea25d3b059b94258dcc3364d68764128f115f141e3f2f649edc4e3cf6dee05d51c15524635442d7a1fb9a8924008fbeaacafc39020d63d2ec4b45807274cdb9bd4c32d47042c7ed25c30be2749ddd9724ce61054a08aa15c890c6fcd4589e4bb4c4dd0f74f49e477a46a87ae07c5b629ff51174b9add274d21ccf0a61349cab2a75a7d24ae683cf70599480a35f86d37b39e721f2bb784284170a6b44c2f051474a0e9f6f898aa9cffdc1b1cb79a366ec8b7f93c52b4f1b83dd5aaa115eb8d4ba91d7d48b61384d31bb038ab5368ac24d379d35af7208ee6ddc626c229587843537eb7b790f5a48df45bef89b3f5e7328809e9a5e7df8ea88e3c18f208618be80dc2587f9ba846ef8589595ac60cccaa79667c1fd18018d4603bda357a83cfcb96160ba5c51172c34fa70944a007e49a58e20c150cda5fcdb3db91ab29f207b4d1ef2e82fe71962f08f41e66f16744982c02ef1212158a32a9445f8a76d6c5eb6f46faedbe43bce8e55c3146f8efdeec44deaa81df815c24fe6b2c89605ca66faa31163888cc14a3cd10765178533030aeb4e8298849e0abdecff14320cf101b9d9d0537276b712ebeeda21064f98c8a3659cadf65e428d0293d9323621c94ecac4c285dba6a2a018b4aaa189aa58222757f70acc8b4b075a105100dc7a72f8665cf407f842726fd8adddb6ce0bc1f6ac92e1d2ab6f0cc9aa1a9e7cf445816d7fb9d0c83603538b9f522e9448bf9dcfbdefa87e24f842537dd1482f0860dd769833f74e5bce0718bdd4daf0ad3425d3b300b691264a2225c7ac3d9eefc5b5db9b7b9ec3008f930dd853284025a3df31abb3d2da81cfd96c7a89af2cdbc741313dac3761d9301b025440399abce9f9fb4cfd7f23ac6cf90406f8b683203018e0a979000fa79cc4ec8de68bb49a988837c90a1318c97468abd145122de0c9199996415e9599bb46a25228507c4c3ac0e7e05467cb8bc340f436918af3bd6a50ceffc1a619e2774415a1c3c410104f5c4417cfd6cfee06ae5c60052420a980f49e82c1103e7add655be56c394cc7217ea6d89a88d3e4ba78205af3ef76f03fb6321799fcc6032b02338b393d3ce3cc67a05e8ff2e63a6f00b91e73ee243bcb116435dff10a5b6cdd9bbb5963d192cc43085647a645412bea0a19422e71fa08fb6e56a6d061fa3f64cf60d301132fbd6e40e83dc5223e32617a6563dba3ef1cdc24ce5f7f717085edcd728ccf2c84120297f9258dd65c2910abf91485489d23e49958a052f469213504192b80967cdd0d3be7c047875f459ca73f4625e8f9b318a02922558d92256967df2dc406fac0d9e689ea0536bdf44547086af41b76d9daf19b5dd0fd88bbf476b3a967762b8dd994f5075d118d16b3198f99f3a9432dac8ee25e7d8abd39d4b6a47fb2f3f909271a82d580cfd6fe06331f16a261cf5f13491e8fec59158a96616caee933518ed447173fbbb4716de374a109f6e062eff132836db5379bf8d99d2b1987e93aad1c25a0f05bd105aafa85b3708da60b2538562834bd8b8d70bb82fb88b01e3845c2f86d99f4ae9b75d178742a956716fda5a7ff44ff6178250857912b56dff42aa156eb92b9c80e80ca4a6dc1393778ba36a82fe4d2586290f993ec3d25cba0993b8b0b4dcccbe08269508dc114c12c0988ac3a676c87cfd6a7302f93f60b0c91c8359c69d91367b192fbdb5582c4ffbc63ea36507d978111acd533068f8c5a11d59cbac90bc02a15d3073bb375b2bda457f678d927a24d25014a3e639ba5991118f778ca2015260f90ea7ce11d2b6d4baa97acc4d2d86d72b83a87a0f99bc7efd3966dbf5ec21db5127e149e167faab60391b95ccbc2d32b1327e66d651eae336711edb8f0ada6a6a40272fa0bf0e38e77bf580bb6287e6303af14a8d6551fd1bb936aa6789297996427279f6a33de59b74dbcb5ccfe08de9504d31c7632f28fc02cbdb93bc6e4d2f988eb98e017933917eefac9d3b2e589594e9b099d636cccf7c1e7e281eb00db7ddc7a064c6431b2438153e983f565ecff397bd73f54365a9c5352d9e3afd6c97e092774dba71b25d37e5c19eab42e43fad4038e47004eb58fb0e3f2151c3546769163a183f432238e62d05913d8aefc37bcff968e36693eaa0f9d1d3973683bae38e8e080e38f83dfeb4fbb79d8dc44fbb433a41197cb482233217d64b40a81305fc6d7d2120cebd7fa26983678ff9a5d70c1ea23d17cb4eae151599e427d2ff03a5bc5259907f76055e3791f7c120d0bd04dd89cfaced0c7284e6144af91daccc3030bca78023e82d8ec33f4ebc8a249fb720099ff0866044fe3e449b307da4b747ca9897a3a8f0576f0eaf473fa9b4855d21f9210bb6c13c7feebafde393d3e724cd2d73d0e978bae16a88a8a2c36f6838c50afdf044540c17b243a93cfbf621843a4bf1fde71a8c78261c92124eea7f93f9e0a1ccf486cd87bc953e4437353c6ede69571c4b9159fd455b9a8f248c9e929d2a63b4dbf972135ff068ffddaee5cc30b050fdbb7b0d768cdd1eff50dae32136cf2bb386ba229d2af87d3989dbc138793f10fd42c1c6e303457c3f437b2fead4d7318f5cdb592fddb7bbff46e26bdec706d77a85202f43ecdc082ad40eff349cab209edd5e4c1f34c3851b7ba9692f89ae25aa179c88db1d94907b34a51e98b45bc2afad8810c363b8a456fdd18141a1c48afa809278804a8226a7c5a6f3bb474bf0ed170f3525de3cc0bb5f336c7f0ead6dbb8a78ad842195887c43fa1ecd00134dafb63afd0a5fb907ca175316279192360b81ca37411f5b754fcc9b9e7d99db19accf1147fac622d5eddb5ee354894e04530d97e289e23a939a5f913015ee5b6c1d75d9d5f635467abc8bd697ceb0f7acf4a200839a8033d11a3b49faba8ac422a83d6190ff7cdd7899d758cf6d728fbbd1c58bd4c7b0759e2d6bc14ac4001b3c76de1018880a10df3d3ea17e486d199610bf9dc8fb010700ab049a845de329941c8a000fe9c1615ded35b537e62aa20b408cef63bfe10cd77aa2402185779139080b5e40955bcfaeb3160d241d0b86825b23c0b4eadb2f3ba850eadc5191cdebdc9aa47b64fd84968bac0fa913987ad66c4ce3af7082a6db07854f56a40a2b48cbae0fb82980970048723764473fcd88c4a4f059e9a53875945acd05f23e050555b827ca292933e9d3605e0f68431887455dff4e62666bea746f7c27d2cf2e29275e3289bba3b355e2f3a583d5c3922ede260a572afc4cd28a5d00e3f6e3bf0e637a8d15a687d3db61974465c0ab470c61c48e46c724e4671d6d62c7dd94f2115c0368c74e2517ba8a76775c28c123ab0366547225de7b81510641c96365499307e4e881a89d79a26170fee04618e6e8142c879a747dcc3db79f377770ffa5841820579b9d6b4be4e728cae0a79229a04574794c848035f61fc059426c3d6f004d1158782c5326c04facc07260e51a1c90c8f254dcaac26eb6dfab6aaa762954a304e161898922546012620d92a713224aa49310df84050554fb59fdadb28c51125d51c0f0059d588ec2dc6f56a98f64410e940e311ceffd5d45e2622e70fe617d979575dc4651425bef2ce7697f7a6990e5892c72a130c77e6c74f1e9f4e4212f6804a8aba0b768c5ca5ca37d527369f38738d108b32b8d5bc5a175a1eb949adb22272c6a0690ffb23b96a38b37bd6b339d33bf4c2e32162600914edba5183b6e7be26c9124c4ade951e3a6c957fbd5147f7abb5c349662f294978555ed91908a2354686d2b0d78e8a569efeb3f825a519f5400c2fb7d1e2a9e3660bf7bf08cb01145d068fd65c4800f98c03c1d43bac32e98bbc391a1495fef70150f1364912eb7d892b0253b2d695005a9ec169b9b8e13ad7427edb7524285a03695db96a0202c5cc1645ebf43e7defc743d27574c3b815eb6c5e872b6b3a8b97fd92d860ab3d5aa970dec0105750b9277b4c3e7c81d2583f3cd50d735ba7bb179bee6597f2051fe709ed2a84bee332ac9b5cd98575381afe0a02ff1c7c334e0a7b252a9787346d26aedc0473051a21759a311b56be28558a5896f5bc9917749d7f8ee499531342d8dd98b20e632ff25bd29092b48740249f45ec35b4c8abe7ee6cb301ca1d5d10961717e4081b9499026264facbe4679837951b2fe8bb5538d498e2fad072320c77e6b81593905918496076fc9a85d65f23619a12c06a854bc41b550ef1f42efa611a80d0d8bbf906c437c36851ead7c3136894bb7c0fead4b7df22959d63f23f5d07f50c3eac35b3148516775e9cfd2de678061a7cda0b3118314e17ba91e6dfff2caab58aa63bb3dc2c3e17273fa70d2ce5935325a3b67dc54106d177056cf9bb12d18e12447d1211c8eadd5cd09900b79fbecc8d47dff6cf77489350744079f41511c9e8c191da4e5b92af14c6830c9a69d6d6cc6cc184fdf7cd982e5e0a53e415270ac55a3e8062f3eaa69157af32512b6207610f2b46552ffdfb753fefc284adce7cf113c27f79b8845ee0492c54fddc7a37c3ed4602e1eff9e3f09effbab4537f8a2b5972c5abe57f808e8354033108697580d3245a887f3293b89600e7cf5c5942b3c61e264961bc6a14dacb9d033370533d84e7aa28ce6e30cfae08a8ef7682cf5f0c33f5f5794d452c8fe67df037dcaac1db924e0047dd15de76d6f9c43bb7da3e29a1c78de5608e03e2f76a2b8339fdb4160885324abe265b3df68fbd4699bb95b54212dcb3d9ec563a8464653d4f2ab4331fca1e60ae9deb9ae4aa9e979afe1f0f822c35d8a53ee7326139063731f96267560bd035267ece3b8b42cf45dd70e7b77be4b303740233d03fa51134648534509e2d1c21180a6b20111c2a61e275b8320779f1d343be543b022442629ea7b14f4f2d40f258fad5f8be8049f2812473aef3f9ae38444329951b81bdaebe6251d11468e778503eee3527e952395b3604457ed4bbe8e2110185c5224c717ac5da6b8aab44e289a3cd049e7fa67b91b57ad560d7900b90f783c08445fba7eb5c18e06a2c537c9f076c7038dacb8a0967f4924ed62f60f6c9a7e14db0e2e4e5ee1c5e30b92e3525d95b40c69a4d7bda7049d523ed350e7fbd7e93a77b6defd29d15f8c393381c0ceb9e2dab6f9351033d6d8ffbc62ad5858f60c8b6a610715e5f9927c2a1b926a166e976ebe490a030e81627d0a18f083febbc6fd4907996815c875a962130d6ea3913bbc271f67f0c36c8b8f68b83dc87d6e62a690acaff555bd1112cbae4fc52f3492fe1e7f14bb803c27eb0e110d187ab5f12810c4b9402a15b42127c118b7d377f87b86f0feb302459109f4c89f380bf7dd43805f34ac8d6e5dd37f49cdb116c25975d664c3f569f7a3d64704c2d4c525fd71df1d44bf9609bdd35b39426bd4e02133cd23d20d4c7f3044bd98dc3d17c815c567b3ae388724d2f3f2695cd3fd1630a2b16bde7b837cd9197af56c884b4089bd5bb0c50eb1ee8e4b09759a4ece31c78bff193e2b1529381bffba9c9ce0b43929bb8988af31b5f225c232379b410da701a42aa3440f290511fb2acff09d1800ff643d6c003e779bec86421471af618ab01d1700dc2b106796c178379ca6a8ca2ae9f9f58d0cfe1e745dc5adfef1b7cbf0d9fa1145457d1062d7ed96c173394b0185949dc0257aa2d8ccaec852e2d376217edeb0a2d89f25a972f065f44857730247cd5e3d4733d158fe3e9d2f8a18067cf23a67772f5ab45f793ea1aee3589de6e5c3a61a30d43fb253d71728b9e712a5d09ae0199c94f6cb28935fb6e5f7ef25e2be6a5e25d4599ff86615a40e4e63e5bd8b3477b9cd28e8f1a9b5ba6209251c45b0de1463e6f809ea8fdfc805654bae6fb9d74b6ce4517d094e346fdf6458aae64d8a64fcf16d79957e1cce3b0bcb5fb6eb8d4480b99d116569f25e4ded07206ea20364f3e86721a50f33ca42bbe5a2dc0f1ec0769582700b91f20aa6051ae7a6c93ba3f4b455903a780e0c911bc28946c27a6902b03dc2327da2705377fe91a064ca85451932dc1c47df0ede8eeae615f92169734efd7d41cd20c3e5c7476159ec523f5a8dfc94661738ea9658e215d45dc727767143ee18db956178e33436795559790a116c9b0d6107566a78d4a16acef7a134f90e6b345b0a3ce30eb7636ef646c5ccaed2593cd6857cc9c8d0c5a89867a92a863c46efd4920fe77d79d59b16ed257019155c92931f398c5a4a2401f711480e94c7bde0b3692f629e242822056b1231d5e7d49e52ad112bda7c2c5461fca4b43190f2614e931802cc5f938507f4fad8d6de3b089c8b7f43c4dc84988fdc7d0909f3b97b6648db809b7d297ed322c547f7e991f7ed62d581128efc1a98286500864714c4b7bb97bdc2df8b07eb1c1a5979256284161debbde313985a8b9c4aad310e563ea39e3d29193062d6e8224abcbeab943c16157fc9d14554fd23744cc4f257afc1bebf4c11078a5f32aacc2a2415bda6caf5ff8adde5ab731d739fe19c2ed521f1309e31d10cf2e5953c9fab944335a955335b465163509502bd7ba6bf65bc8c55091ca213c429c6b6f07a4767670df78e90edeb3768735a82dc4d1c0fb3e8797803635399d923c126a7b31ab7949e82321a07988a46e2c533cdddbc0cff21f912f59b57b5802811a5be8d8e3761b34c626f79bf833df28246ecdceb7c48dff71dc26e9574438ef67e9d56a68dac3b866c8d45fac1a37326a9bb31f8711b6dbd86096e0da343d342116b54a559b5b3b9cd349b923b7cb0a3d2b5183b9ba14fa5917d5a042f820c67e809df311b3f6751cfb66643209aed479d4636c667030fe328a613ac417700d9feca8dd275d8af6374aed4939fae68fb62b4ab440a533d3a45fb73bf8100fe23ffe6131471eef247aeae7c92936c4a26723c806dea967f02eb08609b6009aeb35b411fd8bc66d19b807a92a1e10cca6361648ef50f8a7c804f0548d4c46517c26a9a5faa833aa2fcf6457645755822b539621871efa5cefd064a67d018d074892530f9ec4078378c79b868ab1dce2f2d58d43e4b82b99cc70b33386364bbd9ffcb3863aa427ffad693e4083ee7b0d205aebb6473c81a1dd360844c9a2155f11180364c5991947de39210e6ea66be3a6fa46dfd23519c792b71f3db46b66477bb70a0b70581cb9834970b80fbf168ba476976f6c6b26a9ce13d1ec31534fcdc4afef787c5f26d4b528693703fd8427432dbd91722da6fa71b72ee4a827f7ccea7033baa2e0ed2721100856c19fb497b3af24d4aa96ab5f30f6ee9d0813bd81bd2100d3b4c5978cbab66871b9514050c7b7a7cf7af6e3a139376947d2d9bc9da1be8990b6326bed93f1fc79ebe7caff02852c519e1e9615afc3525c3f80205f9b6c8061ae8faa2c16763666b9c9b2046d3c11b42f1fb5db449020ab4b604dc11484c5733c4e6b0c7fd2e5e5773dedf5ac94b39af2282f54e6582b24291e3ad26c2831712c54f245bb45e73ad0576c75a6b7008e13f98b350259e09df3fdcd5875b528cd7e4bc3ccad76f51b3375d6473fae3a75dddc6915b732f4c4b0185b3d0489a9daa86479bd040b8bba84d8ab568af1077b0dbab32ed0b7053e657b96654489e49fec4d3f12d5a593536de239d0dc2fcd9a161ac3249fae53002f27ca7136d30c068af4664b70c092763d24f91082714b51d67c560226256561da8b2cf81606a3c171405fbdaa8923f34bd195ffd11c5a113898803c25b6a9dade97ca42abbe86868032cfa25b5755919c3f987ec02d252b8ad0aee07f889d2015f1246e70f71bbf95ef7739942e8e4eeef48295a74f9dd87540f2f59d69a8b7f6c0a8b13baedd9d44dc88fe6203979972d0833a1e63281714eeec7de01ee60b5a10419424e0c96c859b2812ab4c672276716df58d61d1bbe0a7210aea76fee91af64784abdce6b07698784b8f57d19ff2732030367f8039ec0ba21e749bbf30ded534e2bfd08032c64ee38cb779ced7a84890f103ecc949b8b6dc388b999b8d6b9cc9dac4f3b9b7b8a9584693d61b9150f8406be2d2a3efa8cfe8adbc90510e53b135be1db00f258030750c4fe673ab1d622d3e92f02d48b33c09d6cf9b45b8df061ddb613de5a4b49a1ebe8fcbc6d36c2ba486687eadce1f46c8f5cfa76e1c427ecc5d323c49013a2f63395ced73c4172ca1428567cb7a9ec8330c273c37db0cdf4898c6928352802736deeeed526d9ef078480f236c8d7bb8e48fa6a12d32a93374c2dc769d115c9836dec6554fb6e049980bc698f82d3a2fc18da81f5466aad52836152552ae5d095333ff367850dba2f35e8b7220139bd24ad30f081e756fc981961266fa2971f47df4f79fd9083559804bb673c1480a83e100cf157acd18730a5dd2ead23cf3a3aeecb935da51d8da8de94e02b927b18f27fdf6279ff8b22f6af12e8d703eb6e15e8783dc019e8cc1c52b1544db1fd0a432f6629957c7f76522df9e2179feb1433da9fab1e775f69eaa7bdc4624394711b8514fce0b382e791969fff8563e5127f4648a1c9ce5b07792507257e6943e34126f87f19bce08504b69d5ec2069c0c1e4ea73a4ee93439038551907faeb6f6de7f85273309e0b1bc4be04dcc8641d38450546b255d8973d8c1c93f4e97ea06b5c4a98523201c634a5c62f5acd9f02377ea55e13692f0cc5d6658530a695ba891f5b3fd70663215c843af3d6c07d1349290c7659590c704ce184a676809207d69480fdede4077ea681bb48f7d6d2567d2dc472c11f475ce42e8371e10d060e530e8c5212be69271c977c314192229e391fa8ad3135374c14b0d6c9b1fc936efbd04abfa05bf69a1629a8989493f60cbad2e8404d8396591b98b9f1c763692b8077bbef06e0ac652189f3a654adc2818b99bac2f63681587e4da97925733212327c32da3bfc23c21cdfac2885425372b8006ca1b8a0fe5f8919a54f86829755284b1e20e86b4fb42370e5d3f60747ea4672b91ae6a94ff3f2cb685cc89c14bf088bf65ec57709aff4d671046259d65b02e48d1fe5279fbb7d971d5a7e1bd4fb4b5d55694755f4c379eaa410553db4d094483a088347ae2516428b0f378c4c76803d63fc5aa15d8dff77821e19a54b6e34402b206899d6bb57fef81bc9027c53dffc94f20be9f22ae1444a88f84d7b90ea4bc00c403e9e2005791983883a431565daa596024718294a760cb9c10e3cd09be997da13fee7cf902530cc89a933446fc720d1ba62f12ac0ce84a77cabbf06941f22adeb912c7be61e3310f30f3ba545dff4d130b39b15ed92ec31a8c4f04268b56043546a3f4b940c94ea79830b3b01a46902ea5c4e7ac9c7e51bf2fc32d11cf052e374b2e74e5f1c7d512533d0cf2317392de9d24fe261d917167e8e3acd7a01cba8d2ec2a45d27d8023346fda8329a26a6d70a08ba8cbf802420cee3fe727146df32744d168635801d557f52f0decb2ef2faa5ccb4bc973774bfd39eee9733a41c334d0694f42ae8a2d4607c9bf5811aaa47c1fe30e30df4ff1d105c7f4976fa054c0241a38f4a284b133d6bc63894391ab42959892b2e7b843473265d37818d2cd4da40da75c9523548bf573ec5a64b4f2e919cf6595625159a93e973b00b9eb4d07c685c6b0309c41ac823ddf137cf6650d472bd2b1310d122b52011eb4843a2d55993a631baea975fb4e4fe433eb34afe0275dae45826757ca7cbec597c091639d4afbfc457d58a136fdd99cee1c65ace61eb5d9d92c53e5df5ce878e428e851736a2568b256e8d4e84cb3c2003087c64a181f8a8e4b9e0f1a43860f6ff005077a0d5ace0c409dcc852f54ef24c3bc05f74ee216359eadbb519345f1f51982391ecf58169fb7c56d7c2d8201e103926da0cfe639cf590698a66a8d4b979c2f9551739ad488128ab291f5f8ee4fe7eea9d181e3b5bcc16cb61b2b96cc5a77e0141eade78081197f0c680418bc8aca0bc918f36d68d90975e12b97f0f44e5719abb6a6e9abeba5ef6c9d998a69ea12cf010ee847bf636bce5df5d4bee1696396231529647a4eb3293ec14981c6ec7af3f716566b60414da65a785b51b9986dc4a5c502bb8390fb3b059be3b447cb6e798a0b62014609485f48d133bffcff09291bbb741d124d8bbcf45a4034fec13c0295ff4cfa7b4004c398c66d177357d741a65a1701bd1fc11f29702b9bce7a188be4cd93e639d78e7f66454a091b005e7efc092ad817a0af0c592996e3628f66687f698baa3fdb4f7690c3b0f334f22c4c56630361b6530affda79add623752b950c5641dd54eb8e0b0d341ce0195330d9977dd43edfaecfbd5e40e2f4a50bc28772c6e2133e0b22cb93660b61ffadf15b898203c9e58c2ad8c33f8eba9724c17264247b6b04daf9741189db283b9ac8ecd8f0276b8de89e74e94e698b332afbb772782c6de5b20878f4e25858e9787a8cb5ebd9cbeea8845228c46d03b3fdc517722cbbf580f920cd3b2d6b96392aa596ca6eb7d334cf5f6a7bd84d4e571ca1f081033d58cce0a44d273734db59cba94ba5169b25eac4e4b93bcbd41e606d76c15435f3fc3f09560ee6201d7d821fe913813f07d49f1364ce1015307a44c163da7ed49f89f10417b94ba1bc6253be547ebefc29b886916cda0a42c08b1d99bea29c8c1c8d40d6aaf242cf36e6c20da07f3785eb6e6f104e95009bfc12922522ec9ff254ee0590b95e30989627adf9ae88f665c8e0247f2bdf104a375bf78fce2159d1a7cf36c9fe46ed8d9f2b3cae80a875f7f7ec143fdc4f22b9745f7715c79d939dcc0cc0deab18575f820f9c83b7ba7f15de13e0caafacd88352050262061fb10083574000aa5a5bd4019b73e01ec000086b01e264ea9b72146d91557f72952dad0c0077744a578283fdec1d364a3c7b4312f59a1b3800b17469abe0c0d8652b778117144c6cd92055f8152199694d49a393d2722ae1f0d791f6f8ec52d83c68dc6200afa1653bf507cfc0f73d4d81405f564f2a9a2c1f3d7a739fcf9a8da719056c65d9b203f17db9bdfdc7de8693601afdddb26caddbcac37a0963dbf0d79ede1c6ac116a7a6b53644a9f8f1f0a2f8270b2043a543454d3eb0c159384b4cd32de1fcb706fae08c3f5a519a16d13da4ff882a9ddb492bc429ca21fa9e470f283502e99ce5b7045f3e4cf74cb7f147237e59c68f1522f939e0e918e1967d0202fa861966dbd8b9b0f9453c5d52e56e4599ea733b1264aeb62f6231b23bea3250b061c5964ed67f2d4168a48d1b1fcd7b3c683cfc01edd2d5f5ac6161b122ca7d7aa5adc7311158f82b5e57292e247a340ebbcfa2293203b1f600036b9eff32706096aa3442de0fc7eca5e5fd93367f4f1a7664450040645ede7e897faa08bb967c1ca5e472a1aeb61d70d97bdc42639bfad2aadb842a1098a7014a7ecbb69c593bc104d249c1805770f657c56f2f11f93873e5b325dc7efdad2aa9bdcc0d569de38f8814634c8bbf388f308b298c47c37524f03b580f9066a69a3da9c14ff92834bfe0a11ea05293fdb43b6877d063f74c7f49d01a1f4bf74bb574e7a7f25ea8d3532670eff996c9ee54bef310cc3de1eec8050aa370d1599e83fa68dfd17d8ef506c434b86c0c1fe21deeb2106934232dc43ee1061afde819d15898814d33ba968c04ad7e5a7878611d07793696b00663d32397e0d0aefff9e61af3369e6fb8cd608d5ea36bea6236ac29e9e6546010a02367f58ecac89df6ef9677eb68b96177e8ebc3cd9ff6e8384e9e35f526a8f94a26876967a2c612d341aeddd01f4320a0e25c46c93c66ea67da6232ec783ce38a76b768e4e406fc4033188670e1e33d0bf0ed18ff34f223f08ef6ff6f7c40d77130a41452b544b9651e62c7f5c1e11b10e7e71b4fa5e92366aa85ed9fd7b670dfcad6472f6585b9cfcc4d55b12f14c04f4987d3dd871116218ff966b0b2525c26a1b1565d3bd9822c21a8352a15444605605b0a0f88cf664a0d0b58e45ed1f456d136af6484d15b5635e4d2e96186f8ae07bb2bebb20b36a48f349fe4c47852dd8f514b5dcd1ab44e174f51f941c0fd1b6d6f0d970e2de117c404ad8850f29f755f98438fa342c328ed72dca973ac6886bd173386190771d40bdbfc7f25268949dc875a8f7f0c1633019a05d1211696471891e829a94ab23da7bb9cfd5461d03550462e2c1aa5c364c3fc50834b9e70fb7861d8a560a39b9359731e93114e13caec08362886fc1d41846169ed7e6aa946fc3bf6c227bd1b26062cfdb794a2388b619c9df1e17b989ef8e5c739dc1283ddf787043d929eb407b5c1eac9938a7e7b6b1dbdb8ec047d04249f8dffd6312b6167cdb0d5370488d619045201e6c178b0743c5f236114ef0750e938df2ea7ab3c4f07b3e4f61c2fec0d37a5d25364d47673794326b08f635164ec432053f5915a465ee4f2a25bcb217c739e9d0cb1aa7206f20fc479d0bf2e48bf59cecc6304662ce68719b0785dc1198944f94392c006a00672280e876b954887bf3c4d8978b8ffbbd4a7de4f51d18893974fc85a39316811697ca50174e4bcd47d5bf345aa312ea2a474b58a5100ac92a59191751a80df73c80d4f006aa38ca8def6c90f314424307eb6ed4a88e536a45b3552ddf2ed13d09a0505bfaea96aa961a835c1bc064ac1770058bc913814167f044127cbd70be127069169e810a9110870a5294afd7017fee6e88be5c4a468c0a3b1fd89a5b419b6e27ca19f9d2bfad4633b767dfb8ee42e434db032bc42017fee6414dfd07b4b84f7fb4df92d481b77f45ac84e56437e3547c4c4724695dbe35affc16511668cbfd8835b68329cd83233d8691f2d35a0d3bd688e9dfb66b5db91a64de8237bd41cb1a666433e0c8a542d58b2c5b6689a4374d78784236a7ee41365c827ef45f2d40f056bfd09e9ce26cbb1803772f366b562217f8ba99e5a7a11a18ed51d3059cf715f7e1483b8ef77d11684f8842eeb0a8b6705646f7c35fc36720c22a9957ab4dbd2d8485a75e086989de62825d138143cd28561bb6f44df789378ac257cda5720cd2b3f0f14d7ac1e5969ff7a39ed5b0f18824700c35dde1f0b706f0d941daceebe9cd374978b138cd971eb773e8a018fa97c3e2ec960988884b588e5a1131248493f1d1aff4e7c262ed3854bdad8352155dba0c1e7bafa7c50e7d8f2ceabf334e95dff35041d623a855591dc7f7056a3228ee9ece6dd1c817b77cb89f12e9dcfc03df602dcb95353ae3326e200f52670c7e36283e42171d13d7b1059ccdd9fa8721afa5927b95b68399fb00cef03708d9b4182b62e76bce85792a3a031e28781847f454638ced36f1a0d2c532178fd35130fb665d5c861de4f08a4f144bf0a22689054a501a50ab76d7199510cbc618c392d2171854b20a84cf2612e4e67e352d9cc8f394e3566a0ea23ed6938b28ede58ef2c4636b38059e6dbd16c4f50d331e848423dc7ce74123f791890a6a2a7654a8acd1524da467d83243750585479e7d97981b55fbee8a8bfd2cfa1a8b3451d7b6a649918cd4d655bbaee8527925cf3d1d2288996f9090e78bb50919af0cc1e38c557f275824a427201fd8adbe4ceca5ee9a63a549d4d74369de352929b4bd61738033f1264e02dbb2ce7f9485e2d344fcb6eb913d73f50aa69df8e815a72c371d6d416a03407b5e835fa0a167dc743dc876453a02fa95d142870837dc02f33245b571c998760a8077e69ca52d91b05fb3785e09ae4770ed9adf1d57e7cfdf5a7da8c92b252b888c5afe53ea8adf2570876fbbc0c9322d01257db0be81472e803a98a07a9a850242c0cd793fa7d2c5ce8a77c05b5a5c0f19e6329b66093b8fb2466d0bce2f6fa58d0b591734840f806a17d51264fa5aa9325fa36809f2eb97c04a738d2e4d40f33a3c9eb69a470a683e101133d0f5a0891e06f6cae815570541f5d6e22fb44422c3d4da41f9f98724d8edc70278197c78a1a2ba30a9385e201d5ccd97eafe3f04ef7481d8e85fff79da02401cfabb181751e8164192ddaaf75edb6906807db646bf620e0ed6cb6f3d28e8176ee8810a8d0ca085f569797a415f94524994b22a5c58d7cd25db81a84fc2851d26fb8a9de8ea651ed1e6cefbaddbcfba3a2d78e4fbeb3a10f7660229ff77b5c4dcd89ef292088be0cb6feefa64a17c82cec1772a7d143717cea80ca3edc31ed153946fb0fbbc89c737803d021e536a8f5b5e8c360b8d95ae4b70e167a7f367b3ec1921362e9f730e3ae56e6860b73fce4496cd2854d2703456544cfbd07373b04801bb3e99c23f9e8b3e2fe631963d1ff2a349b888f415cb2035592dc34f8e6197b1eae6b0521e8cf1adc00317fa57db34d18f2c5f2e2f0a9a764a678fb2f6fbcf6ca2e8e4ff8c2938d8381ecd3436db599b00e7b4314236a35dbcb8b912b9df6822ac09512073bb689f93d5bb069bc4211234a32fcba7e0fc704663b64d8227676efbbc394251d71478f06240171c276e11488c2de9a462bcca6c08cdf0e651ac03c65ff91a88c825984fc162decdb6bded9746da3e836c48879e6d4b96a6ae548eef092e9749649fa258f7d5d6eaa78a08921127cb8dfc22e10b2e67f0754a674cae27097fed0014646e09f67a0bcb2ff5caf174e635cd47162e7b82ecc533d9255d3cf15b2584e6b99546eb626ff7f340e1e92ebc9b409f601fcb730cc6a259b445591cbc3b2f4cd47df77019935e00998873ba3e0ec5727481b0f9c5108eeec53f228a75daa2fda056ebdc343759f7e61569dccd6d92bd5aaddc64cc02bfdb05d3de60538f2aa01b25de3ff2e11c58ed930868790dfa1f9e7d9142e880047578a9c83bf5a2ff02b40473d0f649c57f6e3c659ca68a4f22d235c36b647c97e7a8262852da03bbf98c4bc82832ecfcefaf9a0f977fd689c3bcd1dc8c21f5cacf7817e51d66c86aace53d28672e3a7fb39f318d48f020520a99a9f9260613ea72e05d836c95c500cd216307d857f6c060abbb85d3ba42ea0e153e3aeb8bc1d847d1f95c055057261f28b1b005a67681c36bdebc3ee9ba2f1bfb874fb64bb5b514eb0cf4957fcb847037102641ffb37185f2347a34efda8ab0e5af86d5ce9731865e04596fa0be0fc3e574e246964f0d6f10607dffc1f3da32d1c845f4bc8bca884fd3dd7ea87f925302a6b44b7e232f9550a48ee52945bb87f290b5ed3386d168d4019af7b8785788ad9349f88da70bbcaf77a6f66b435c78e90fc4bd6331ef6d13776afc0b281d7d968e98c9e6b5179563c4693eb172c1ab0dd85e78edef2fdaa1f6618b6ea2fd7def00bbd92c9ba1f205e277a95ba0b07aea27dd932fced13ab908a09d8649798fe7d15f72562019c0686e6283d456657a44f4b4972af4497e61a3a756c0a92cfce7c92ad6240f3caaa1c11358959e961af0301fc4c33a9f7ec604cb2ac12c66c12da6bac31c473be0be7b1a0542842c0f06afc8572b558fb8f5c8516d9b0634a8b8199050a207d804b19fcb1aef232438dce0bba97b154a61f7d0ad9d600fd336bb19e5f90226f10292a71246ad6f7a904d1a883dc5c9cce3d163b305a0a5176e5ab73fa338fb848521e51e83059a6b8ba1fcc14f3f9ebad93444bc58c232540e31d6aaab84d9c93139759ca09303654a127fc058de2fbde7316a8deacc4f75ef3f0d48161b58cca6f1ed09bf0b78a6f55e487134d6e4b0f6bc017aac71c8493bb64ccee70574d6c908e3e74abfc82e7d1d1c38e868df781cc3828cc10ced0ceff1d9b999cb621b253a3a611d08974edd0caf4f89dfcd30d69b740d451994c4e2439335263e847cde617e9cbab3b0e1ca59dce6c5c00c53d07954bd2043275f41e916c90c2843e65e8c490d84b950d834d64c3278b0415c0e17af828d232b6fd22db1ec059dde0e7fea6236068fe407f1036c61f8f119ca4975c26c50ef10abc64eff3e537d09447dcc0834406a1225db0fcc290281624f6f2c2aecc45cc6a4c3059183b406015437eeb7968452fc2f658b745e0b4c42b2f205febd987957ae0c9274bf99409e72f18eb33eee9c05fd9119bb23ce1512c0b76f7bfd667b5826368cef5bdf31cacfa2b953402238760e1714277e9f318b52edb99b29f32010e364c9b75625971f6e3c763a7e54cc0dff0f418f0cefbc08160c7828eb9ac9fcb726ea87c4afe6f5d28ed6dd878f68d7d86039e94821315ad52063550dc53aa022fd44cb5dd22b3a728e0f0e8df390d53170afbac7104eec53c84e12220aa9a6eb1bd4145353ad9bce3ea026841443dd4fa3310624e91ee231c596249b8503e38b281eeae0b30c5d3641e5c10ae9b84aadcbba151666368a8b66b7b5a4ec3cf39231edef7204dfcc76acfcb6b677b745064bc18daee54346b76d0329ec76983bb1df773ce22209ebd17e84b6bd98e6757e8d7a007706cd8ad120557004fe9162f4c2088d82fcee6187b6a2910a3a923c9b1151b21bbe78008ccb670d127b7bfd58ed1819cbcf4a2ff1eb538109807074c407ad5f196ac493ab63b51ac2bee8ddd2bacaa8a4c980eadcb9c9c3be0493baff8c1afd802877aaabdfc4a646acec23dddde8bb7dd1bf0d95b1444deaf11c6d4d6017aafb8a11f8cbc014e50ec28a4d16a2b83b52cdf00b1d048e6335b0bd866ce640ebba1d97d7d39fe180e2ad3ebfaea3dec9de816e73bc7e7ceb5d1a579f602b8c202fdc9e97af249b15cb612a1c68995676b66421a9d726b61588a2d8be65cf18c058826b62e7edb2b8b4c99ffcb018d03d52cdd5fa3326af68d0cfcbfcb8cea7d5d1de5946b639bee23d34e8abaac730a67e62e216233241051e35bc04b81ebe8204ea0629a5f675802e350d1cea23b97a3ba2f29bc9e978aed99163398b23a900e771116aebc77b95d6462c7e66213d51171441565dfbbcc28c24e8f343fb965dd727cc2c89e7e8202df1fee944dcd5476ee63ba4e77e5d0e0c028577f2c926f374c58c23f434c6260bc3c45c5c3c104d233963d3564b71ea39b0596b5f4fa321fec0179d6bf7de30f301f8515b95d9482d827d608a895dbc3620246477ca126b50722e6b627e6fc058a9038a3712e97a6e3a632b0b07318c8426c0342c87cceb8fb19e4235046598fdf0f4a264e79a1c3b5c5384f017c38c21d76fa54c5e9207d2a260685fe89a562c1b68d53a560d280c390a37b91f2832218ac2a24e88ae7ff3f7cc6ba844a2873c18118cc0a33b225a59de372b2adccd6ae05943ec5390642a759ca18f593d91b20c7fd1b726394dbca392d98ff9ae5e1f5380247ab3af349389fd831eefc24392d6784f3114f9f34ed774eff97eeb7048eabcb1a0888c11384709b6de1043ae2b84f59882481d3ff22779f6061ce3923b61100db08c9486b61e35bee395deef44d13849c767bf01827a6ac4a193a198d5a18aa362e8a6ce9d4520c687704fade2f73fa2655d54c5f4c58efef616667c2ed868a2822b89f6724fe1ad78852cfd15903603b53dc102e34a799d1962543cde2e1bfc39e50bcf1f3b1d4de89d8b96d3a35474573be4aaf0bdfe05e7754917bfa118e9b10ca02450758d12a5cf229ecb16ed4240e52dff3d8418fb2a36e16a70e26caa8f2c541c81416110841301c5e48a755a3e8feee949fd3730def136c3b09cd801174daf318c190b3ab10b140b2c9e4c5de353d183cf35eed0aa6d31f2d8994a69fe757761b05ab099877d7c9f55967b5cda22a292a6fc0ba9b2cf45610ac3ada6c1adf2e2bbb3dd10aecb575623ea780a82a4ecf1e619e01cdb132918afe26f7ebd910aaed7511f3cd7b75af3edef1ed69805516fc0df16ad6e1877e5dbec7276c49d41549bd0a3df2936de31d840777acc9d0c0ae25ac8dd0013f94fe44d36849ca359cc0085453a62a6432b8a08b0b26743d6c54463f6a50d8ba1fc4503ed683283cc220c0f1ab5276a4657dc3a7ed0831ccce97ffb1e4d689acdcc6a4de605e7e8de80dd12c3d6cb59f318a842b3b2555b4f7348d0a08ae7dc4d8ae68b41a35cf39d0b657dbe5fbdf47fbc89a025a5381aabcba4114f8b18fc2c651f61b38e62287285647d38b3fc0c2bd732eb607f61102509d92645c7dd5fd65f746e3cc2354831cb1708152dffc9ff916a822a00548a9b8a517bc31c879e708772d71e28a8dc5daa5f8ac26c18c9aa3dd7c4d7fdc8ffbea67ec3f01d6a0aa5d1be5fb24f90ecde806c3ce1cba89720cd344608bb2114e78c7712ff665a65f3396eb8813833cbb421092b9a6ff13fc4bff6f7b1ece05b028065cad3d6df69c80f2b19e554371d8f1f1de657fffa8a84dde6fcb311c18705e6b81d77542439c4aa2b70afed8ba94764f0df6194c318e535b5d9a713dec99ee92590f6faf7d00da686bed8744dd23babc94c30b51f295764d8090001a6f0627fdf304c838b2c1464b2015bc4a1f37995606074471aba5c97064c7945799ca3d246eb1253b2be2f988ec1f1ca60b77027ddf71c9fa9a35045a4430a2193b57f8157cd8c20f3a5e8c77c65b46d367d2be965ed6355cc3cd9160e4efa2219603b60be71c837bc1f049916425d270c510c68cc60c27c5cb6200b4c0f06bc56d0301e8eaaf4d8e4bf357174ce8d8cc2a899b016f742fdbf8b67e6695b149f74adbd98651549dddb83a6f2d488f366617e4e5dc618c7d39cb675eacaebc9f7dc0ef4bdf40c86c0e5184ce87e947c5483320ce67887c1d0db758b4f1e0aa17d9c1938f9ff9315e7f5060a9bbe0dc26cfaf0d8afc5903a26a9410fe410b86c35eb61e8901ff0060570d23afac125d53368d1503bb8bcdd2693403ee2840d9ff7f73561896b4186e6e77567fe61ea31f07c57d4825d3825bfdcbd79ecb4b246f075f7df80d816b66ed741f3abec71e7627ec64b6091d0574c803c47f9335d597ebae0d15c5a7d078cef8d12a42ddd9bff4ac9812bc1ec03109206f0d3002b1e833ba087b37d3ed99ccc141109d1c6114a27051544fc25733cd71e64adad16fff01e14ba960f0be132dcfe4733994f450eac6ecad6aa9c176a13d49f7f955c3b90d6e3c77dd1ee69dcb112131d81cfedd4a629b927baf828a38f5312f2d61dfdada67a63ce07e1c78a00d900c5d41333b29209ec71fcdf1af95763284098ed9878d80d004f860bd3c3f0e82a028090785babb0b6b23e5e24ea4f186390b5a2e1644238e2b276a6b9bde959eca2db1f5ebc0c633c600b94ee3d997ccce0deea7d230e76f2cd831784fb13a3eeb51bd54140cba646233de4f942592d9febef9993deebc1a9a43f525ba575b92e0a39cbf1ee3eb292eec08bf4674a749bb14f095ed90bd5c4ef45fb9ba23113251cf0f10261869918420950262af095ad1564d898864fc7d2016fa5d62a2badaf3626931784b7af5f086225350e5b5385f19cdefaa40c3ce7737376fc7486a55532d707ae24ce7cb692d6b85f4c24e4913c092873636488b1e782ab316abe3eec161c42b54ea6867a0b0f9bf7ec66a37353d938c15bbc88b622eade790a0249d146e8f886f6f33b00f4ff36b24c00cac68ce0aa73de3220afbfde03b1e2e71857bec77f161328ac7a28b9ea22095c3a845472c6389304e1c0f9e51e7ae05b4b31deff1756285a72ff159d95e5b2c112a163d44107221aa4ed5ce6ada93e7d68b655e4444122bffd20d9992a20701c9f59b287ebe3e5e4c56cf7bafd23aee3596a121815320970328b1e46a67424ac7dfd5140d46ecb23fceba05bb08ab0c3cb477806f391459e363a62b3f197da76777d1524d3e243b3f029a594690a90ac13bd8d81bbaa8488d8b314527c4d7d53c95b7c4a8a0cc5fd2318abc2ffbfa44c5801f4ec95f3239cb7ef53d30dbd7e3f5f6d17fc2ae790526d7af72ed2c24c0ab181e3a09bf24277b379742531ffa6bce0c7c324c06a5cd63526cc6d0e570cb9b05926e1414825dc6d1f3bd727c32ed571031ee9f4d925c8c10d2f9fbade8bf708c09b4b183b053c4cc3d8a7fb4f96e153776d72b238080946f0dd7a359829468fc3818cd768a42c901c45223c7d902b7a863519396dae976c1c7c8d08e207c510686a2ee81c9ac01eb1feddf2fca5213670f8aeb2c23a73e571fb1ebf5cec409c19161eabfaa6dd4f78bed1e086272d51db75d099069cfcd3ac7f6c9fd5debcf6942b31fe4dfb39c2d3d146b3a55e3331ffb0513929de5b1e0db45136723928419a854e1055718daf4cd868ab2bbac2a63f715d362d8bbf0137d2ed2a1ce87e9e29f496fd69b714c0fe1d9fe8f1a3255e397eb3fd2480ef72b89a9a314e0f2713c5b363f70baec0b7acec6538c69fabbf9f1f17381d5fb2a8cdcf106f728d6b7a55167907b4992573b8040352706a40724f4c2b49f664861670d7195f8d8f8d11c6a095f693b2694656b3c8a7d9d59f5f98646369fdd8cacb7273bb18a28be5864fd52760c8b618e52878fc345708f57dbe12b65487945385df944312bc56645afafebf774f3a998bed6af724ad16ebcff346147293d33280e7537050ad325522b5931f52c976de68370e857cfde2667b973e3fc31631275b5cdea50ace8d2869b66992c4746fc2bb724b4239a4ccdb93d57ad55d457ed78eac0cfb5e664d693e3ae22c9d592cf424148dad67e426491a53db2e30baa18ac6ea7ec007a948a4304208483bb602e721bdd7a359ce3c03e6f97fdb83bf33916114035b9a2df92cb062d6b4cec723038c6aa6349b741c6031b7c230d2e81acc905382a5b37e65944c30a2c6abb101c38ebba7c8786ae29b080ccd15ae4a794bde563db6d0b0c33b80a5b2f35f4f2e6c5eddd29d5f03389742d75225bec0347b7e24b1c63a2c4fee4ea18a2955f2a2e5722f539ded255f039cb04602ff63be3694dd458f087eaa44f67314ab7e16084577f7e1a746925325bb962cea0c2fcaee2f48f3c6e58b581b5e65d5483b9d8d5d61aec1eb143bc65b5065480dfcd31b40e4b8b5958285635b813b4e29eb2ee30bf2329a17e9685f2ea75d341de203a2f491da5a806d25a410f7d8a0ad563e9bae17725b88156d2f8333b79d2b331d732f86a6fc304f0de342fed03479d94ab1809ca362c5c83b5daf5c9e3281ba2470a6c1662cd34a86abda2e6483ce0d71ee362c729cdc0a6e1e07953ab499352a01513ed192edf5ee29017f75d0554578838f8f10118e9bc31e6a7b444eaff65546cb5408da8c0d0d6ce0e7040230d092e929d07ee12dccad49def27a8101bda4f9cb61634be4a40297895ceeb0996da86da80f95d8aae7a8da0114bdca4ae4726914557813127ad589c96dbc2489840ef6a4c1f37a346a09669c9bd6ddc16c8a0ee0536ea26281bc8599a83af31665d8784d2027dcb0544e0e8814a8789f7864c82bcdf78972600cd646cc1e568640e8e5f956058413ec2a1372636dc6ddbb47cc4eadcae24ad39fd5193a2eb0cb27534b4f9f5acff4f407c8e7c418ca04873ca87d6d0d035466814d0f9acaffaf4f785ee316cca1f73a5edb61b1aef4f7de845b4e60ee99d38bf47e9469458893c306220518fc4224f1c73f6645187aed974815a8cc2d449936e783eeeeaf53dad3bd29ee1850122bd4cf162390e03959de46cc9660bfb3b757a4ad73f2ca2fa66d869c58d0bb5d7be5cdaf87077e47dede8eb7401f04f044004577b84a50ff5b49910864b0d107c84ae274a5da635a06917dcbc1eed033db6ecc7f5637343ab817880cb4ad8f325c5f51c264009d155e36df56adc1a8026e98d30b30c60bb0604c85aa8a07cc1407a30a41ed785f12f773942f3042955bee1d7267a23a5224da43d3139749604b2751695772cb9340f761ba7aedb1a237a04595362fc8469bfd8a47894537048fbf2e0d7e46771883f410d29e5081db040935987c87302f9d3cfcf4841b08cc39fabf48605dbcb89c10c30836583299165c9064e8eae440b25516a817b63fb1f7c59b7400987d56e8f8de0882da9ba471b6b7df4e938260b7bc223fa83df7a1ef6a31feeb1c3f292a215bbab0e9e926781f0e6c2b48f1588d3b3c1344b898698020a7cec6414a159a2b6e1b0c0f0dd1fe6f1fc4ce93c6952c48f6666268a76152d7e73415e48b50a05186a59e8b648faafd44b880510371dedcba45b9f2ff84fee52b74c7660980388d7816f3151abbe5848906ea335f47dfdb98b1e0e35f665f53c17b7908489af90194af21ee965d45165882e685b8cd44f72bea18f0ec4db0955e0ee6184d3be64afd2030cc284525e0ac02b6b0818f95abe26c4acc2e4ac1af81db2d3ddb03736a43243701d291546506703a142cd7053cd98cfd6d3b29696575dad289af723fefaa572773da9c709dcb85e907bc0722f49bd92f3ed8fe05065afd182a5a4f3f9945b44371ebe82b07fc32e0b42f84d176f58d3ef283e7dba79926f3051c2f8be56dac0f8db6fb96d2cc330145c428d399a2af0f6e83cf184b2068875c4701be7d95dc78696daa24cc6aac8081e72c88fbd8296ad22ca302af1ef05f37effcf66e3ff9df0bfd1f1b84686b68720910d371d5a0a515c727d8b1db591c8daa2dc3a5d823e1038691d491f226a943fc718f5a2b5c9700c4c4db7a00110b849e6843f046459a58f8c1da24f21f0908d5ec2a123bdf71ae2a856563c425d8a412a40598adfd3271082e16291e035e2d685b1de42ac453305cf72186c3d0cb4a4712de474dca21591f72b0134687c5350a4ba656c9d632a20f799b1437b76d245485b9d7c880654f6521f515f6222353a77c4c6f4f58bf95142a1b716338d3014e8fbd9de95073af78723401f614eec40a9fcda08470d65f1d17bb403a6d2cf5cba9992e24412aa35da2037beb907485b426b2da8e433ac6f95deea3e032f80ac9c086392ba59ee877b0717cad9f40fd4aab13e377a8843ce81772108bf9ac3f4a7b842ffe0137760b3238d9f3070fc7976ad2a31dc3b6c12eb3e5da0fbcc8ace14abc7473b08209155a5a51a577574db40b216b350001581f342a710a8308b35289b56565a81048a62a814569d1a6af11405925bb512b21424c8ebae857544f4cc93df72d65d2e61bf45707174091da0181faf806c42cac8f11c7aeedd8a25cd35e1ed01d9d431b26dc44104d38a37bef9701c51059fd2243becc2573ebbbf8389060bd8bc442f6c71e44d2d39ba05d14d56800e2a8672bc733458499fba0591b534cce32cffb25ba56e88eaf52635d06ea20d60752d4f8edfd5178eff13734c6bd9eb822f6d3c28a69caa33270ef846096bba81c2ea4f3f223427fa9696459e1944452d9dc930ed7d02192a852ad9d7f627dc33622efc59c5c72a3dbc26989f508c746b84d8d6a36ec90f743a6206e0375d88c8e44953a9392aadd56092f52422ec11017ad83013727025a190d8c63d7585036ed23be3f5e85f2900fe557af30c0f44eb8284417e813ccd6697ba5fc10ce64b89447df7cc0b8d45300c4c9822bc3cc9e82f82be3f68207c380adec5977fc105184a24124e82de6016ed263c6603e3bc4d1cb6acee6af8cb5e0fa4efd729126484ceb123e49900a66dc27a9b31bd9a2686a2c33cf7cebffe7af3cf194ab3c0fa21106888b9cbd36517a8ac703023fd9eaedf7a3a3ba249dd96e709c58f3b03e5889d66f9ddf14fc60056a1c789087dfdec9b2cb8cc664d29eaab3aba8f863f9408b9426d1f77a51af05aa7d40c0c1b8a4c47ecbef1389eff1a2138f104637f9519e5c33bdece3c7d8906090aa2fda363c9cd56065660c9bed08a5dcd5529d6ede95c7ba1e776174106ae8d04c39d958e2a846a7b3cfd63c8c5a433dcf690bbfee3b98e0980487c9559cb76cbc523333319736462af5c0721b2a184c98b6fda943cf8eddaac59b987ac5fa7d008485da644049d869212d54fcec1f0d4167972aa3a3c9e510abf3f70c15f64784549358c30ab4194d8882bf7077f19e1f28dc2cba2f391134f92074e130c4091a7c49efd871bc37c0f6d93c17f55c685bbf65a554b0d867e173115ffbc091dbf4a4e5bb9a081b44fa67d684b536ee943ddc54b9de9fe76aba6b5e5bdc3d5ff808052774e58e1bfcb80a7fc9737514089a85b62fa46a57c46791b72077524683e1f4997bd5ab31962f5d34b4355376ddaca8357971c99154133c0fef174c7af062579d5e6f2d9c7ab1b507db8fa727a213baaba8f82f3f558013b5923264877be0f7468ae418238ff1eb5537efbc425acb2a580646b132c1a125502b2f18ceded715497ec4c08dc75b3d620e63ba5b0bcb11490bb32167229a5b80a45ee57a4b439f6e7b0299b412eeeb99531b90a2f62729117198ee439e2b133a910617ee70df4b4050311644202899210fc357d190bfa9cfa273261419a6738efdb1ac00964c1c29070b0fd3df1a77aff5650ddf6f81e70321104a711529fb03a50128dd7249a78a37cc88863f3cfe3fcfe22f1685ebc26582fdcf0cba5d012ae90293ad050dcb6e2bbb5e49e98cb20a7d09883bd39870245bcbf25b6445658b4418ef40ac723572d23d3bf364161cabf94612951739b37034df9c53e33cd83ce1ba97950bf046f8787f671c97cc255d946bd8a7ae3a63949e6668c8969fd6cebf6dbfa0f08c2b2021028d5ef8796ecb8bccf9fe7d026d48d2662465f2fff0723b321e8e4d8392fbf1f0120b24dc3a600c04be040e815e3b4d28e15d29ba0e5d41ffe89b5cbc25a9fa65aa8e5185033d8eb832f8171b502fff851bcef7ff4c41d8d05f25f717f26cfeb296ed83af3b1955570cb36c37c0124af72abc6295985f5acfeb987982058460ffbf4596ac6","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"731e88edaffa707c0029a6b34fd23319"};

            // you can edit these values to customize some of the behavior of StatiCrypt
            const templateConfig = {
                rememberExpirationKey: "staticrypt_expiration",
                rememberPassphraseKey: "staticrypt_passphrase",
                replaceHtmlCallback: null,
                clearLocalStorageCallback: null,
            };

            // init the staticrypt engine
            const staticrypt = staticryptInitiator.init(staticryptConfig, templateConfig);

            // try to automatically decrypt on load if there is a saved password
            window.onload = async function () {
                const { isSuccessful } = await staticrypt.handleDecryptOnLoad();

                // if we didn't decrypt anything on load, show the password prompt. Otherwise the content has already been
                // replaced, no need to do anything
                if (!isSuccessful) {
                    // hide loading screen
                    document.getElementById("staticrypt_loading").classList.add("hidden");
                    document.getElementById("staticrypt_content").classList.remove("hidden");
                    document.getElementById("staticrypt-password").focus();

                    // show the remember me checkbox
                    if (isRememberEnabled) {
                        document.getElementById("staticrypt-remember-label").classList.remove("hidden");
                    }
                }
            };

            // handle password form submission
            document.getElementById("staticrypt-form").addEventListener("submit", async function (e) {
                e.preventDefault();

                const password = document.getElementById("staticrypt-password").value,
                    isRememberChecked = document.getElementById("staticrypt-remember").checked;

                const { isSuccessful } = await staticrypt.handleDecryptionOfPage(password, isRememberChecked);

                if (!isSuccessful) {
                    alert(templateError);
                }
            });
        </script>
    </body>
</html>
