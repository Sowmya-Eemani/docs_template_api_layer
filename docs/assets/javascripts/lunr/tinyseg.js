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
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"8ee915bb53d2671eb497b2a32c0e2e2d2c062571474e0d093450632ba6a83e284688ce5ca6685d700054fe3c67cfc6f0c220f929646c54791f6435cff95b61b3782f6b3509af0517801a6db99019a7b58eb17f5832797c67b779c4ebc5776090b538e2663e0307f5fbc4e33a16ca13ecc175040af8e981aaa5ae2da36362589ba3d43cc0a52f1fe4bf07f3bd0c5ce7e567be5dbfc4a34c112f79f70fa095c196c89747127040dca23160f62db57f72d03b6d6b623fdd56c0e79b444f9371039aef4298826fc1c67336755505c37e0bca37cf593dc1456dd734560d52a7072f8d27850664be1accfbf956a5a7e9d64ae9d6ae10d5b0de7e981b5d07e12d047e3592146c35b776c2bf29da3cd312c1a9295e69022a492f8348297df324bdb36e0fc2a2c27dba6120661ecdb6d8a8e7d37971b4c2d43a3926675006ab32b6339216a336ec45efc7e02cad41bc6876d68524bcc957df140f97bf3f834e7e6872140a6f0d4b35615ba6ad6584e3c860712dc20e70bbd90ecb474e53b0c3d087d9f4cbc33285097ab75be23f6b3b5794925e018886ac51f3d8b77dda5889d6cdfbba8d5897e92cd08cf6d907ab7157e4ee90954f414b0afe04b15c070e198791ced749a5c8a61b14ed478661988b4a716ef7063b3b2c55bc4c0e00d1f5814b72b9ffcbff7214116e2c3b43c56c156a961fb933d61b116afebf1f430d666286147b012e66180858bb5cc0b9d038e36007c2406c834876929199e79166cbe33652b3e0b806050eecf67762865c17bd360f50463d8d582b6741cb906c1186f92df51fccecd247ab1bb1de3d918bd1089fb432bf94fde87f767ed16e4b10bbddb85b3747c4dcf8e94e9e7499aa35f993f0c710ada26836a9cb9ef22f23550acb80e0a8beec078ed0138fab9efad1a991708d28e19a962e4ea60d229cafd94d3a6907605e879da63c68244288367efff12195b6280c22404f48d0700b856615f6db07ae301af841fe6bc40e1938c5f931ac0916f4b398a5ac22210b1e1288723ab862ae6206e4e00990679800758048b0df76862f8b226c6211045feadd948bd8338bd3c47bb3a1c0fb4592a88dceb721de61d21cc0795ad3631114fb333a3ece87f57cabab2ddeadae88a6d08339d6b1a2cd0fd25d3ade7c542c9fec129a0b71ea5044dd47669207bc766f256e4c0b1c7d327015d812ee49cb1f144ebe2e7d65c8d6ab8657447339cd601d4a6189272549ca290696a35f296b8a3dd4463c7fc4046e403746594e0b26fbec4fef2fa9fc42268f14ffd33061dbbec5cc3b63dd44c6ef76247ddb65f40b83a80d4a225c410577aced54a08bd59616bf287e32e1ca77ecd1c31644b675acc2fb4227a76578076d959d7c19f76af2844103ab7bff559f9a7307da1a2944777bb82c648ac7d8bd4a16a717fe6ee7587a9310c39c1e9c141dafe284ad5ff993e66926f2b966f4f0cb7033ba3846309de853d12594e463f25f64a5346e8887573fb7879d652e764ad9e83a9d3e019a4f0df288eafe46506af1b3211cca2ec0d50f40121c30895dc03ea2ce92a54b43fcf973ecd1fb9eef859844a551057167042a4e0a96df5ecb9e910e151aef63dd813dd2eb7c0cdf6573e9812f8165068bd28e3220abae002ae9121d8ecde2057b74ac05d9e266432a0aa1b4787ad7c0fc117671b4be78c644f4327f7f988eeb87c991783dc5c4f1bd708f49f75fce0342d47dcc533130b8e99923f15d229a60e2d748d3d4112dc3636f966805ae9b2e6c4ba78ee4adc9f3de4bcfc7844245a6bfc7c0d8b796130cc087ae0dad1e511dd029595b6962fc8a581c9aff7775a79d55dccb1696837563a9770a90d986300681129c8e2aff2e3ac05c80f2ea7e83ce647a40edf167806e9b23cfa10fb08bd8d3ffce8f41bc09d89656906fde18d0baf534e6abe440e2ad2fa62127176c4412480ed4c064a2ace441f62bc37fd3f3745f718c6c0de55f235b3d490ef439276031f4ed753a1cc7b0e608f0dd5eb537ee813ed49e81f6803082e0822372ca54c043c4ee2d8018b814014f13bc4c8563b3aa96bb2276e418916356560e96be65e1f6a6b6b81cd7fe96df339de7d4e82a536fc3abdc787e8ce1e5c7a4c0b9190a0afddfb9e903a4b6bfe7fda0608fbd348ceb2ccb83fcf5e152ca2bb2e8ac4fa0ce074551f999458617e2e0f045833c73ed3e1bf1d7a479f7e5c5fe7cafb24d9e65eea462d9b0252834c465b985d1bea7f0fd8393c42a4b160ede97941d430971494aa1536475d94c26cb3e980a5b7fdbf639135e17df4fbdb3026034610924edda52c8231f44cb5892d92f8ba09045c66627abdc37685e314ae872aedbc64e5048ca665eb641a643f69705701dbfdeaca92fbc9b2be534e026ca815bc457eaa673c98ec5902761c37e97298838287f928b0019bf6384a97bd152845c8a9bab57d695c2469e8bbe7263440338b3f9ecc3c847f3520ec26ccc4e91c1b4bfd1e2bb465f86b0c2d99515ef62781e451864b6f53860d1431125bde62031729367c4e919bde0bf632194f51d2758795c46b80aae5497e83426389819d9a19068e50b094e7bbb40cba786be18be715d1dc2b054a9a80886b8712eca9d9f0adf18bc7b84c83a0bc729dfea83d93005eaae44603e5bdc5210fc0e7960a50415f9004a50526cf93201e140022d9808e37b27d470c6dc6c6d275eb2824da32abb66c024f0f992bed3abb9be022a7e74d6bd094cfa6df74191049e9e075246fa1c588ff4e24d19b881023a0f58171533260f2a69d510add3f8191e8d7b2bf3a8eafebfc06f00a5c21d0c2157f9ed71ef9c6f3432b618a02d0c65549b2a72fc4241d48214c219d1c0fab5fc7156088e434bd50698eb65fc530d52ec09ecd1b43cf0d6905a29e36b5f370e9a94c7b5827338c62bc5d9fe2674b65a7e30f3188fed925c5c885818ca20bfc988c9c54d381825ff454f73116b2164e426296cc7971266e882042f2cf5481afcfebe097fd36411621cd3abd65fc3c61e01712a67758bc03ccafcd8d4f61386340f03683a839d10955dcd3ee8d6ff87389d1f8186081c00acb1232b45ebde57575a159873c79d7b14d4cb7a542021874cd755acab49af3ef93df9c16af1c7e303c2b9be9f39f701e7ad5f6780a4cb5336ba5615fa7ecf4da07064fa58b5364a847bc3299450beee1db0659ee459baf97aae3f9643ab0a3d964d169fd91c6b351491171759e4ad9121c41e28314ad032e166326e23a699aee5af6412c454b9aaab8d7621d9be874c9b52ba01d6fc1acea2d8ca5ab69796104254d93eca966938debd085f6c8db46e5c1d2f88a97734ea61bc9b2f61bf2381f1c1abc591c686d0266c6c1bbd83cc6ab97903fb8a553c41a0f7eb57402e377e3e8c96df944eff436759ca412ebd47bbc02b4c13df84086186b7301f1a5aab71c707a0442956aa57e84b78810dcd21ff615f25d356f868a7a0d9c1766b71d5262b6ee5df9e0a4bbcf96df35c2e822f9c6b70342923a36fc2d189d5b1d2d72851122a1915c609d5c78cabc8e45301efa9c5249db2bcdfd3ffc41cd25a5b15ec98615fb247855fb7ed4a7bbd7996b129d6d090effbb57b30553bec538550384ec6ca082411a1503ed0f76ee1290d88a3d1a2984ff436e84cadaf676d880249de23eba049cad49bd94ee4f74a56b41b1a8085d5dd1b39b9442144305c0922236a84daebbd37cb4a99363372fb24e7421fd8559925fd2dbe0ac61799f5a3f6f7ecbfeb9c61fb91ec1472680bfe133c13018948028d4fea165907a06f0174824a3fe6f9db95b91a3decd9dc81ce32e2cef81ddd401cb31767f99e981ed7f6580c40e1a1dda0d582555406949a27f1e39323a6ccee1afcd6bacec4a507bde38c777aa82cca6df5d154b15c89c2353522b9c358c13425ebaf92852619c0974f3bb8eef7620b4a7a44d89bb53540e1cd65a3081d8210f55b2ddf95d5a1dbf1c350559d7237ed918bbc6bf61a9f599a43520db7c16e8baca45315e0cbdbe4f643f3138dcf732309162c5a2e3e4d37c99ce92dea89d1192f61ee396a0940cdddf4d438a7770e0c176a9780a7c09b4ff78a955d056ab26a66f9003327690863b383aa1dba24b23e5cce832ccf33809bd43023a668a543420f94f49a132f68beef76bfa51f8fc9ff29b496d2578ad368c518db1f134e48a62ec00885c21fba164921e9ff885d1a015adc30e08557a9442b074da1a6b1650387ade077f221b5e402ee22943cd991fd70b0f41f9279c517a2fe3996ecf621162766b0dd586d3cff71f890b2b3f1bc38bbf6742999cf1125e5e29f7d85b2600ad7e6db8d6326fcef86a274640c902339753deadfe3cc20ab1141497669b57a91d354f1688047b4b3876da07471f5c71bb58ac248b842e72a40ffcaadd05ed16e1d2423ac430ee4b6c2ad8aadc9487e6f079bc54d86f730371b4ab1379610339b391f7902b5127eba58698f8e70e384ca33d0dd24617948e9643f99ed86fc097f8b6755e9d8bd2c0d850ff16a0204f6c9d31805edede397cf746be9cee4051a138bbec7751d839d3a1fc08658e04ea9444a3252416ed42919236183b15d6b09f2ddaed105c12524870bd673a1d29fae61ba73ea5864641145dbd17431bb4d847567eddf7a64fbb9ce0ae93c132e68b9f90e57c423b204112f476ff32888b17b2f0d51b6aa5745e437b682ecb6352a8bde8d5197b4bc6eac82bfd87df893cdb0a60507c35143541d0a11866d89b5ad0d79b07255941223ac8a5a2b3c69934de0a6ae1da1e294b10631ec4c843c091e954d66dfadf475c4d0822751895e0fab75831f8e1624ca90a6797420f771a599dff94f6c0eefecc9a424ce5b3e1440bed70a2f703cd9094cdaa162243a9853a862528800cec99db16d616b4fe4e8c1ac386d1ee1947c449e98b1aee7dc401b824e98d3f03cfd50ae21acb719ee817ed7258cf7a69ba3ebe6f3b7445a1d34469f27a7b050c8e3473cf7ab3d2ce01f54ee90f40ad0d871ed8e5e31b01fab4078860f1836176267095945a39a0c1164e78013323d5d200bd9c36603d7a1b1b738cd486a63380e4b7e74a47fe321a6791d6f1c14c611a5455853360d06793c033e7b536f1e1f1c73e7645253fd796dfb972488ac49ab584fd4736a1b0d6415424519da001d92e9bc18b882c28febdce49875d9364c8d39a45b159c9c9a271e487e7f5827e3e5e8981797e58f8400fae5ad2eefe163a2e11e20f9b2977802fdd573364729ff5b4e26af1cb6be8edd888dbb70c50f3c89a0a4297d75875bfea189bb9d62e37abdb1d520b490eecdb006cd544b178ec4d6e86f9b38534ba3a5f310e15a8b8677fb9757d8b8d993eb97247c8021173345b3648f77ca3bee7582e89d9d3e5429338b98d9da643566be2167c7b3ab3448a42fe2b6f5ac6c224464d3510f976f5148882c10ec3da37d972c133f2348c9da5159e67956b1f85181f376f0cfbf92b4fdbf93e062042ec71459b2800b0304d563880add952653f7f298a64227c34d284be96b59e3ce35c8b8e7b16adc0ba3735abda05e38925a44265b64a6b7c47343a3cffac96f5101b9d9951dacdd10671245e050b8bdd413963cda2592d76123aa98707b8ac42947a2013eff2cee13ed47f8eb1d3858fddaacc26fa55f117ba2c97f712db35788fa58a788f1c30de6742522a589fa53f1ca30825ab577fbb959c1b84ccf5ffed9bc7c937512f129ef38c4c57e6e567016098ac7a9aaef90b264ddface8b979f5289d2649244e62f8d772574ebd49c43fafbcc2dfca421683ec99ccfd6d7e521d54331a0ae6d785493a178e00bd2847adb30b051723522681a77867dfb31658e766503cfccda5afc9727d31174b6a7e5625edb0e999d84e00095029ae7ab1be55353dfccf9dd540c49063cbf00006473377ac54c164c4e4ed403247982a00338cf6041b538421835f93466f2d92f811b587042294c94399340d1ef41f082560704df8b192eef6fa3b0e57161eb096f4b8ffdd7eba6e540f0371677ac54d3e4a505a1747bf262c0e1f0a95448e3a5cae07cb8a97918aeaf2b574d4ec86412eb9cfa745ae7d5a0bef4cc40a539aeeaf4f50c1832c65052214f54f1252fd2f026f0f7b878fe570db2814c83581637e8cd313314621052f45d825348f8274716a209f068e823e0ace766192cc20167a84023eb6359424771639365d30159bf21e00a59dd81b4c43309690e10c4c9116ba8efae9b0c3602a6c7d4bf9383a62bc743ea3b11b6a53972c6d94f6aecfeb060d1aae285298dfd4816f7a736530b84681d5f780d2cb02f9e8beab37351653f45f559f856d9b9e11173a144d64dbb8e0af851133d934da6e988b7d38c202df5a4257deacb10f0c43171cb2969a2f195d15caeaf2ccda99fc30235533cae1facfa520468b990a0a548831d3f73fbe94ebdb9fb329e4dba125605f350b4e42ce529cb446483ca4c21f9b16c9c49d524136008be2711378fe43af40480c8f1849c27389872f9f8edce63e0daaaabd82ec42644ef8b6b6e709eeedb659fd7b02bf4647446785c08594956b41a5d4cebc9188015d73e962b3d6f71a79e5f90ba28fddd5a62fd29918beed4632c07f3da04eff27f6427a38b895a4b48b8fccd40336d3571699c926e8a758856e92a97fda07036b66c5d3ee636e289d2098423465d854e644b358dc1f9cd82b0c04f150a2ee6b6cd173247c330cd80a3bd95c8e96b55eff337a1ba7cbc408cd8fd17bdfdd323b30f7f1caa7298b3b41a7030d5240c7c5594ba4894579626770b08b375844260e1b2b467c913ba7cb1b2f367d9e283213e86182d536c860b95352943b55845ff03782dcd8d387d98b669509c369a7fef06f22876cc895b5da4cab58b03c6adc3fe0f33d3cccaf1cd76e84728a6220171fbc445e0eb2e706397c02285a8a82af1be8fe69418684c13c62698b1006318166cce167549e792edaf6b547b28bc4a645463e22730f9c8a185f39c99cece710fa24b5f5000de95b48baa9cef3f0e3d68df77c9c71019ff836a199983d041d7c5c8c89f22fac9406e837d674b0975916719bd1b69550b87223213f49de4551250109a29079d89ecad13848bf4de10f5ba9b795823d97d265afa54df40217bdf5db1d502651800f5aa066e810641957c1b2992c1d5ae252a557b0c0b8873f6f76349f150c6481bf0b35404e0d34abbf88bdc60edc3c085ee33c65b7de7f7fe919b11563b2b64c2267f3e198387dc05d8001705735912b6ba34670b0434890b5472b1e253943115f8dee9aa739b010782f21bb0384ed5bc4fe9a9dd00e424d952bc38c183515b7bbe551c2e893dce13db596d5dd7a849d49fdee4852e514ec83e889e9a552c77433f9411005f05107364ec01a337325e328d1839212299963cb5db58955ee94400a624a6082fa10f0e834365fcd5d0273a78621d3ce98ce71f0b6719050a8c4a130cd13f06bed8b35dfac7853a0ed4943a5730631c283bdf0dfba9a1be6234af878380d3895f0ce62e399031dc56ef3d92d3285208472176a63a474b3fae0e7999ea4e7f8f01350db07aef271db7603acdd5dcfbc40059f2f83e96d6e87e238d30af2424d62da73e869822917467bf2c671f32075ef713c5deed53ffabad826d1996b45de7d23c49d241bf063d992792ff5b4d9da3f884c863c4274622fc843ef897ecc7a049a8db87006df282ce1b2a03e5435e43e649a1a15e3c9d9a722e4ff0c370668d042bf34a8c2e9ad36e7bc49c2d9f8b98c0768fc2d7d88f96cf4f559c82d0f974d0ca9fabd57d4e97e586dc4ea79b78ca68f908014530332e7bcb1e9e485017a66f8e13393c019d4a3cc3d224d03239776d2b94347f72db2c97e40a597f765529412fd38dab67b550369e7e6e2a01e15c184de05aaab787f492f4c75831fa5c5cb1927b029e0c4939f050da0c7a1f1895621218079b0161a65cd5865d69f6dce11597764bcfcc4c5018a0591ac6e69124cc5338e7b7f22537ba824f28b187d255d7d34e37a0d5f3e34e1422f740fa078fca8b2720c5c053c10856cd21281ecb02ab603accdccfd54642143d2b6568cb295716ce30907c87351b31e2144612dbab46d7621a27fbcfec8e403326d3672e7678b8e10d087e8f708f01e6b2e6535e8128b2a17150b7325b9c2baa7eef3450064eb130ea274034f801a47116ab9e52f79a998bc528a5b1582404a2a52cd561b0eaa8c96e90d2fbc1a6b1424cf682e34f1008fc217071f11aa84f026e6af1ae5974c14a1700faa5097abe986c28d23e31a5347394ca338a4ffb04c600fb08d1ee87f32c516bbb44e352adaaf6a83f06a681cb39c5232d816f80cde416bc71f88046bc2a06d69be03a36917f2ea4ce155b42f53f4131b2360bb109424a5bf40d47d9cc4b065be4eb33ade83aa73ed35552e573e251e7ca23314373f322d5739607dccd23aff912d09900836ef39cd415086faf9d13d3db21f4df987ed9ea62243d7d94e8bb198ad66b2a82b179bb7e0c97740caf03ad689a4d38c26375045ad73b2a478fbd6de812a338f3490011a180d50cd0675a6c6ad6bb7013128ca6fea15a6075365714202084b22ec940bb80c2ed420adab823aa3f3574e35a3f8a80d00b74f36b45c9bd97972e4d24dcb24b079fb1b91443e0568367f9cc1248b9f2d8f532b6bea9d12d76671bac1295c99bf11630650146a0a2b496abb3c90e16e811b61f305876333e0f6be9e56f8bd1e3aaa1c5eff29c55d508b7b641b5e70b9cac976ed3df6da569b8da08db2b569075ea28ef30fbe26b2450d14d2c3c73f4ebe0e3f13ab41dbdea206af72633925f86904b1bb1e41f9a72651e4fcfdce9d9b3497cced12c658c80309db4c540f5be43b849fc8e6a0dff6e9f36e74f6205e55df2c9a7460731ed157422f804c7dcf7fff695e9753c30fe87beea9ee6411a168532a6e7dc21148f23f79a27b55fd76636bc5f72603cf0eca189dc798c3894f6b24257e0662d3fd3d2548cca3214b88260a190759b5d159f607f98bc632815d0be6d13cbaf454f6cb5a0f795ce8836d72b68b6b32fa9434c3501c8f7c467c500eeaef866319e17ab63586730c0a7c0d47301dc1818e39718e0825d3da27d7623f4e591bdd016d6dfb941b1c6759e51e8db2ed7f11dd1785a10b152314bee17628987baedeff4ecfe38421c05ab69191fdc26f340eea97f30f745d77cb762becfcf4eaa251d5d63c93a96a7856588f538aa9b2a2724f35a7b66783294b8d19b1af03732ec891610213bd364b1c84a64607c77d23cefc3b64a0662fa8e46a3dd52033b074694ac1c53a09ae9ed57bb62ccc252b5e1520d8ed124fa073d909f7a6ecd5d9bdf08a5add9ce33521fd8f0b3abe0bd8a5b28f03572b04d61a5b8f679d124582a559a490a23b8e9061a57d5d55f559c0d8e53919ade9c75bd37ff9b90a11b10d4ae300b679390d6549fd4a124bf7b45c44d4f0b2cec7d573ec987e403b0b5697987b65057ac977393c6f23157791be01927ba50b84d60a5a2bb9ef1002176a0e58ab7607186e52f536dccc8c7e987d9b47acf5ebf2e8f2c85c9b6f1dbfdd3c985ffbcc0062a735ede5ed1f8a98033c9ba57014045fce169695f42439dc3ba609ab8256806216837683cf0d18061b65cfeec52708e0771fbf8dbb2fd6e28d4e48a46c29529e7fb089431d4ec3ce2f4ddeb29232e96292fd4b2f0de8f67013e5b0a2b28d8f9f8936d1196417197cee3cb1f6619ae2d57563f1b3b7c2d5895945babf546dd446f8ab780b07e1930b8dfbb7ad7a2fd7e609fb22aa2f8e3d778572c048cf9bead4aae4cac8ecb01878cc5032c078bbedd8cfb5cc77c97c975a90e9b3d88ad113f035aefc465fdc7b4069c41d0b184568ac1495bfd5aa47aab387277acc7d0c36598affe6c256b0c334fb3983359ca20e2190d390d5dd6fe532b953456099a071f2449400d0a9c027c63c9c5a550f4725c40651925353db4c6d028bf63397477450ed171012b4e03cf7fc6e7f57ea374827f7ce53ab0fb240b80644db11989f112387d2d37eac5421aab8faa318d848afc81d72aabc847f51c6526d380dc2ddcee6582add620c1e80736d84f9dea3a284d6a052b814c928ef8cbe20aa0f4fe6831ea77d12f3e4b909dc408dfb736ba402c8f6c4928603364791644cec2a20b476d011eb80be75058b7eaa2d97a15393683ab1686519f89aa3057266284c104a8d795bede7056d384a5bbf1fa287754273f3d1ac64a8857f4de78056cea554b29b52534edd62df08607b00b275b5e4945ebcabf9e60fe91adcc976886d8a44345933ab27ef6f1732dde82f75549a307b6fa7a84208ab283b2fd7b5ab3b8d47242559366a11a31516e4f693c1c228bed126b8310c3a69958b75d4b7da8c7b3da0d0d441fbbaef09ef94b15fdbfeb88e1215b978daa9ee194b10bb50a2d080779bbb8e79c82c8b91be9ce917cfa352f62c031fd55805f1804f2aac121388a970388366accfde02cbb13c90e592501e746160e5c3c174948d020c27694738392b7f397d07a182a9e1152e79760caa43eb5527ec97a986e6f88250c4bb7208db460e69e6a287d86bae88c57ea74b2aaca750bc1765363f662ddfcede3754b239812ca5d071109177b295e90b100bbdd8c3247cfcce624e0c4e855a7827715fd7e069653cbf7a7b7278734d7e62c32d451597cc5ff56bca4d2a7fbbfabe55019b77cf1ae3cb9becd7750fad64fe8c25edfe9004d6903bd7f2dabb3650fa6bea02478d90169602a8f62f8808c16307e887d1400e88302cd7533e8dd8df987ce2b1d5a06f2c33d566c4e10d15a33a9ef7a01f2dc579e84e2cbc58b2b2a5a23cecbe4b51768d441578b50e18c360569aaf266d55955bbeb69edaa070dc063cc6794db88422069ebb4eb6a36cec9c38679fe4dba86f669458a1f55ad6901e31370a216ce79e239babae0d970347da9b726581d2f4680c0c0dcbfd9de5a3a803f6aafca6adfb7c85253823d877efdb2ce4c27660759a61a316de59590060624307a6fd3f5fa34ac894980226d8e750f1bb1e7fa21385148df700747565e7493a0c99a3724f4d66bbe443f318730f673885881570dfa2dba4c63253c2e5ffba79b9dd0e5e1a7e841d7d7f59d2950e6825d54731a934a0eb068f5109df713545842cbd8c50452e6ba0e8d5bf28f15bec8ab1aab3403861cdd39a0aeefb81b8e6a288a435d0b63e34d483e6ec10dd4873109024da498b57e46b6d1b257094e31ec45222c45e8cba418168f11819832412aa07e801853c6bb96a91e418ffcfa8fd0774d84c1385116bc0ff035ca3eb643102126e33b69f4626438a44efe3e82afaaec4a25ea5f40fbebd32410e43118c19d1e14f9a768a245bdfaa20f407204c783121d3af578b10298e43c0fbe4196bdea0881b802e65c63057f7e0c813e3387d64c06fe467782d9419714b25c9c542c40ef635849b9a5bca67a5e4920b61d4845ff212f4fd010a40c55189f78e265522c412d9e362165de5f65036f01bd454b47d174ee1a86f7aa776a6d657fd43272177dbbbe236367d8db0553e8c380d2b507d9816f52a7d600d388b4d31d48abcce6e401070c26e30c00cec2741329766ed263d28755ebd48db899af634d8c1ffd1432f6a521824166a69f977a94275fcbd538b70564d019d77c55ae2595aa0e5883c4b83201d3aaae0ccda201b705fc72177972830fde85f4fe344c60a691a7a830a5533ec4d779bcf0bccd60d5c6eaad47568a92c980cd0975b9bc54b1ee8cdd0b01d59a07125ce1d72debf07869a7303427d10ccc4af6af078d5ff034a423309c4b76c1623a814e6c9079a9a66d0e9f4ae99d06eafc0afb9546231933bd913ec5ebcdcca018141add827c5f8b738d0537bd74e92e60728253efabecf10871a30cbceff216ed69d90dc9fff329e661f742726a15490bf50979378831a1076933db1c67cf681340c3b9ec3b9fe0eb616379410cb493c2efe8509733d0ca5211c63204f8deb3a1a253c07c811d00369016beb87bbd414e143ce0f66e4cf21b3a3a19db7eea1af744b4905ce2629d67ba278cd5effcfdc29f4fdd3f58c2be12d63a7ec3d2da16985a6be686bdb2e312994f3e8a87f429a3b7030aee804229c51f99fdaeecabe780b7b236749b0c83de14356554305ec43a27479436b4c7b19d969f457e1ab1da006df1e39dfede54e70dbbc4cfd5af793dd6485fd3b8c345863fdfb45945a08fc2e42c3cab523f70c171a6e31d116b5a78539eccdfd86c1410c1fa02d4d018ce7511674fa5c0d76c931b2f8c99be683c33f845fa935b94cfdb0924d0181a32e5bc5f6d12d3a652607099cdb49c0695e152a692edd3a396b9b77843d78359c29ffa4a6f980b785efc4466251bad91da005315402f94673d4dfd13d90d7c3e79fd1453989bfa5610e3265c72d24151cf64ceae6950a3fe1483428c08263c56d2ffe26dcdf6c61b2d520a271a67ec120615a3fb51c4e7e834094a6d6918d23a724f853c147d9c52e33903bef2c93c39dc9787dea712a4a2b85d08b96d9daf6c35f3627a95774da94c8ff0bae670808b60d7aad9c9474206bb0adbebfabf8b86362f264c9b8c030bb29e8866681483cbd182b8fc3ea2e6b197f0cf0cb4e558f48d2ad7da961b3dc60a8f3873b77bf2e37cdc3918e9c3a9535d3a6674b448a1b499ed8e99bed3d17f9e3c279bf9daf1bde9b69b8ba4d1543df22ba1dd884937af7602b22bc1e8f6be166c12533b99a631d89a1f7a268ece9ed435523166c5e38bf74600818eee81d2b861a7012db1d5598c1a57a67bbd990b58bdb9264cb6f7368b6084795397ce3673cef9fcfe0062caa62dd3ce05edecc67a3ba990a075605d5d9d73026f7aa050344957d015fb4605552e0b884ce6ec248beb33832ef01d2141b55763375ee01fc816af887abf53062fa683af7e906b6284453b848eee8269d16557641e95522eecd8a3bcfba8f93345ff9ee53c5313ed26c6d7f5efba984b8a6594c7e437c61c3c7515ec0b7842b71f6af2f1782a5d957ca63a4fef18123e68ffe762f063ac06174fafa3e6278467b1dfd4c4408982e58d279505c0e043430fbbf57fa6c58b409089d7808cfde81043403c359a06f23eb159047582b9b72102d1c53af304fb96921dc00ca953ffe7beb9e8bb5a67feaa1608660c19e42ead56b52ab83f682eb4c2b79d5f15f2711aabe1aa8119dcb80d8741bcbd2d49c9d6344b175a41037399158bc82b0ba6b353cd108b8b1acc84c1a21374301189c6f0cd723b7fd96f92a9d2d51fbe535c766f9468210d3d9290122f4f22f59315c94acbed4d98ca16cc9273627c2b5fabcad24b9ee394bb258aab867c5dcc7c19ae33000f6ae1a54efc310c54019b16f95656377875e4ba40bdcb24e7df56112028eeb7af444b6b025d9aa84414c72528b28bafd26049a0798ae8cb22cd57d47c5effb9df6e4bf09bbb2404bd96c8d14b4af5b55044ea003fc1c8c9f02f7648261eb6e3a47463b44578635db97b287af960ed2bcedfb34f1b4e6ba816289116fb4f9ed0a61c6b605d568f3bcfc32090594823bfd876977f1b534fbf0af65ce4d5dbc3ad839cd43521a127077f3bff1497ab5b6e6779c37a0197f4371774b7db6d4f0e6500ee623c01f3d4468d24f8c1443aaaea00dbdd11a6d1aa9aa39b29551e867b6575db03ae85bc51f754cecc3cbfca36a0de6e815073c973e7ba298cdd358e7e49d4205f78f917f0543f3568f5e8ea26aa18ef489dedb05a88baee45d76ae6cf5047b02bba68c7de33307d604f82518b643fea1f1173b01f8e3934aff2252c49ba93208454302694509d81572d5c1899f47796406b56924633078e54b83fd0b12009c6c31e9b4e83b61bd6c0b4a39d675cc77b2c6b40be6b870b0dabf212e58e2bb06b799232c38b2dbd6dae025f09554537c2584ae0a6e40c1eff53957d99e370e1a03d6fb24bd908b532015d84bd20a28e4a74fb288607221e983d89be440c6b8bc14656c72b77b34a6cf7d8069cf56565d471298a49e222474d6aef620555ab3daf4417660aae32f542e69c64f9f0d962d0e37208febce33a29b50b6d0160302bdc5b5549988ba98e4132186dd952f96dd064a1097649b47228bc226e70334e5da7a9c8d9f34fd18957d984727e984d1c623c306aa8431816d5d1e4f546fcc8e48b098eee6c0f2cad729e7a24c9e79267928a43e1b832bd4999cc887aa5319473eeb8c4078cd9c88b72ffb80357bafbf9151f7ae3b62ebf0aa348edd8525a36fb8a9762ae54fddfd40b5c2a2320e95c2610b9044ca2b4ecf20fbf5b33ff985a1057a99db3188f69866905c2ed5c17ec6447acf8a5db79b42378c195046d00d914285025856c2008a84ce66715629982207f88871af692a64930db19984f47a9b7fcd887c9bea85b80fe68464f714a08c755e99aa6c1ae86e1585550a6ff79e439ea25f814d1a66ac3bae20b8ba0638dbd7d40063d5e2ab5bc52b09e59e7c4b7deef94f3f399f9a08c02357594556caff654cb0e482bccb8b3d5d1eecd484bdbe88defa5c0fa3ef7f2a83743bdb0d3f10f0cc49edfe1de6266873913d22ff8e984e6bbd74d48dd7ec2b7da3a8d5fa54873767d55f2f053ec6ff0451985d40232969360a8324b7c93f9af99177a68fca8f5dce92426dafdce35d8a91634c6c56cae0d3cc10863e79bf5f26c08dc65c201e940d318b9e41912ea777b70c63469987d76e6de4b1ee3011d37450a5082d759509d680be285d6f586a01ff89a4b0e0008f4ef7b2f86e468a71914df0a2bbc2238fa43be789a1cf32e223a5fa4bfc7e5a1e32958179f4d3e599dd42d87a196a6253d094a81aba156abd37ed7f75528e3eb711888dd6aefebed072f499bc84a2a626488b0da77f8ce37c237037acc849ae940974483553bfe28b0af69b205b624b328be64dbe537cfec63f18b1b2713112d0a0e4408531fc82181cc16feec496df15fe87da1c72c592e13e6e941f71998dae090eb47aa5493a53bfffbd9f380c9523dab4edc40e03d13fdda3ac781909d44ab8720fa2975a2103349781ba032cd6d9ceec641235f42d262f358cc2abb303914c98fe50584baeb1ae400471a8277300805f89767765f8da271fc1b10a7f815bdcece78b21d7616f06b83be5bac66e0fbe6a6be856e2c851f64009c916dd7587937ceb6ad33e88ef8a54380883b81097cbd6f01d2426dcb691d219945eee00170f94500ec4fff3d25413aefc2512039bfcfb402b27e1ea78ecea7b3aa42c0bbd18f83bc1b45ecc62740df222e1a29c1aaa144cd3d2edc0b45d36dcd55af19a016791fa3946405a1314a99fbcba083ce029e034923c5728e0896b9845c08508abed9f13a7b4b3a96e15894695735e312117f475d0911947b3ef18a7edcae73d36a39ce98663a818b1a3956df754899a6ec06a6ef568de69b967e58e83742b4d02d7174a9a552f3179fe657bbad6326e1b9d7671733ce4935f6e95f32c8f1f67e32456969d71a2a89c14174518247d042cfbfa1a34ec096bc247c5dd67c571b8346beac6c69ee6552ab7a0c2f06c23311f16e9e64a5437a4f20ed3d817b0fe88b1606b5ce9619d94f043af986b5582c54cb4cd5f158d6cfce079f0f04dff94dc2dcb357cd81b506ed25708c2d5b2c40d3a6534ad4f97e4502cfde960d92bcf588a9a026aff509ab38a0eca5b30e7bd5d21a217310b02b4dd322f097200cbe9614ea3383cb1c6bd5c6241ed621907f45463cec8c87687564e4fa59327bf986bd7e9330bb953d90589ebed4834ea94915ee2a654e98c240ce667b8f775f58acd6142d5cc978ba14063616c629f3c3a41de307fb3d33e26575ebe08c07acf32743d9f934393959a9c4e3057430353966646eacdad019a79f175f0c0ba0cb2724fc3f8749731cf805c89f3ede14833526396c7bd9a47f2c7d05b2b09cfe4cdb7aaebb2620753deff2e4720455d53eb76bdc04186429a125cfe3a646618b50cbe68c9788db60958709b408172a4f0d3acf10277f545942fb4a67a63d14564ecc34e7f87c26fea166067ba7d736ff5e651ef0f8eeb8d24be4ad6621209f520527552d3decfa158cac2137b16ee179d1fc31a5b69a31ffc8aec799e84cc1af9adf49961bd9ab3bd23e5427f55a125bbaf4cb358b5989c14060ef1a62cb7cf9efcec3299089a1be3a129c0a56d0384baced6a8f8ed397beee2d259ff126c5e3184fa5856213d9837a28327862442590da6ca20c9fa085c958d1bdb98b05fd8f7d9fa634a4e65dc778b7009ea7c3d2baabe84cc65571c978a287d37d33b4cbfbcce173337e2e69f038ce512128f8ee109a5dbc6d28bfdeb329aaddd41195092ec4580602694609f1791893a59cfe4f576408533eca419a39abba49187a479827d64f58ae6a43124be68ee7edbb7e930b96cd33bcdfe80e4d1a066ab44f89cc39c43274919036b70d9d92c6083ad4480493466561d56f9ac10b054ce837477b55077d2c2fdc4fc86b0b506457790750dd0f7823e9f352d31778c20af3af3dc9cced32c2ff5d89534503a6c8a6fdd952d25bcf06c47a2527f45afea3df933cbf3291b2ce0212b8afbb4b388792f38cadec721474f645552a5c5f999494fcf698a7561f3ffea94e0023fca202bfb3fb9cc041f2db419cabd64b677410227a5e3e5b60c41b4f228ba8cca630020dbe16251dadcae61c2e62e93d6c2904a15b3971b7e410eafa9a455cc35fef2e378f3da797eeec7a63d9b3032ec92a7c15bf0e0784fbd6c0b641b6427ce9d845e260fcbb523c4f64151db75642b6d4976bdcb8049281fb778d0452b3319260c5073df6254904dafca4d7534f4e466e01fbf6e5278594b0bc496e543c489f5f1286f3eb803f72c4856c21d8ef442df10666cce3790d46a16f5c3745c00acb0c21c36d0c477be823d2e03276556f03bfe49f97adb10a4dd0876cad5e67f9edf7a77077f043f06e55abb7a27eeda35cd861bd0e9ea127c054f7d4101cbc8d04c4ff85389cc670fdb1735acabf230fd6c481c0fa1a3c7e85ca24275bc2d75c57c63c711af9a815cd4d5760932cdf7a731771236b42811efd03166d984643e21adae2c2f66a095018b9eb79f54165d555a2a60cf4096af8e6d7c35c033d4650fefca2b68fda6923172bf3377dd70643aca9af27787fce62950d36be866d04b2fe469b56b3718685162e5c98bc59f9c4dd2a76dc3d380857fc1136e24469aec4c82b16438bcdddf6aa16163324d409722b89758d2614a73ca934efb946ccaed20b6e571a807e4ec20cc85a0279a3d85c214371286d8a1df474fb6a889b6bcd76e303e8296b74c8589c083d6c90c725ba0acb2f3d6910c8a3e52a1dfa7590afef68d17a32bef0616091bad4a668e418b8f9cb7daf18acc3887f8484f87228c7fbeb2210a7fcc45f572d0ac3225cb9195d2d213f65592eaac4dd3f10056c4104018d96e7c4b6bc877b395e7064b0ebb95d4eab10a82c27ad43389e95c03b7789c2e09166a3ac938cd2fd7c5feff6bc7994d321bb5fd2d68e5437edf8ba55807f77930715f4bb5456e50bbaa7259b093d326bb9185348e8aaae2458537d7a7e443ef690313fd088339274478d3a36f74d5f01e07aa6b7e3c18036e30bb36b8931eeb760e670a2c2f94cea3e0abc88bb958c56c5264631915f25f8d71de369edd17c4e2e9d0818b43bf568d52f5a58c2f10380eee183c051b149358a2e1ee5470f39b2ac45b2d2024a9789a2b75c27a8c84fcb3e56f8410f9e5d93aa7cf307d7f793aebf6f4651b117f71d540ab72081b1596c50f77e4bc4819c591ab68e754404bbb7744d39513ec8fa1d172a11c6695f3848902bc0b5aee4ea5a29232e01f211698435bc2071f0a971e60680edd59360ad9aa38e680ab37bf7958483257689f539f3717a2ca37ecb0a605da74907336ce02b1cd5fcc7f52ab98634da72af393dd8fd0b03d8ad46631a7f9eb8db4584591bfbc0780168ac388728ace6092e245f780e29dac0e9095b33f94705636db2b6f1f7c47ba0ba6fffee7bae551ffa85dc07869c6b07e39c47a614e085c5a9eb858d0501ddae4190160b80f84701f5c09fd4383852151f11bb3be9eba16ce9e2e3e362cc4a20cac54cfea4fed8b278530d5c74f04cabe3a73db8683f7237f6e8715ea6d0547e457275a55efeb28c914a29f8717ca676408001cdcec9b397f74b16b9a841d95ef6d76c51c897c125e61acc5481177398079f606f9c056602c3a3517689bcef890aee8e09bffffe4fd41892b9cf2162a653aa1511e7dc43b41116a949d0ee584de7d27b67ad8f4d45bf2166cb5ff5b9e73f6d62b2945a1009e683b892a8a6b2fc13fd641ee06a7c13ff8e4885bdb2edaeda19c21e961ffd424a8949c8e4847d61819b95e28e1efcde9f5372030322ecd630da8a8332919233463f1fb9b82bfcde59f0e049289b783513b506c7cbaab9788a07b0dea44589f43d66ed9a94e7e0c9bd653ebd640e05eec9b3e978ba5a5a3e8bd344ac941d59340d695e4b0628c97c06cf787d6a97eb15ce0c9b8da7c5c4c17279b1b5ba9c0272f125869d6bcf7bca87c1ec4589f1981ee2937a5484d5bea2ed879cc17532305ea0be2e9715692a014482ee72978171a3e6ec60b68503097b52e1410c5975ea6a646761c6b68ee4fd32acec9ca33f52ad9f74b562dd61c3ca3028a04ae26463b4ea6f91698a64b4c7b68ceccc747b80284fbacc162a44d2a4cc7cb80dcf111c85ab9a45ff8ae464b04a06dbac079b3c5fe2d8944e581cf53d8852addf9bf53e8512b038f3f3b25ea026e30bb222f9c086b7fdee4db6ab90cfaa58cd19808a85c0602427417805fd21dc647c8af73ea104d8511ae7a67837a15d72e11a97a9f608ff22298312bb6c93622237694a0a4a9f8237802e380cea9c2c92001884e3bbd8961ae9a49e6d56d5324caa664c56939e5f103f7ea8ddbfce7f007845d8e218b6a19da16af952ff33bb61296d703bfed7599b5b660ae4134c29d762777be91554c71d5d64ce39dfc605960305918b170e74110e85a6d704171318c28f6ba380f1f67da7ea7cb8955362ce3b264a226a1c50090ebf49f7a907f52b40ddc5a1ba7193d58cf08a0206ff8c34e5495959736f364fe76b7d1c11212f8150d967973852990c54234a5fd2a5ba3d7f62a890d54940d8661460f2a252023c3347c8b500aa5dfa464ded061f7b4f0595cb6c640fc296b032f9b4c3428a9e66bd72aaac11f325e17a4daf717627727977c583c1f1472ce370d1b53746bdbf75361fcf2df90571549c80d3f0dcb9ab92894c886d9beac948438a09121ac8add4654ac88a9ad78c5699a026d3ca5b8180966d63d3b32fd6a9807825f37d443a6139aa44d0e4f129314a89b0aed5849527b335b52f66a38f8ff3ec4f1796f139e952456e6e9b2cfdfb13957c2713023b87b279abbea72ade534223e5c259250ba62843e86b26f733ae1fb38f6dbbd667f987e2a785d30fceb1c33e8ab5f0c847dded32f6cbc1f0f56d6c8a342e1a96cbe5da76d97ff9d28a7f8e580e5d38128486e1124d9fa3126fe062c01b41962d2cafbba46db141825996fbecb963688f7e8d6ef9821e2b83cc37bf07562fc61d9074c9d6222b1bccc5a3ac36fcd2baba993e78c0fa8b57f8b779e1d64c7141dc1c66853882d3e6f129bcc110f5e9473795f7a1d2d231779823eb0b7e4774bcc67192c77b7e032ee1452ad6662bdb5e2df2c526d4f935c056fdb3c307e3646432ef168c1be56cc2a9ab5721f4514ccc4f5f325a878456a9391c7df80c44eb07da1ff44569d45e3c5ee643a97e9bd403bad1347ef725d38ccbee34601aa7d8046a7679f2ea06b045c16665c45746bbbf0328efc6adfcc6dc7d865e7adc2d6a5e2282f79f2ad8c3c2942a9f5d4f15a28d57e36cdaf393bc3b441a18e1c119fb1d6fb2322bc5d616258853e1a63a047db90029c60d8f8266ccfc90dbbae3323979b1c27a489c2f838103ab67959126293855b88e20672436c9a08daab93c26545c463cb841daa857975092d54cda3dd8149953dadf8bc29f41e05b7055c9eea67b48e9aaeec9cbcc4e338643f3cdf1451b519e9c8c87e1e1cb7baadc25ba0f3cc8b6f73f5ee65b9f65b61dca66ed65bb3ef34c3a49495acf95337ce0820e8af2c2a9de450583adfa53d961b03e52bc62260eb863cd24219867bd43852e13b4e84756d7edeff289d12e726335b58ef1433c10d82721d172e2b1ac65336ba1fd1690821470d790bda2dd51aee681ef54cc0df2ce3c407fdda37f7890ebde013595437de4074ff8d8c54d28558257f28a5744cc5b862a56ace0a35a13b770d6812f2a49272391062bf92c7113ea00ac7a53bef041d8ae4a006ce582972fe7fb8eac085b9e4783e229d6347e7073159c571c1148da816a6cb6ddcb63003d98df1319a81258e45ab7fbd2ed1a76b18825159586326dc85dfcdd37866dc82b56b105b2366acd283cae8c89280e53ac8d121d89ddd93ad811eafc128a0d8e64331214379410e850beb22b47f9a62e5b152443c75975efa8b2569272334cbe2c8fd0d199eaefbd96bc533d02e7b9bb5a87889100145a4eeb6d68d42dd12f973695a8cd4262980e174abfe588b554e9a6c07dd8c385e9722979517290afb37a7aac9bc2866426c21539a5d4136be6a8a4d100045fdc5dca19f18e6d8ca0c13bba67a2f0d257df1ad9fd5d9d4856056e0c43aee074c24a3b3ed8fd6cfc370030cd7d52b07980d3f2e94aacc16de43a194638cf4fa7d67feddd2f7954cbe98afcd087fbb21236804da7ecdda9c2d389fb202f36c6373b2b45120265b176b637179c1fb103934523cd9ee4ec913961b52ceff0a58459c99c1af7b5c001ce117265664f3a908806988843cc681084a849ac4ca2872d5c0fe740938f77d11d5d7543ba565407213078d23864d01e686bb4b21ad2674e2667aad01004297d9cb3fca5ccd5217c7c1d405860e3a69a2c61c2ee1a61b27e5d200a3a7c3b8908aad5ef9be56d609fc617163248c4a1dccc0f123b014ed0bd1285c5c90385b3663b5d9604b29498f62ad4599b819faa1dbe82e4a01b82d60b33923b3f43488e9102a80a27470a834e9bac70aff745b4dab94745fdff597118dae0d69c94c057b886cadea1ce5777b1cf9e3842ad5572eecaf6b87a4b8d29e14e9da5bb74a48b29d5a1cdd4ea7084d4af3d52ff9b761eec1308b57e704934a187fcc846550268ec5e7f0d254134f631afbd51ba767060bf8dbfbfa13b1e83e48208964d9c93197ca759eccd8d576c6cc1fc4dc8295cbb5995fd8329d10b4450627650130175d65e69d9406ac66768d8f83fbaa92a0764cddbe7e8c157901ded1dfe5de1f9324e8c4fc0f683de1156e170cf5b425c454f3627c754c1d334537382fde0b17359449937aab8c96c2b499893f26f577e7fa9b43bbb4ae183820dd46b2a5bb7bee5f2ed3e8a001440c1238fae6adee29db7e722fca07c91db14e39f74fcbab9935e47e5b43ce14358a7d4b9a4af529575a61efc56483f47b4f1524b40dd6445a35a9f47b93f020a3a3eaa814800b5d7d1673a57cf245ad6ae3e80d953c24f62f3e3445f02f1ba8887e97e35fbfa899a37c054288a9cf75753dff4764c32d8e084e8288b685a8d4541831602782284f9361581905eab92eeb0d2735200e0460dcc55d04ad7ed1e6f8bb2f48bb666b54cf27c9bf7880932afce3b71edd34e1bd7ea0b16f019be7014b04f3bca13424894e757c3ec085292dfedd511c55ade0562911256a2da292c3cbbe44a37d39a1ba73601323e1d7b10d9351848af8df15c8cfa93e85633aa354d7dc769ba17048b4b1e9af290c328e67ecd68701281b2286a2f738f839b30427172fa851f2c324066bfbe8b363412352913baf118225d8a6eda29c50e2898b3039886458ce2af3134b3f9947cf59259c1cf9d3c0b0a19b171b936348528beb4f166471fedc7d73d32387f8f5084a205090b3df59e5866bc854d37bb44ee19d18830923ed1714530af9840d7248c485741df5cf9f6fd6185541705838ae980677b2a5c2090fedcceb1551d8dea0729f157a6380e50e2274ccdfa1502658ae0f3aa83f09a02bcb4421307b578fe7e3b99f5bd7040e78ace2793a92f0b0cbe38ed9456a9028362a4df50f5eba5ee3ea0ef020be14e7f65fa7da4f64d66b1616f2a1fb4b526719e2ecbdea38dcee920627f0ee16fee69b690cb266b489f670770908061837a70aa9e1ec9c5a1785cbd929618c9bd89a5482e751558a73153e206fcd359aedd9ce285dee80944bcfc958fbc40ac8f3a264549510fda1b60659402a31fc6f5e64ba84a2dffbf101c7f4882ed588a2038e16321f69457195d40fe83abc2bd5867e8f041b2902d02998e33a3116aff04c5433de969a5789c18a6c08e43284e31b5b8aaa37935bf81c25ba9c2471dffad5a6c669b617d212d77c95a1e78ce9aa5ecab7d8f45ff30669175c5169b4ee5ef2a1c174f4e9f620afa26f8fb13b7c327dff7213a545696c615d2561388a2c9f42113daa9b16c641f04f398e05eb8a6585e059e2000494857c3f357c800caf1060b20c100e824d78c578e45514d0be5a5a74fdbe2dbe9d5bf7da42c30403826d5b98643c573f10733aff896bc8b2fdd03309efbe14712b64b70cca028c1a8f5edaaf79f90a38ed4c9207dfe7681f82d8653c786d510152e0e99fdf4f6eff209b0faa3b8a274dbe7b79e6d79fe98ee3d612c47432c100922d6ec121b51479136dd9171de8eb73199d0ac0049a1251571f25e3e6896d7d294fb03f237e7682bda07fadd14c898f74735597c90035bcbad0b7990f4285a49438417877a1175b09ef9efadfe96dfd0f651cca99e903b24f2f11a9dd6ec34aa207be73d9e29e7f931fd37801813ce8b81e1051a5943fd74f78fdf8982a1eb96793e8498661ad757fdf49477961e03539a84ff2ed70dfcbfbfe7d5a41e81186755391f32001cc247265ff30d678b42eda62dc41f0366262e41e09f2a67366ac901869d4b0c51d37e9e0eb49f1c751dd640679e7da3c5cbf493f44abaf1b678b926bf6feba92af4c4b4927d8a7cfa12a17d7d9a64381cbd66f05e8d132acd37474d80cf48b16b6195486e632ccc7f641e2f8581461e90f5d96853353b9c844db7c4a7445fd68c54afb6aec21d9391e8a6aac7ef5212bdf10434e994d98bc259f22ded643743f4f793409d5f811755f67f7a420b21f3ef28a378553008570d44ca532de95fd5dde72bd254cf88be00835a9a15a39bafc76d2b041f958ac7c6c14690497534c59473eacf6b073d52d20686277509220e98251a904cc4c55a5e2941c66fff76bb0c43c5a9b28e12bcb105913e7e0dc7a394fddda30d53e5b852f5a947adf8730acd84ec4ac7f6c3e3a2e28c0927fb3ac69b8c340459df0cf63a4c4b0f402dd0a7eef43495d8d75f19d88ba70244ace96d111e021e640a04b1193ff5468bcdab02ae7bbb038e620bb835769bfef617a0a385e791ce03daa1cec0a7023246f13a6d471e2433b4705c5f61209925002c4c26fd4f22fd73e897589bf50d3d133642cc41f28a7d6d5270b12505f198ea63c11c6869674229bfd7802bb92fd8a56854af2e94586d3ea18c6eefeae90a69a7bd3ed541528d2e90c0027f598e1587145252d4084c19f028be26eda64a135701b80f864175f62f9884ebb680098ba90765ca1398629395c59d69dbd64f9a2446073d656a12068a7a0da6943f66a163023c85dad77cff52ed547cc7d0de79ef814f134dc3b687bfde9672433fcbcdb5e9c4d946419ea62a5c039da2e6a0ce7ed4de804ef5f46e4154a0b44f6252e7a5cb54896d3008b4c6c00fff6717a86830afaf9ceca497575dcf065d90feefce3d29d400b181fb6c03cf4067c1bfdddf4cdfcf36240b2caac8fea58f9f6c7b8619f9a50fd5f7a5ad6fbfb9aac45492c23676014b06407070c0284006c13b4b6dd205a39d518d68a9369cba19a4faab16e4341ab42f1478eb5480677a075557836a442f20554917c84ffd38fafd63afe351b5a7b54b77e7bed864fcbc7eec8ac90d3f22d9483b480288d056a49456898b0a2c733adf5293e3ce1fd63ae8debc1a66cd94835c5796ceada2b8cd9e48637e46166823d1cde595651247e493d37b17d7adb18b26a53d508d161df62c5a4d026cce59d751aa449e38872d6563568d9dcdd8a7231a2af247f8bd81ad2e5ec3f5ebab82ad26a0cb2a8156b81cb852942b87a7a7f202ee74adfdd669f99b9760362f3ec3c04431fa75d2f80d5557c995f394c063286a0298f45110f712f6b4ea24137a68e6749f0259415c24b7ee666af2285bde4b0bb1e316b24bbcab503cf7cbf27713ed24de1c4f816d77e3dde3a48379e71730c1146a319283abe2569def2fb196035c5a9b780e49f5cde1a7b81549ace27d8ca02d4487f09e7e399af26a1d57e1b3cb2ee8a828da94ad01237331cd7ec2e8d3d0fc345e24aadb7789444e8a13d9255143e9a9cac1bd9ce5befc95ff509807c3282a9984402733614abe5ee9ddb6d07e8b34fb06340de824bc92aa07396884e282bfb2454f77e4ce03227773ab98e0eda45ecf804f646eb6694939c650a187ae51f918d400a52dce1d93932412b43b3d2dcfb7aaa02d3fa35b9459978a13b9e4e28ff663be60d10d9fd6663cf917519093a6122014372a4435302b77c2286dafc30b2517ef00d914138369b6aa68a3ac16a56b9355fcfd88c38264d12a393d0704ed77cfc1664b7e564f5391193117f0bdc35c257fa4ac4c186cdce687e7dd984798a76cced25f7393423d4fcb5d9bb2ffc46fe61d106e79d0efd8d12e5647dc9f36677bbcc0e2a7bca5067847ca3c74c76b56ec73160383df072ca65d44b2267a72824404fc1979d7d7b2ed697c8c5f1aaf4a972c5979e0c584ea002a3867393aea5061a58369daf92e1b1867c3754664c410d14456bc2559de0b65a6adcbe19a57d8acf8accd99951e742828b524e7847536a46ff355f50cf116fd9f88fbd8868fd75df6086549007b4312ed16a11ef0f339442a58f3024774b5249b762a97111c49a6ffd263352af64776dd7bc3022e8a58d00b695d5af1f86232776a3b1d8cce5de3f4594cbbda29f39aaa114adc49a9137ae4dd697a766a5b10550b0fbd6b66b89044e3844c52c2df25f802d863a7491fad29612fd6a3e84f9388502f489b748cfe3d88626abddb39634c5cd31aaa5c296636269c73590321288c8cff03c37824e2399e5dc28d60a7e834255cb88a3ca0aeb0a8316fe3289a356e81b2c4813381f88bd0ab2c3782389fe2c1f0864221a8b109a91ee62f81ece59e5d43915d548782418c10723736718abf86ef278cfd518eda701b6545d4dc91fed81d6ee1ac18bb6e684c27564a21b61d5d0966d3fb2227ce116aa71389d0618e4610e30910bfa703de2babd4271da3e3b749e8ca97fc9e72d430390bd0718e692e5fa8e9a492cf3b312cedcd4b68cc55fc06664a29b2e43aa4e5e53aae88244e2ba95b143d33e641d1f9a934b802d926ba7c4cc50ba7330d4d86bab84148e92adca539f1340963664d100f99136a138002fb25d9add7ce61252e3ccbdb1ea50500ea2308bc88fabd5930077bdb14f44c39946db67ad14385ed424af438289a260b10999d5d6171f460ed35dbe54cf0728f6ab3aff75d94e1763ea11e3bea673ab778a8132be14ed849acd0617b103f24447e7abe46c3e7e0d16d7f626a98dd5909916f937c5d2bb0f558d39a51738e464d5f3862b4dc9027320e3294884f7fe9ca8040924eb7538e2e5e86f645772f5899f79d7f0c68181c5dca42ec0e4cd4eaddd842d41b0ef660f6c652a12d74bbcd912f82b4ae82218bc838b0bc0828574e7f0a3684d8d0cc2718f2279f691c017cb5011276a38fcad7e3fe10fcc803601d53949a48ba1891fd906c50d7c62c406bcf05956310837987a1857ce033b25df4b0014485bd4de4bdc2b65cd2182fef1e923964f343053796b404f5d5067581e90941f1cc866e37280cb380ef8168110b55c4ca1c885a93ce88aac7b9d9ae2ea90348b1a919ebc3792bc5ebaec1544631af266e245c009cf0a59824694657b36ee7ac210ef2a39cf51fc979bbc4436cf7dd2f5b582d9a8ffd478f8ec772392a6ce4c7a572469972a1a832603cfdf8d804a28d32a4a6ec95ad607d3238b6e7d84961541bc750fa939d90f6d540d995ca355b7facdc87536373ea8255362af6764496000a4b0c2120bff0f49b032872cb0b48ca66fa77927c415e042c62b29c4784c1dee5253398b751fd1e49156fc3420f927da6e6b0ed17f95ba2e078644c7c9340a18fa75c2e3a4caa3066be58123730f5efc4b68a4f767bb3d5b85837381d630f67ad4303ea91a251177e842632c6438ae0f23502ec0b74f5655db08cb212b45e1d5ac801826a7934404b4fcb742e612bcccff689a81d9813318eee4cb7d1675d89d47a8d7ba0cfaed6f3117e85bb6b12a3526f09e96448d598b641552600e52cb2e13f4037df6218fa28e72e665f26cbf56fff55b548546c3bc3247c72064fa41e7a893dbd734d089660b2627fc672406d3df5bf93643a970d9c91eb5f46a95d1282fe685bc5bf4416be179ca2e4dc7ee6cbe2f6d451964b7ab5b156c17a5c428d99267ce6b85ab92797129404b2c888af3019493e31d6ab5430bc7893bae67bed39fa07f8ed2ad367621b5505ae7fb69f5e8e5220c55d053187a644fe7f38d7aaecd0c32e37aa88b22114a8ff7be7a4962ef7a9cac75f992a22830b302c088b1bc35a6827adda2f8fee8d434e34d0636c4be510d5db2caf51a236d294871ae73cb78c69a5aa7a153e6024d59badffe7ae51307a403f04bb7542b45d6686053987943b4bd3b3aced3f0922572695b27766465c63d082b565b289b2f0eed6fccad2d408e2bf8fd2448a1af9d6481f8370397142af864b477d67e26ed63386336d75db9c0fbee3603cf2149b099bb489d81fb68e9cf1877e9ddb2f017e8c847a63e2ef36e70f39f31d71a8938dff1891f0331b1ad9eab10890e45a2d605435529fc2b1514376e3867b1dd18e90ad0716baeed44a88122b7d2701085e7a7dd4e4c736cce1054fd4de586148665e344999c3177f549d2a81b504056bfacc3ebaa1ef9a9b9eef5eaa344637be151ab95d165016056c0857772bd84e2986fc21994378120e4aaca557768fd93c5e37610424eb76037870428a2f82c90fab3ab469d860d675ddf0dba053ad1ed48610e82f3f279fe4a2415727bbab960119689827f60453237d82c1c52f67a2d8175ddc7d1387f408ac47bb71636c6253c9eb39772244c59cbcfbcdbb38b040e4c9964028f38183ee7facb1ff036e59a0f4908e364991650bbf764a6299db78f1b464071c3f9c677700b1027e1762a52e49ddb1fd6abce7dbcd3a8307ac86318dce8328fbc3d562ec4b185206c8166f7bafa496911f07116da65fd569b1d2badf4212310f2a83efe91e8ee81946a012a5d4667d4d5a5db57085f19d3f096e537be95b8a95df87cb379508b9517d588f79d9d1255b49cdc238539a7d19cfe38fbac8979a9b15eac4be7518da66358202147898b36ac008be52e2034c4ec9cc6a8747568424c57ed6a464221a24a011ac8421554e9de014b1c68775bd3c8c36c5b6fd52ed224f6eec475ca4edc6555192ba16d2faa1e4881a75ca217576bbc9ca1fe66300829e7e31afe90d51b1e60e7b87dc20e99e8e5e4c48b124b2c163c78cc691a89a8f451fffc2ff675d843ad77f78b023cd9048c4dfc42c05df461bd0b6f598b1dffbf423c71616b6dc1c39f9658419e85a3b4bd67294d0b0b339f772f21c334cc69d254118b72a41f780103530ba86e2fa511bf37f5c43f2e1fbdd4ab0d8b8a2c3f9271af53fdf0663ae9c322ca991bbd61f6a2e3ab29546d0ff81feac5c1d49753d957c9b51f7858b80234f1922f1f4c741003013d98b2b3252fe4995f38e51146059f1fa03b55b25dd1b97ec09ee9945bd3d3570625eade6ef8f91ca2912aac9c16a1533f71125d6283fdb87f3a4b43375eef7fc98cfce7b09b791a1cf3a7ee23a7c906428206385d81154ada991487cd5b499d27cdd7abb5d35e6301b28dc8a576c40ecf89af6d346ba6ad82faba6384289c0733c857864548efac5a455bfc9fbdafec785e9f273433e15091eca06ac6d4f757ce6835f8d802ed32e71f49c409a0e5a72f43020ad1c147d77f3824f9ba5d783838dcd7018ad92fad5c5e183b76d2b4c17fe74040800836e7b65e900f97657d3ac7d5ec1cc4523b7b4c04c56b1d636a39a4b464718af62a9e60fe24d7c1ad32f7b25adbdaf7e106458003a0df099871337aa945630459bd956f13c6f8bfc5c499948420daae77f829a89820479a59852803f4a2c9277edcec48ab19c8d361b50094a1ccc3fbcb15c81cecfcf14e1ddec2afc68a09cbc58e8deaf22b19245f39c656d553718f7d9f76fc7cccdb692b88b4c89eec0c30d616c67c62268828af048239d7908e3c879785e78e476ede1c88145d5f2f4fa735893d2807eb8ecd7c85d5cf68ff73fea9fa888f0a78b7e28b568bd52cdd659f9da2c3e1c7ab9ae764650eb9fda974641582139bc2e1c454dcf2494ff7bd618910a16c48520f8fa627a95ca2ea3f09a7d98677ff89f8e76112eef92616877aba421290da3bbd1f65c1a231eb41baa4fdbd5c614b5e811cebc5fcc776dfd1a8cc5fef558443155ea358904f74bb80919e252dd59f7ac86074de64618a4c4665debbd8cefcbbbec7ee40dd397dd9804741477872a31a563d99af112016170283b011e8a76a2d8cf672a544337dc44a2188734ee8b3394ea5f23648e1372e10bb9568738ba8b4ffad1e3da7bc182a1695dc52b8532f7c9dbf9b374dd43fd2b9dbe6b5ae3355d23af8b53e4342f9f14a91b47427d6555316c29aad952ed8be2cf9b3db39eef0b43956a1a8b3d4b8782e7e91e6f386aec10a4d2b0946c4e91e91a98afe7f64b593406e4eda08b3f2f5b87d50765a79b80d1dfd75ce44f3a4bff4cc84240d9e9d53ccd626e49577d7bd0a031f145bde5dee68107aee936065849c072018489affbb639ea8653310afa6e5b59cc2cb4fbfa9d3662b48e77a1be5e740991b8c24972957ee807349210f014a86e39c6fd6ed6a675f57140be5c65d0ee9437617b815c7b3ced803375ee127f98fadcaed85a69cc00c88ef697ad5f2b417f87dfca24e8b9e8bd85c4277d4cfa62c036272bfd2dcfd27605106a914207aea9f0f2fa5c7fac83a220312c311de08f2649e8dfdad9716bb5c013f2e9b86774279207973486bdc7c48e50514e1ad05ab6c3ad6650725f89ad7d6169e29d75659ffc85da2d7712b7774ec0561e0bfe8444bcba3857db67aab8e49158b494eb919d12c141a54cc69c94c2fba1d530ca7420e2d3f83471e212894ef2573aa7260c4fcb9661b761ab8e926d47f7764a81a39aa96318b77c669d089f6e323c2316597952c7bfa54efb6af4a8659c8eec6c59b16f1fbb4c4903e86a13385397a7993b1d371088631e4220efee9358bea168399d1bc473488413dc5d03ccb2b751849ecfc969ef9dcaa4ec76ccb947cac0c6fe0aabf120459ada5ed1149f4ea2a3334b55abb222693c609d6ac834ede76d82aa489a893f0e34a2ddbeaeb9d92daf9ab59451d62dc4bbb948c85877da42505391979f1ef45e891a8988a3aa72e61441ddc978e52d69d51e755133e428c143780525f4b90badc5c3c17e40d491f4da60369045c473a11a53fe009399bb215e71b40433ce0337e803ec071e29a83bf51d419ef77938bf3ae40472e572adb96c24e03ac24af2ee4b44c5b9e6ac3a52fcf4cc105fdd9a89cfe51ed2772b8eb51be5590e88dd34e57d5ac506cbd98082d4e4e1ed291f3be8198d8623103dac5435a9fde0a0a09fdadd98cef184e899b2db3c4e8e6661be26e9aad8fcbc90d3540ed7ca8796b03bb23c9d39344b15f760e3d4ea9b04150df76f1ce7cc42b79b3395e40edc5b8e4b3b9733fb4c5f4d9c463628d35f489d9d1154febfbfebc75c95b3fdaf4a4a9cf20630e380802555d32c3b31920cc1f9ef1ca729718785c7883374a81557c29c2dbbf7cbb2e08ccad582feb277ad0311c3fd5e0b7745d155d6e31c97031cda18786a6c61b0014c702c1cb95cadaf939722d6a7597f940dfae86d314e36c39cb211b805d142ac8f6b104e28d6013324dc39fba570d87e0440c9e2a12067f1725be6e0819de6ff688d75600caa7dac54f4a21a97f9c0c6320678146eccff19d7e21cf9c7fbee30241391294a9af99fd8347ce482944257ae0d1c8f7db5c8f3cbe078637681aab5eb370f2635e3fc54191baf4c7d3ae23b787222a9ff22a815eeaa6a9040ee02a9ebd64822e8e83412306e14eb47c5c65d0f8657b5345810f8a9fea2e2c6b57ade491e10ea90b9aafc2f86489e2512c1e2a2c0af110ec7d8817571df6d49d8e92b3fa26a269dc840f4bb2ebc9ce9d2a694fbe405b26b53f3ef7d2493616c8bba518101b5d77d3e698855394f92823101eb9a28f40314b2052c51a7d7d44f20f16d6f143f49415e0f0df7be0a9159d7cc273a223da33c6184fc6708135a2d5781c32a9cded845ee7ff22acaad70b4a460b94c4bf76e2c9bd9c266ad292515450c271e9bfaab46284473347537fb2e67edab81b36da87a7f363dd8e634b45d5c5cf93439316ce39fa7385fc5d323d5de0a5b32b3eab815be07dc8d57dd5a66589034048e0467cfe23730853fe516688444440b23449448221d79a916f3489a265501d1fc1ddc43e7381b8b9b3a67d4cec2032e4d5ba2384cb67f0a7ef2d65effdcd1d0784c37ea63dc376897562ba8d87f23568809b5adf19338ff4efb50d924981a6e479bc194110a2bd367e541ebef23a0483c48b3edd97847fc7d836bd2d030d0d7f060e30f86652e27804d0e5c87ff3ce87f5e7654ec74bd2b045c65205220760fdcf8186953c4793d646d9e0825d2529a50ae1f20996220de159151d90591de4ee975eeeeccef35765ddaed99ebfb84a8c835bcb0c5ad6080a76c0f1ac0ec21e84a9bf5e066de9c6d7adf350c7f0a2cbaa49fae7d5b98a7b70dc9dd6d4803174c6de8dc486de752ec5db75dc085c71655926b143c6d8801bae90420376c5c78c251c3764a5ab0ff7f4ab29d7b107cfdbce4e1e28e421aba5e8f1f9f5fccdca029697e14cd1e4d689bc56bbb8da07146c54e2aa5b88aae80046dd7862a7929f4aa0588116c2485204bf8144527724f83daaa7cdd5e379fddeb5fd78977dbfef143deb5f5b4729f31f8756acae75325028697aac16fad57f295b96c23958df85be9488befb079a82c279abae20dad17b952864d947ecae641e8b02c3040292d59b33a43704c8370b28ffee4aab2f263e3eede0004d762c353e098039290903a4a420b2cc8a47b1dadd4f29831ded5ea48dca5c510a2e1243c42a25c0cdae9404549d6bf7c769fa93c8defd7e2604ef4661e95b9f2048fe961f666250f6d5dbd19a29a48134e7c147325b95f71bc8cbdae69a7dd57610c220d8df37998299fc76e2b15c0cb298cda9bf978ea4c9be6734a363e9435af7b902e033670552a008f04c4bf15b97af0a1f25af16baca475c12199644ab1ab224ba7662031f6e847844fbfc09e28458414f9f836e7a362135d0b5370566a79533b658b76ea6765fc7f8e83eda71a15cb9dcfa2eb2f3144b327719250d5af2f6184b09a42daaa4b7e2c0ae0b6a893a4ca55b6f4df09575f62da4028507ebdd2bc827695144ce274bf9b743def9de589b8296bb6721320d4cca3d668800c3d044789fb8149b111a0960af327c087d4885821469e0d295e739d2b80964eed7e4fb05bcc83734d7b7a60229b51a0b7773b9999bc44deef84e53385f21721114f868e877e811b3a6f3a310ac7354160e547b976a997844828ce266f53dfb9c8d14befe7c6d080ef6379f746ec775f9ba9866b071641891550392eea85cdef331c54affd95d1e27a26b19bb42efd14ced8673669e12b277ca49b67b04f5822a41c3c9af6ed8829adb3b42c5a827bf04fb3fc37ce50137d27be1a0efb152545dd64f9616745fc5e09ba03d05535d03e2106a402978fa4a179cc427919e618afcde3bcab947e1dd5fc69aaa5bb2fb9b94b4387dc16b9e54d68c34a09b1fb69336c3df590c51b0b2908020d3141f2150383ce08eb595e33d4f8c3331ad9c73590325e796b974f6c055fe98911c83b16cfba55dca33333f7ca56c84a225119c1584ac61f87c86ca2e20e71b0456c57f570b5bbb897d988980723a8de736bac7f7fffd674a5abef8ed95dedf5e228ca42bef988a8ffe7ad8c23a3d4e85557c5df5f4312613533ec99c63c9b5d596e064f8e185022ca907a3149117c8ab4190045fc5b93dec54bfa341fb71c94b7b68d7b23e6e3a9616cce8a56dd51d54b513a2337b9a2db02df2443e830b5deed309d7ff42d75e2e0f4ad0cb8b54b60","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"731e88edaffa707c0029a6b34fd23319"};

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
