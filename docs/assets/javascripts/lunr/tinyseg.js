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
                staticryptConfig = {"staticryptEncryptedMsgUniqueVariableName":"f7a80c92f6d5378eec0b7dafc5f49e5f8346c91aed83d6c290abb76340193af7877e46f3dadc9da0bf6198e7499adbfcade3746a0b37dbcb25e3a42e7fe6eb11ac103fef9f5b98988b7b45f72fa066dc85dbddebca533fedec0c05d789136a8d9dd9ed0831f79c4a284b52c12a8c93bc4e6d3dbea196333c674c8657a766f9cb2c2e09b8210b6b57d0cf267819b1dcc15d7210ae276ba87f0092b415805ab0f415a92191ef4d4837ae69ba4a88d5828757e7570da4879c6e4d080c3fcd8756e66bee77944c22c368d69ac281a3f0e100ca6cac6f7ddb5708a40c1db6f55dc860db28f8aa81455a1653f0bf094944f1f51462428bf9fe7135728d73d6929eeae3da0dbdda8b9538dd2e9616204df7d2e8c90ecf393ca0706c8c87838113e57c92c3190174748ac6e4aa123f3b879f67af9420a912e31c2802882e7cd83d30d10d467cae1026665f6c06f54fbaa299a49c942d9bcc6013ee10875a1ee9c0bc37bdf65e853f0d8a531c010bd63b6c2dc0dd0dca7256a53ef8523066aa9b4183c78ea6f0fd731377ac0139968b939935ad57f03fe7a108914bc8a0322bb4278bb3136c4bccdeb94c2cb8dee7d88b3fce7f4b408f69663cfefea3d9fa7f6dff20482a53390f4ba63d19ade2156687696248b99481bc44067c135eaf75ff2721855e46e86d14e562df3ad7e86ef872137f5f2928eae38c62f1a15b503e3bfb2d2491f4ce0b9487f7081ddb8e03d878928f3324fadc9385b5685b38e8213746fef323fb5e129bf93bdfe06e67557dc8beea2c0f66cb8958c57d099a47bd784f832b883960ec6a5abce62c2608d4b695be2a169ff549820422ffa7973e44b0ec5a4bc45395ddea1cd94d149adcdbf361868df088d458a498700c01b88afdf64e77d33e12952d09ede0f18319245015d56e6512116605d8279c69c061f168b2474724741c90db25b8666a6761e8f220d03d938fb7dd20eca9237be00c068ff81b3c2c52a5d85fd0d3db664bf07143de458fc78239417a1188ebead69639c798d2ef1200ac023bb689242671d528412ee0f3ff9d819495aa32fe7b840fbaa1a4f472a4b67e82040ca1204c087628ba53e5149cc409d2d6b1ea354467f8b781af153fb9abde4c78ef8bb4bd7a1c8dd707dfcecc666db66083fac411ef21fe996a67a8f06d0b5ddea3ee929bf0cad9b351a23677e703ae6f95d62754ee8716832cb98940f06c69f42c9fcfd971f7ab395abd1bbcfce101b42be0d4cdc1e329140150a2c7f53f7f290195c035adc59b066bcf3c17914baa03046e8ccc71ee53b37fa60bb27869d7a640450b9da18c36da008b2031fc5e5dad0a78ee913be79a8feefbe1519702d0958e02e9a77024ebf4feb18a23de824885475426568c0bda99c0315f6be5e7c0f435a2b06ec473be67555db908f7c3b140079080fc63f703f4b70b68db5244398ad80e871884d8bd19d907e015a4167871ded933844d973e37500b44e64c3765c96b0d71c46f8e489b28f8ea53a09f5b58724b252888f1803aeeb8e26a2f7949ea14b99b587af91943ec32bc423bf1262f4df23c8297aebe81bb425f92e7c3f5f0c29db63203835221c0fed48a94e4b0c4bc2980d0d98d264d8187346100201ff3b6edc647caae12bfd32aa99e6d4d812dc70ad19cae19b41cd8199dcac817606fbd622c9c8c9d979afdc72d51adf0fc49ff6e9c2d4cff78f05867301111601b026f923a4ddd316de08898feca00637795a0d3fb84e94c683cdec208facbf41085ecfdff8be010f4e05c685b3e601b9b58c977c93ff935585111329e36c682eeef778639c9319020ee1ed7d02cbf1a71d9b0f6d8be80d6e965e6463df90b96e4b633047bb356068d630efb7901f6c887954fdf8cdcde6cc048b66fe1d8a0b56775e8c92ee2ea05125a68d132c2a0c52752a39df2abfc36581afaae4ad7703f62bad149be3dc20214de2123c7bd7d3d4793016aaf0975aa3d49ae0a5228da285bd2f706a536ecda1b69b799a3a3e0ef7c0735d7b2f58e3a2ffbe2b648ba334ded6a38bad3dbf801002d3a1b16539210cd801d18d20e9a0c167d65adb19ebf638aba2caa046dcc317521810d8c94c391c647b820d5eb164079145f49073134572b2eb0262616fe90c6516cb2ad23c474e2cd265bf97a9560a581216b65c5964fe10fa220398f1b3ca973243a0e7a8c3749e347e14af63047451395c37313db2026558d39b075e327a34f9b619017942227fe34ac5a05cdbd39585838573b0ade2a348c76a9c947bab29d6d6ed55a0dd568f29566fbea69dd05552ab54b3a46e680d1552b3ba7037e15e599d74da2bde00733fb4b704b259d44c46f7d7f19e5752e1fb9051bf17c6fb4a9b66c5b89c023c95081fca669b90e63e82a9fb7f9cd78343cfe5f86150162003308379f6c335f77f7f62fefc876c5752b20a40d83378d6f63a50c9889d3692b788203f531b76dfe779fb62d3f40f74d712ed8e29c86a8d271f279383d8e3657fbbbd1f98f7482c3b75ec8dedbb15a131af3d0a0c9562ddc706a5e0eeb3d548b24f81c4d4efa184b8e03aae01d7b1acac20bada40423c173230d575e05f7ac6eceb85e4daf956628252e4b2da5ccee40af843414d17df4bac7b0e39394e9ed137fa312132fbfb9a67501fecb5a271f3830a0737e5cf0fcde07a7481e20f462c7b18c7b9e6c231fa65069d463322a3e587d2f7aaa3462ce20eccc7b3e446133db998b2a7329470fd5971f92dd8dc31ac6705bd47467722db1b9a76e7af8c3581436ff6c49a3c9659c7d1276c6427a67c356c40747898f42e962df9438e6e0fcad6cb928c060bae13351cf9d10195b5704db07f1a01d5ca0ca0a618d36c2dab28ac2a7b2c548da1f9f4e8b920d9310e9e7e03aaebcb310cf59c3877342bf8e40cb570d94c59042831443f5d695e3545fb375089637ea7b76240d4aaa54e1a9a3042c050da17ae0c46c89cf6e84a1ee366bde73e07ed8031a91ad6edc0332a0c9ecdc497695bd4fccf1c9170f35fbc2e0c84b95b20aed75de6e3e8eb5aa3fb29d5ce5ec88c511d72a19fa96b8f94ddb0f2c84edfcf18857a4ae7d10c9d30183e85cd046e23edaa78282dc24021a607074512dd1ad134c5615b710f5756205674b621e4a3e9efc7e0f9ccf2a5482047164aba6e7c32a99fda6db48b5a9cf8a36508239b2f709b7bbfbc36196eea68fd64310da8b24a4e2d5a3febb1922b1316ed3749f39617fb3af7b37b6ec114fbe6328ca757edc6bdbc63429f708cad6f80741447dfafd458d8fe8b56ba2b5aad121f705dfbb3e73d958bcaa10d30dc2be93239bf386288f28b4f3e09dda68991606e1444436ae67e27adaf6d62fd776b5ee77fb13ffab52ae7c7a8ab1072c37b1eaf9439f1564a1f164a4b964e0e401401e9cbc1cf79f1f864756f66c1d8f34acca96a35149ec73eb7c486cb832fa6f6c864fe4af18b812acf1a1b7c53ae6c674ef6c5a5658b0aa951d4d366052c3971da1707adb0455b71fb9ab95e892148c34e3283c2614e54a932c865bfe32c70f098691d4ba931923efde14f77b39d5721858ad78ff0e13f3fa95dd2b47fb87ea2d9b836716c3a8b5b708cd1f651b631d1e6fbbfc98015d83ae9d095ab4c7bddce63216c34acb73e8bdca00d2fbb79adc8205164b44f84b9a84ebdf9c2c701b2c0570875b45c8eac258d1afd5577fb68d6e34ba9091d56602da3adb5dafa68c44aada38ebe757d468f6aaa863ff02d2d350d950290a9439afbe9c2632a0a3e77f93454886c52575dbbf4c2e0d39d495debaafdc425be9fa5792a2a3c55eccf8c7027c4fc69b2c98fcc805fcf36424cb88d6335bea0ddf5293a50bd63703401d0d6d9858eccb90268891e96c1bc60d2e73f3b1699aa3a71221b1a51f5bbac0dea655c0aca5efbf87a8c5e206d9d0cc2029c7dc62f242a14a3b44c49513ef1cca0bed0e48f693427bb509883c76928950ec6876dadf324410e6e321d8f64196f7400a028968e9cbea5624d2efbed69f6c9250bdbb99d2067bd4a7d946533047716554ff572314b7ff871eafde4b4cb0ace107d4093593662339f8790a69d6a291e3f1b2deac0b80b5783f7c6845962dcb88dbdbf5b3d7233e2fbbbef79743ccd380a2b32c5f7c645c7986f17a74df8962df243829dd49d80fd85d6981770da50cd5ffa95b3a3450b8aa71997e22a279aa9343c8eb6eafe0ea76cad3c9fac55e00cd89767a228c3bc66459adcda3f58676b7de55cd9eb61e0c499ebeb439ccf03d207cee7ca679d9cdd5e4e3b6274e9959795fdc8658492fc619d3830f59d309045e5febdb859e77f088ef406d2641d33663df0e0956c6bd5cd096003480bbd6aeeb630baab1643397b670f6aaa8542364400374afcaf7d371a899a308d1912ee7397aacaed0c2f739fc60cd572e0fef25b2a054d303a65eeb83ccc06988f08a4aa0bbd0690b83749780d3d7081f49ccf76fb5473e53aa67617cfdbcdab4e97efe98a7db1d63b032c6627cff9bd5b59937b0f5c92e4c14bf4f5e40acc9766c0d98fa617af43fa9c19c3f1692b351d47e85fbf59f243b61a78dcb3c1fd516082b99985c110e59228d37dcf731089e4ecb6a3a63f0c3c5ad17b6d8fa2505b4191eaec39efe5e9f28414e2bb89cab7e3772a5e88a50c56871174a659dd89c74a4ea0ce8ca85e630d89c63732fdb90b0d099af50dff363623ef7797b12d2c0c96c75ae62cbfa7c0c79e224c18dfe6942cd1ba0a96a36ca2a6df4f959d14191726c29fc2559308d487672f641bd5e2361b0498438017358b59ea9ebffc5526b9e1dc0b47000e67782155934c2062f1e921829ffd4b1ee041f323802fe302dacd500ecc8e991780a5aae9956c079a3664b9819e4537572c345542a516722e921a583fd4d744b6a1825ff790a30abf1a3c1531e2485f30435523b5b198b582ed05f93e11bd5b8b35fb0d67a621bc30cc0fbcd081caaaacda2f228e0e2ae9a904e88c2d08a9f0463b3c6f7f0efdae626e30981274c352e4dca0a6015ca157e24cc0e1dfba22451d3458dff513e32f0d49e71f9504fc97199244f241b721637481d1dce557e6a076767929a43e4305c9a29e9c2a2f282a5dd297e4d3e6b08ef3d7315c2fbd14540bfb4b32cac5dafde181919828ee605e09249ea7a268a7e74667a885f52cb8ab4f3d9939f7ad1d6c16bfb67c0eae51efa04619bb084f10fdcd0ffcdd90893137278e59e0729140c731df480f6d6d73e065d001cd0e01ffe18493b009221ba189fe45e7e206bf6b8dfe412c7b6870bb79aaa78a5f5e34b275232900fce4a860319410025699af0c0f9f05b92f2a7847d14dfe5fea3c8d9c987ab6cf1998c740e6f022536e248376c4d7ee62c766fbdef6718629d785faa175ab71c0cd5150e2d3fede90cef654dc71b8bf040522c81aa7b5ea6e3098944a8de01e059f54b3e13d02e832d93dfe124ad5669e37d36a94b2de3edaa0005033b3fd19952cc843ea5e9d9d0f8d8300dee239d893b67dfad4732063fd5cfb1f832d0bd01fc8cdd07d07bfbdbc3c164ecac4d0d28d99db16fdaf87e40a70eda38cbc7ed749d13f837f185d6f2c442735d531344aae1683e3a3d8ce13564b96285d7f9fb6ce23d3dfa704ca009f03d2aad21ff2d6b700b0e20deede37baa7081f19ba6e2d93e7f685c081f7d167cde125af23d2fa5aa01bbc461efb21f6f7deac417582e4d425ec38178d02ac4c18e9b99685e992701d032b88a8fe91a31498da5a6ffbddf6049c9f58322bdc93ec6d8db7216ee17fd9e585f383d262af4f28b3ba4bf2d2b2e225318fe664b7d39ff946766ed1e91a020110f56ca2f3e68baa407a3d3f7c339f7dba28371246434bb8bf0ff34197f5b31cb6ce7d944a03dee5cce90fd10328bd07a584b97caa0e1005049665796f99e6342f0cf56f2b2159f2747a61d915188366af4a36177e443844ee1a44d0da5d4687e57525d4bd4942c72eba2c543e46c8b79035d4c497461d2946e710be3f2997e48f053e851640d19d83f9ba61503524b4cdb0408a97524c4282f7a3f0914cb35f0e97f75466a8a0c6aeb8de3f02401bf34e4e45ee5d83e17508e1eeab2f791dc3d9e859938b4c0af61b5f710f07fc1ee9f844e108ad74d42d75fda91b4e651d981ef140d2339fe9eadfc09c44fdb2f32fe428a7b20ebed74716eba6d274c49f49f70ce7d349e6782f336238b54376fe037422901c8ce5e9f65c4fbb0108e3ed79c64a63a741a3f1da9daf446e4a4e946c60e5e1df93111fa6cef240bb522f341babdfc131ae252981987f2af096ecd5e443e43e58ae30fad00e1d3e9da37f5f76d4ee945d98fb79dd2f8de710846d32c21468a3cd570846356863aba2a179e8a751ec7842e834c733f9988fe295675b0d4abb82cd6daea2cab47a76ce552a746f0db41a063440d0288cefe24ef0d415ba4dc794e2756d1e1112e3228dffd9cd60b1d0124d84fad038e2f9eee4d04e96745f0d1828a949dd43f17571f9e5c8fcaaa81356b9af301509e32197d328d7fe1461ababe89958c921030428076305c63e290cea02b60b830b193314d0f1f5792284227af3db71d0bf97e60451ef7304e13abf88c6848a51a1aac8b3dd5f171af7b88b3854fda81d364710b0092d1ec2b37cb3a2e4bda9b49fdf66b1955ef908af5ec0129cd0579ae85a9bc2d3f143b92c47553bb3bc729445cc042e9eecb8c9a4a2013e20ab7b2a99949d5ea7359b99dc93bce61930ac8de97fb219c3575ac4c66b8485d2b3a8ae0c015a4c97d10a62fe7911c4b91d6aaf740014c5632b502b0072de14277855ace85b06cbc85f55fadbe6a697ebf85a5eae4ce2248bad44cae360501715ddea37619309293b9c75c5a0eec94cb58aa636452ad62cb1bd82abd90382e6f72745bcebf97953e39a75d579a21e93f463e4a02ddebc0a867b27bb8eb2976559d623871a10bce5f03ff6c97a5b03a9ae02f390e5add46e9f667cdec833aeb1e239956a47d7c51c3c01d623a8874bc92bbd8efba08cc29600135dc1af77d033e7ca018467a276212191cfa0c1e3791a6120eb995ad746effd6160a0b3367af53d170eeeb06f5bffd06384b27df9d5aefd650dc701c394f62b7a8809b9b7fbd375966f5630dbdfbde2953faeb7aa38188e2aadfdabfd72f378c52199b0b0a8f87c1f0174715ddcc8019d9e6cd9ede9e9487561826bb7eea3dc0b7bac58f9c8ae9bd828e05968edc3ce157288a56b537499949a3a7c497478437a214094e9531544e1f73807c53adbb4082a7ca5022eca9361747003a5408a0f2d1b7967bea3afc756de9f02e1be949fe5cc06c64762ecd2db3600278866428182ab4689c7cc0877bc46d2e63bc3d47011f87e0ac6ca8c4a788d43252d7116bfc4d5916df6a38e6b35af057e11a5c4aa91cc006a3a4c486f2a987bd4616ccce919d0fb33722c5eed4007eb2318152bd2d581c0737ef6e12589a7573f4caeb34247283670a8f5de1074b58e6aa07d95589b9b1252ee132798b56211c43a98873c05e736a02a34f4a183927d4a710dfb420e2c1e053c431bcbfd35b3a5512bd34923c9887ada458c3d9dcc34272f59028c9cb9c5ea64d102cf27c3183e8191ad41e4d5faa2b682d0b43afb238489c25b20786348ad3a8bc67cf0e1670596e6b3f345120b5df33fa43cb79d383fa508c38273a080979dc3e7108b90906ba72f0a5ce9d819046aefd2e70687ef97292d2b0d686c01e4b3866aec685f35f6afff6bd44dc339a7c805859dd9dd8ac9f64cab8eec7206d9606c4e64d16dc5f571f0813e9810280cab1049627d3b372c56ca44dee5f704e5e749d128bd708e2c5cac128ad290c6a2e3b89607a7d37c1bfadab7d21c538ad9ea3fc1700ead1b0e8e5b551ff0cff525661679950407a37df6cbe0c5b74ce728f3fe5ba717d9ac4384790890af0a17fa920ff0fcdfa51be43124d45c17b0c2916dc285db4ae3ae7757b15e9d912dced0b7e393ffde11a8fafebb2223c71927cfcbc493100bc3790d37f1eb9cc1f85bb7b9c40a81de2932919c6102886341e184dcac3cd7fc8634da2277619a1b8d557a42bc5fb0774b0d2952aa34ca8b02f04428af47ec602409942372b73fb2663e7bb4757f2f81349b97b83255358732abdeba5c7dda7e00b5a4f5541bce9e1ebd388460e0e301d3bf68b9799a5caf718be45f84485fb5c038e1ac598809adf12f65c6914078361fc72c195f86fc681389cbbc6dc37d4c709fc16f4df8dc04fb52ab052ff7f652a81b2cee318949d632c3bd9d8131c038a6cd1c83bae28d58b9823ca18069c5b4ff7d974d9e99f6d9707da0eccf811d1f0d6efe4ecb6c2cfa0ef1f3f6875802b29dd6a1ab4ada99f64c9710adb47e8d0d169ab179260734b3986f1a0ac26f817ee2ea903fe5bd9dc1aa384465a962eea81a37a5d07588c017c635c9cbf8cf624e03797a361dc46c56fe1a86abfd35a0f8804c8fd2dfa0e72f57a0f71ab63d2ef84e3eb6edf4054dc8d4ed4300760a9e700023334f20bf7865ca306b7c6b3e0a45f09a81511a95f7d7e823d5f00043976aae1fe8a251797a08ac5f22edc828e59ad6b7fbecb8837b69454a34bba33c0ba4570fa7200a25120459a78b0a8133d81a674de58cb33d3ef796fdeee076c39563047cf54b68a64d4665e2ea739897b16af62ec9d9a3dff49d181af89a2813fd0f2e18e07528461e77fd0a4d693b77df573786eba6d774063f63bd824553c1aff3b0cb676e6f9b6c930658a95cf9e0fcdb4ec76b7011472901458ce07d1871768adc9e83d15abb54835bf11102b7aba062f8ef55b3944930416d870d44a2287a85665a583da164a73e56ed597200842bf8e75408b3bb403f50f275f18f6d5d521f5cbf104cfc9e67b70795d67445e0a85ab86abe5cd21f8575c00f084b89b4ef83e0703e09325fcd06ef4bdc663b170e5acf16bd4673c925ef99db3abae1ba11a34ed73b8ce6a40c18d387ff2c39bc14e623a7b38c7c32d9c5ef2fdc460406de7c776c4062fb16b7ee1b2612846681a63e3046d1ca54999d3de4e5d38b8b8e3299f5b65e66d68af60d112773de45eab2c3554f6a7d67eb1c7c47ea4783a684837410e7b483f7242e7ed890f7aaef2b1370edf63eadb275a35dd2fcbda6bb543013d661e4656558c63b8d740ecda3ce640665de5e6e26ebe8b9433a8e735c133b6a60babc703e713ffcf32a6d6855d971a41c9bf871b3a6ef351ae9f453bfdc85c1f6d49fcead1bcb0b8d4a3cbe268c4c6543e13797f4c10627863412a27621d115c19ea7df0a1d5bb80b80723a1784ecd3f80f67fb79bc4bfd157a97288792d3f0b6f4eebd198e4f241ba26601ec6d754a92d709354424581b0b5423a9b3495e0ad5dd7c2a593ba835424472f079cbc354c3731ebe4eca91b54e5e89a2a1102564ffdfb84bae62f6937b6f9055f3f7b89bba36436dc759c5227630364ddea8f17ad8a0ce86bb0d04fcf0055a8c406b6489ee68323e2ebe063b0fe64d3013d03f5db601fd509145101fca6e7f2b5d5e72c07b4ee5183d7e14360db9e4fbba0524bb20c0aabd7c386bf41989cd0805b524076f56acce358ce77052203c6ae4764810cad0221d1605b81c9edf757046d09201c5c64822d5facc999b9ecd05715401ca119b681a125b45a4d4b8b56973363c7f32de4d7d1192446e5e5d13a3b9ebaaa8fc74ed8cc2873c9bb5e4a355757abd2b77a74912e354d81483ce84a115ba2052a92e04e654182d05e5d516124b90dc5f012161614950d6e49032a0d53e00fddc1e79084726a0f7416bdf754f79c3c4b511fdd6804015ee27785c18ffde0ee648fbc05354e71e83e5af25049af2e51d4522252a297ed07e59d54b48ca9fd153926b56482425d74abdbf33ab751ba14ee36544f76455368b4bb000ea407f3d4d80360cde1e2caa35f2b0060e1e5d5cfe3b086ed0305c276d262a48900d22513f6077d86d0a01b799c7a9b6043acf4b2c589fa2816833ea4cd160a47dc09b0aaf23ff9af431c71226fd57697a66d2a524b4d4528b9c7f7effaab730cbf868f19a6f314331b9816552402ab136ed8e8cd4844c0076b205cc02e08cef74d595d8c06850522d109ea6af8fccd11e7c13c24faa52b47d7ecda0ff94631ab67807167e23cac8b9a06358d44b6a8bc5bb8382d1a2072193bd81c9ef82ab3d8a44ca7c5ba02dc4d6492a877e9d02c65f8b9a835d7ab4f8eccce83122f62aa240440707d34d6476df0b2d9f326432ff6640abc1efba75bdd56171800c22846fd864a15e693c3ef2d08b641442e5d8afa1663c096deaf01abc9f054d1849fb89e37f8abb2977d7fc82d90966965ab44df36a0fa989ef834527e67aef18a80ffd8d68cb6ac80fca4cfbf6383cd3428ffb2683c556d083eb63b60ecf892f3cfc1449926d91e6e02fc808ef71e0a455a073eaaef10b77037bef91ceaf67c1210828199ce20dda2f2e852870ae22b5bc4cab3adff5e1c0541d67f2c167d443c90dd32d1c0403a02595f722a63580ad2f958262030a22f7a496e2e42b90ca48a683c6fca97403243b08368e9ee5548c7492012f3f3d34bfa3b19503c3d27d90319fa04c8f600b4c257044a117ab2ad4fd848d794654c4c36e4a6ac6f862dbdbaf49ea759731806917b1ca8a10dc11123a04ebaec8335b1db15a5469b8a50bccbbc337f2ad556bbccfc044a1ed0a4c742ed8689b6f464ed0cb8ef0c5a922bcca474807960a45ec4483827bde30d255590a33a3cf2795485ef1fbfa0417a76a1fed714d472d4258bcb31c626d40a4e9352369b80d2aa8f7de60fff44dc7b5d5b05159b5e5d95d7509926bbe0f722a5bc4a9ab33008087d2e808aaa8f006cd33629f9536233a8e29cb814a96cc55792365bf939395cb9a3d67c38cb8e6f4dc30e37d654ea5b820a7e54787a429b49cb8bcce612bf8bb4a4bbd05b72768ba9862cf3eded676733760d562a004513253ca76f2a35a3ba48f252436a0adad107c7c3015a6f57550841cad47240e991d5e1b06c5ad4ae943b330a00e1bfec0eb507ca8051761ecc0c4f55560d72be79b420b21b0aab1c5c1caef137ac482e1c77411761a623ff79763749e8da97a11a038569502c156cfb82efae27576969277cad17d3643e3e659520f4e3cd24deb631555694528635b0032fd28a92edfa8ceb6ba6a6f53cbddcf9ba4905b0fdc7daf73657c376f3733dbfaf99d6936798008c5bbcd481ce906bcc264fecac15794f69edf6fec74a2ffe362e6f77460ab4844a842c6a1bb05861168f6a80e7ae86b9ebe80fac53f6ac477277bfce82b29b7e4b4ee917db6b36535505e0669af3fbf3afaa80409986bb855297e994cf9c1add5b61dc00ad73373c6b984c97cb3b1144ba63bb227d92bf97324a222dbff5993450f6683e8be026506a77021c58cf266e8aa270edadea55b6ada63e8977ee2ddffc2fa08f1286da8947487eb494f3514afc4876d5da95f3adc09e38c1df6bbcfcbdc897459bcf13c3dd9214abc8e5a2a1b0b7227e05978e81344cdd82ec6e063d8e79a96366ec2ee0ab2c03e2c6708c7e635b4d11d15445e635d7158ee0f75877e55bd55186f4d6328735ca470143668cda14236a760c2b638293b9d2f3689bbe5569d481b53e09932a1de462964d2b0ff25c779135220a30cd5ec4a7949d58245a3bcb96fe06caee8a8a519082c550c1dba3686d2fa5726ada5383c6aa121dbcf360b8a9efc9a427181ae3d01b137a89e69ef8d8eb5f524f6da7b72d60f0af6ef00b47d1750f8a32450f8de1c2c98485ecdd495cbd0713385f8893287478e5f2a4ac6f579da4b297c5f4926105c28e315f20a2b2f317d00d6bdb9a2f0682cdb3d1fc641052ac1b087ea5cf570b9de973d027312ce6f37f30889cd1fd95fee483bdb3742afaa4fdb5c2e6cf4ce363d1140c6a58daf94fdff724412aee770dc782f30efea3958cb5c7b0a18057bb4fb7ffcec389c1734bab9b3e78939fe1f0060cee227f2c1d1cef627996e2c7efe2a1f591d0066e4b1fdc510244e890872a055f30f62be4e78dc993cff909a6adfdcafb943ead53b516691d6e4c9422f4375e8ee19f3936d2bcba8dd8c0fe86cfbe9519a92f5c1d98e1f3788b5babc23157c084f04bb1dc900b19aaa9701f6c4c80b8b5ede2091efdf9865dee5bd2da1a6413af8675a02bbd63da19fc6a7c738d12bea1a9ca13af0df8cb55055c0dcf08cbb63323fee46bfea28b6e3370565536a582d7eff6faac38cb5db1e17189faeeacc0aee200a10f40f7d93d16cbb6c5e278f72367f09bc3934856b6c923a1584335db007d17d2d454f0905143bf1547c22702e8362792d283dd9e65788abc11dfc6a1928f348dddeaf2e839f555ec3b71f3283641edea0d77fd4e2e715b3f469858e3e1af9cebb3323e37a738715753d3bc383407f77a197b7920b2ea05cc1b03ce6c9b965a82a8a91a72eaf45dc1ee74a3de466c864c0ce55aaffd9565d5df020b014c0c128da90627a2aa211dc94f02bc9fb225c32b260e6392a8bb9439d808c654351c5efbbedde7b7cdcd1753f7f10ecd3bb6f7874887d2f82b80b23edbc7dcccc29d82380e861a06cea3af035ba58939b2ccc7c804070b6e73f378fc34efa46cf5e783c2602341e8153e1b788445ff696bfe15e687bd71eabaca337aed7b6e1d60f7ff1b3c664edf0eb93e671b969b44d8fbe8a19f8729007e71443142a3d326ad9e06c0ed03c194b8dfeb003c44340e5cb29f08da76fe86f943c8b31ae2907843c5d844501641a7d48e812b30c62e4c5d440bf54844d506dee4975cf3e0368449b7d2100967a4475bdd993d24f7c08c36f4437861deaa3a9166bcae9c5986d8b11a5eac3f59e96e3691edfba2a4e4dc68b1061a3bb603d4f6c57682b648e9e56aa82ff52b3c9373dbe064a1d18e4903db32035aa2f33d181a314436a0982355aae8a98781c20fd58d856aa33272b347042a87b9d0238e6ba8456e4c6edcf1674c8614558ec3a4974d6fcd6df2336be8bb539a96db5d3783e80928f2ea8ebdaad4aed2d055729db8ca89f2bbc2cd135a047d2fa2db2ad410cdc8383ef187ae77a4444bcdacdbff4d462c4bd0c040662dcdcd83ed958f15f3fc626c47c2cc270f56080c1fcc388e34e75ccb80bee7f3b0d6624318a59225700148e272e33d55ac3d725ec1241c818be438b7e54a1c8624d9e6325c3fc9a3f4df494f1a9d963d71cabd0177a7ba98211f5ad68c4600fb692779ff9ef79a139edab3f350b1ba6c8756021b8a5abd93105016a1b2f7c4babc5b5a9f2299bb47593a6619dffc7da72214ac2b93447fcc882a3e0ae1c843da9fc50bee6f097fabd52d87186a4f427a300a3b8250fd5fc9f7d081446799273d0ec4d0468ffa39d8669863ea6763d68b3111ccb9362c393639aaf3ea8d48326d01d741d64a11a20c697a8dcc438a69f6264786a81f26e25add4c9502df89e6aa8c21f17d2cae3533bc3ff4159facf7db1da714c3209409d6a56ce11c2fe80d7f59da59fe2ff0f4940ad9da5d666efa0bad9317ba39af39ec2a2f620b60986658f37ab1c7d89ff380411422fa591d5c134d42016ab354460829fe742725a725a98ec9e4f490de0cd83cbbcf71fa24201d1e5b677c27bbd89abe5d0626496b0b00986c1b64a73c21528860930be311eee2bd0f0fca19afddc7f5b785279c228c508ff9ab99163f10e620694c2991137a6998ed3ec2721e4bf336700bfe05630eee60fd663f2aa2d796f153fe1e7310a3c4afdfa3105bacdcf94f83b77d2eec66a231bada9f865c947f82040393b27d0ab2e3c493836a6f5bdadce2e070297d91193317a1e0ea9fcac3683c25c9d735ebe3c9801e6642b2ff40d85fdf518399664bf78869824867b583e001944d1d43451f1296b740864d3b9d57fa4f2080a307c0264cf48525d23aafa9b5cc3aeb9b8ad041191c3d0653875f77574b074095580291d192ea41079ea8cf30ae7b9a392b1e4bf45adbb7f054a6fcac514cf82feca0ec07aa72d030d65f158a545635360b86896a444d1b3d17ac39ed782d9b6cf56eca46719cd10e5e8aab747b1e88735a39ddde6d7d4bbc181a1f850822099abe9f84ac7feacdcb52dff8b18ed7a235cee870bc56c2ac0b6b56fdc9ef700b52e79cd614484bff5283682e27feaefe21bc5cdd303e46b37785de478dea195784d8b23a60ae04a22eff6374e7d404f5e6456b6b33db68247d3ed3ecbec1d2ae77996f9ba4cc92f3592a9f7afeac8e0cda775a7a13cb6bb981d6f7e4b608cfaa339ae5a534dd7577feb98548026864bf79c98cfde3d81d78f5995571d49f827ba71ef80ce4b7d34e779272c481c841a4cabffd0208356da05f848c65b90af1d6e19a31e613e4c64909aee30421ae230ecd143c95a0882b689f0e94b141e28c63fa54711cbda865d304c3556ca506a8e483e0a3eb4117c9713c650fd2b1ffe34606907355f6fab75e53b3cc25e454ba2d7382e5b4cf9727f6a17f1053020d16eb587f5e4e65c353572195b8f313246e0c420d50709280b622643f08d19e2fa3bda2f3af3bbbb0ea72f911267466e5a8f8fc0c9caa9c6ccce6a31069c82c7a2e92f1d2ffcce1ff8edae4e20567eabc79af7e1b491939820d4cf472f5b2b8fc23de6c6205bdb5e7ccc14d7b35d0ca27dc2274e1ac4568033148749117ddfe8e1bc49f589b1209dd08b4de1b4a832b87c97c750562e1181650960c340a753e20e92c1e4f2c3af393cd4b3db9d1e023045e52def4533438e2b960064991d6b37f6477e44a70e2129864f1f6c3c61d0dd44b0d85584c9c11bb15e54c5d0001666d1cf8ba3629dc8ded7ca428476f7e2e7c7bc5d66a325f45243eeed68c5f606bbf1d38df751c7008c6d5035d39c920246d67036f0d93a82639cb09e8f72eb773677eb8980a7cd2dcc0e6f8f27a4bf7584e951030f6ece3597f667d9c62d00ec71415b8421f04ecf2147cd34d72273a497c76514136462cd246f417f3a87dbe0c19b1803acf941e80e849556c985b36fe28fe0f3b4c6e41ccb1daeabcc243c9138d2745124315915be72319dcf619f60cffd9c36d0f2194f6a8fea7111541cbcee96310dbc2f11312eefbe7b9351c534c373a9a105b66165992a9cd0455e4772ecf7c1b1127a2968749eaf40336b99e772af9dab63d2024d215d69197fc6a34a015d55122c0868b51e833f3fd12dc994af08a8a418f1181a3dc2f00d87c37d6201f95c5be831aaecba89ce1a6cc8e7e992bb9f0cfd0837c44c9b044a44a6848ab7146a9bf959f75a5d5340e40b733702d3c5d6beb061667ae398cc2a727e968322cc4b4c9019bc4c3b67561c8763611fd78d5087a255bca280053a4023ac9d5359dce645e8564693993936e662e456b9db82848d3a9e0def80246031ce0a8c270bd21e781e221886abc7946d3a8e25a77888ac13a36c7fb41ac40c6ec93ab76a89c900d9326df1b0494ab74a7cb6594f91e12a6c9fb7dca054cceda14bb104762a00d11da8121df2da39c9cc7e463893eaf6225fd12e196d9e98ae4270012bdb7d0bd9b8b8a32e97e33dd1bf99520d6f3f531303b65fa318d68321286459a20a5534b5fcf8490aef116dedd80e4d837f38ba825c4472755452d8688883342383a0008bd1a1173528c7867b4813609281d90de5c0d635d36665b6c09007a07c5c3b63d169e4dbc91681291b042feffc04fb885afeb2889ef308d36cdde9f25e4c4becb005d92958a3057ebf2c7ef6b08f016b80baf37e74e3a0872879fbb3aefc73d0c0a3dc5518afca838c6c6221238b784c13e4730c7b086f1627962dd5047314bde483904f7a46967d89571e78518bf6c5c0cb039885df8d89bb727d082a083ec15d7235698ea27d457ab231363147afb0a4a203683579d87aff0911ae555d37c339939a3689766065df05c6ea3c9913d97b91ca33ae2ad39f052e9e84b95663753f33a3442733d19d431742c40282a654bd7733e2948142bcf056f5f83fe34d4c4cec5a48531d8a3825cef16ba7865f3b786c64c12de1ddb9e73f251adc7c153358ac407c8fe17c580bdf142a5078de770f9a9b5f84fa538f37dc72964e0e1e8f8dcf0e9b11358ae86fe6001cf2261338aa174fd480e36805811e0a27d1616b6f3db8130e4f98e074b3d20afce4490a5cdc98b9566b14c3bea8d5c7ee3a6dd0708d00599cc44a8fc3204c131f782f773d24a6ab643d89d057e827deafb73900ed931a2390bf0e1bdd61ebe8faccb4b2ac182b5f045f6e3b01546d166b456bcff5c624e13d3d404548bedbb50c28199ba56eb792859e182e1cee972586abd3b009242d37607b6cd19e8c659ef6e0c09d36f47165d3b724d942e5e8777de1c2b9744579baf483a02e53fb3997a6da98867c98cb7155901a03a5e4590283699281937b8e28df7351a87c3aab9b2722b118e1d02c0af6dd2c048c69cc0b83d7214a508107428699d2af60c126bd7cc85d1200d4b3d677f7b9d42c8639beeecc8434e122b3708833912f856ca1339c44e3339e3831a2de3f1add6a91d4fd94317716f8dc0b6ea4a906c51638dbf16cfd216e45753db10394523ae84d8c7faf974359d0512fc5d2059dd311cc49b6b278a0a0066a2b1c0e91473e26e467c2c5e1903b2af37f3a7afcd64e1fe18442c7cb97f023cec348ee894ff4149325aacc4544f550e4567b9d8629009669a6adf696006d1d24168619b87530c840ec21516554b7d0c0889d9093ddaafcaa620e712d8c853c3e05445e6761af111695b18b45054ffc478b8e7e7f751255aa485a08d139fa6ecd2eee3bb0e0911197da3d7b4d086bb8826d285cea29c940344b10d75da821101648288655c684f98b3344418bd3520a9d2a388b2c39cdf22cb22140a4c6318819a1e91a0a95771c81081e950990fb721deb7afd23b9c766d899eb7a05e16fd5f874e9eff478b3bbda2acbcb9574068601c5d2176f5c0bf3af1463d07a51aa56669fa15caa891d1444f52c7459db3004336d44ff318733d6d46ea152e029d5d71be2231597d8558a1cc04558fe669c9e0a6fd05c362836cae209aefcdec256c723f607cc8a70f342437c02658fb359d81be17876316e5ebeaac9e357fa578a3d3028146bfe9eddc1bae961002c2ef361b84a84d85fbc7e527ce7282343e607ab86f6faa435741eed679810b1e07827e7cf13899a6f39707f4d7beff67b68f28d5ec5408d053a0e65c24dc4f3caed655e9b8810e9d6391122077eed4960806ac2bfb9300a29d616b887d9ff6755e367cda2789953f1954bbf0b278c9d51b65cc59e764662f53a41056824bc536f96242cab33ba2b57237f8d37abcc33b0aa4e3b14f259e9ece4ea3a458b8abb2412b05bb78abb4bceea199aacc5e0fd321bcc18eb9144bcfdb85530d701e600f1cf9078074e938490fe3da59522c803777309c4032bbb3599bdaef65a8d40e0c24563524c023f943278bd8f8105d4dd8797596ccc984d97844c2c6f499ca3887f6f410dc3722585e5f40b775388cfb1b57a0e27f057f62cd5ff074f1d80e128ab6fcbb19dd3c3f1282b5840a3ac2426ae8dad833bc40f15e1f144669c0bb46bd50d7a6480ad34599ecc3c0f93674952ea924f2065acdbd2f17ed47416197af5275e2a0e5d96ef033a9eb38173bb8b99fd1369a61d1804905c5107d28c6577974ebbe4d0fb75cf14bd50ddbba4056c0032043d732ce6b165a08cbaa00cdbbccfc705afd0381f2186d60199290892dbde12877c34645eb65b06b6f2af22beb2c47f6f483d4be1d140996f2588cace5d0c97e8a9de4737670054cbf6c45fd66a15b9f8d0d11b27d193ee08fb0cc05bde152b8d80b82105aa252304aac4dd48aadfa43bfbd89ed234da9e58cd07f10053ed5ce7c64f4d839f2e3411f3becee641f85145bfaa55aa4f0de0154c0699fa6cf62b60ca026d6ab6926d8b55382ce567202bc413268adad4b96bd280e454664bca56e494a19b36df88329cf2893882568aa08ec213facbd825cc3c8f8b1464d991ac6c5219d7215d3d83ea4a224dc990346c5c11d0ea4d0ce5af1a504ffca6ac030d1ab45b48fdeee9f180fcc5ee1f57e1c11df2f6d925f9d9a9b2c099d2de9f978bc7b56df1f88ef17317d3339a1f7b983616736d4764948bc47cbf5e8263255177ca595ee32a553aeb0c485724f1df99f0a1205d3a3df7659148cc94f19ec49305d55359198a9b3a32c145e02a12fe5a8cdcb7817803b1a174a2ca8f9d27474b3860a21c3a1b05fa67c6541b8236847b4edea052a94eb3769c2f8ab553ccad1b1f2b832b6b4b5841fe1daf004df2cc2176d6f4b81c437e1bb93ce6c585649c1631c03958ee9a1d2fe2289fb23d2d34fb68f16d29dcb5c6a4bc5b29707f2dd0c40c562543d89f8b5cc8ddeab24ad17d355b6f3e8d68043d1132f3afa0dc96e35e80cf6b10e409451f4dd4121307b09cb93a3713b2cfb60e2e47395410fc32e90f4b3bf3be337677215f9e28a4d048f80efb303d9952192557d776c5599cee9d62b79d7e8b0ec924eadf4e2d288891f53a3f8b680609b3b2a97348c1e020b13c3166974bcadf697655c03bb4baa1cf25c0294e9bc112a9f3aee97a79bfd8ada755120ef8ee50959a028cdac76d62569c261c0efadc1ba2196b199379fcaee6c5c6a97c2393c8e78a25f4126ed8154d8cdc7d33f045b58c66ea85e05b0140c9c72515e031ceff64a53b18f66cc81336b0161d8c0346eda2d29a333e723aaaef266404de514dd085180abcc3a5ba395e3481209f6690ae518abfad3e3c94dd6ad615f6645c41f569e1c2b61011b724dd56bba0a50af77461488fab2d85a612719fba49914e70ddbc88eede7566a1c87b791ad030bd0c6291e2d2941dd36b3857d2c078e598dba741c0f755b7c493b2706ba8a57c1115c00db6e2fc63a53f2f9ff9cfa1e117931d45bf03f2974330ee085a593287c2a6bc5f4e0db3d36d96a978ebec2d0c688e9f78f5c5de026d5838650f4af03b857b0df98aa49b606673033a2810f6f2607dff593321ae4bdf5d53aec5738e12d83f3a1dbe8c5f97b9c8e2b8b8c7d9630814d945e8fecea700ca71c60c324534de2e735e89e03dc23fe65615d2ed0fd64919708c86fea03fc5bf798f72bdba57ca08f94dfc67f622c75743e812982c11a1d6b96113c18df2b475cf920a400795df79e4091fff097aa9d8b25fa5bf2bcd4b6c78939b4f8a897ff738ef18f9aa4512fb506f6bec6824af9cc3bb44980e4aa0efa58dd0c28bb2973ba9308a1cfd29b02ca25c006321614ae68161eec3b4fbc4df0d2d7b6f0d2b82f63c850b5e0619dcac9a9196d54212c8e5d82e25d0f6aad59b7d56da2ce7ab74691ae47aad8daf5ad645993cc28d135c38c7b708c115837b037ff60ee67b39e4241f1edef73a74325880fbcd5b1bd7a16b199f91da03b1b55182dddc58f2687138915a2ec387761aaa451fcbb51661edeccaf68f206bc8b4ea3e958ddbfbb77cc801ef1b6fa83a0e06241fc18815e56054684844ead2c5d3494a10005ad50140990e6b0690ab63ed0c2a1dbdbb78e26a733656e8c87549e53ec5a3d0ba47662b862877c10a81d50892bf21137e8051c3d0ebce25eb08d841e03f370058071f79a6d051d5e40eb6944e99c4fdb3974857d8cc3d04cb1d7a12cfe6a537d06e9c1ceb94cccf3b94e3e27f129aab0934b199898f9a34abb0058516a3e200f8a9c177ea71026569ba7b99d6c478ef4abc9099f7e07a0fa513aa808d7dee8bd9ab6364cb073e1c928726d74f592a49f383353d36da21e857a1b1907ea73b2e5b81bd7beace41f6f32dd58ff2fd3c05b87347a3dcde63f3770a0b0046a3aa042e1f60f633f6cad30f35be96c4a06cbbad786327ceb3a08ba86eee00a48008cd57752bb3ec3b558fb6a7767e0b87998c619232dd416f7df285ff0acc55d14821c63691569ec4ae048c192f225aded39769afa757a46c5125adee54b6eb61b49a80c95ed9d19671609013548113b5df0523db56b1f387b48740aeff59c81c4011db12f893c40058046e421dc30d98a60ec5c5b9f95af8270892d349ab2425cb951ee7994446a2eb674ea2ad7a9b49d890eb8e168a93781bf26f335b37e2668ac36051d27729ccb4f852b04da835b1f682875904dd5934a69051a1eccbdd6d53f11935b56196a50fe3288e8c7667587dcd482448cb31dfcb91b767464bb1be06c340a4ebdfa93e67998b41f2b8fdf23c1534c827341fdc774d7a9f769195500af2f4fee604b22d3a4f625d0dd2d397c7676390b898c21dfe00e718ed881f15ca882e0d6423fc9ad2fd43f9f45961096d52d6b82c3803f7c5807a4182f0724f571ab632632e3fbb65b0e8f30dd1dc0abda5fd05282dc88bff79badc4a2245801f38b070e1a15ac3590fd581ac5f8be7ae11a20ef72a641ae102033a6d39a3025731f63d983abe7074c5e10f24034be31deeaac237c35257215fafbc9797c11a0c881a9c640b20df61890cfe29aad97f37dc922a0f9a31bb9b839454b324d9eaf8d39e5c9be15c57ea946d17e68480fdb458747c4ab214fb34a5df05b0ad336dea0a14740b609a319d9d08b2370a550655ca4b147e3ebbc55f695aaf596c0909b4394d87cabce59122dabc9a8760749ce6f07d639f4201a9cf221803f85caf7a03d3e95ec237472b60a0d5ff9ed95ca54a9064a1bfc9058bc9f92a1e612bc2ba6502f54ff8a50cf21e7ef29a62140b4ce62c553cd56dde7430f4ce67e3bbbba3e2ca0e3236821e807c5a1794938b444b26d38282c9c4498b3e91458dd239bc2760f97f436a239e63401669cb9a1b6ed425b0497b592254db83d894ea9ba86221e35c45749cfc56c51260bf4563d002416bc73f36c0b00d840c65e05b74731beb5caa1c709dd1398539ec92f9a9b97142e9de27fe6dbb88d8896f2d82f3034f003b31162371e6e63359523dba61dcd261d5aba6c62bfdfa14e815efbc7352783110fd504b49322d169ea5cd4e17081fe5d6ab69e574df8414034a8304a788f04a578cc156cd983c7abdc3c879d9196c029bfb488cc280493ce366137fab6d97c75ab0c6f963dce944f41f4b2982acde581db804d7985f5b38bb00028d4db8b0a9534e62f2f7865e493c5fe50cefa14a60a431c8a0119256e045a7f28117ad66fce4ecc399e8a3625d1abf8c7a988808b5351e2a2ce29a234bb65e44c4d9be3d0be46064f7f7dcaffa1bbe1ae0b73bfaf5890ce19e1660c6bf7829bd18d70ce61baf36ecccc1291067c4652ea31e5cae989113abb1f551722a177ee1d7385143b624a7c3c3ae8a16f79eebe813676a6c745665957722015b6256f936dc49a4e7df30e69baffebcaacf8379b76fce6cbaaa8dc3fa5c97af975e02ab243bb9e663babbb3f204bd3271fbfefed8101ad284db61d7a0425b8f82543916ecaafc247d6121284f761f7e999ec30195d3128018e40d6a9966659213abfe0eacc4ddc122dffb6034df01ad75da2aa168462104fc8f555b4af037f74dc2956441bdc7f08c8b390906b93eba728631df6ce63c14da8d4eed223e377c913c0759955ffaa635328df753883056b4f3e00aaafc098c9013dad4338d7d0732ab606942c0c2c3ac6531a9ff2a6d5f7f29446902992bb42bea56782fcf32c9a7e6ac574947201701ae866a8288370c23f61bf7e5a51d4cbdfa1c047cb2a132a4075008b7d98f0c64669b2a8f952818736443d8ef68b16d0d4c9b4e75151132f5aa1afb19bfd562a668a8d8f2a040ff22fa2f83aeacafd8f22e78f08e3fbd727c84a38208c91cd032a38c1d2a35ca21635c10c9283daffc57d714a513ebde9992f083b0443135b031365087e0fc424722c1c4e5e597514e9b4cca05be77d70bab6205a5def8d96fdf11383db851d60e0af0a45cdda2b4de35da2e7faef10389163dc718ed8b519905e1d2bee35beff68e82cd220344dd2b9a907ff427992a499bbf3622e69efd23cd34c18fd7fdf83e65e830c8c3ea3c5204b74d96a644c421a746d5357cf9a12f7af4d333ee7fdaae8612daa02ea0d5989537f451a62aae6c00a3baa6137b439a3ff7742b6a4a2c7c1a33fb419caf4640254ffacd40c303b6f2d6ea7a687504e3136a0934bb83934ba196ccb7aa71c564702c4d38981393d2c674ee6f25018d24507ada4bc043d2aaec818cc57e70457c39c64366aa484e7c8d6e9c124ab15af705057cbd5e6687806baa761bd00f864f21b7c553add3e0a0639eaf8d7425648a02ff7a985ee8779dd993134c52c21336fcb7381ef307edf07e4b2cbb35b74812ce7415977a0d5c49b15caaa8f1ce106e47efeb77f7d7eb89bfc6b4c35cbc19a9b402ec5e77abaafdc189d655391f6718ec3d645e0a16578fce837711a3dfc968b5c56b57c41766432f1971c761ea72753a5d8e87cf8ca2097280aef0235350a88e03d4c95523e124cf06045b21d2d5bbecf99abab6cd58fcffce383442836f54a1833c4fe8dee4fe4daef6183f02d5e8efcff195b73b9161a92e18546fd41229922307c068bf4129665bc0959845db875386c75d92bb0e0522106c0a952559049de76531fe421a205231a5ff31ac307d453027410beeffb5483583efd42a9590238afc3ad688bba5d3b27e2c70e676771dc022383593cbcb3995d228e1b2f7b6c2171a1974d6256f5e47ccdfe66c0028b3e3e4c5d4597a1ccd528eec61d0edecb045f69f5b4370123eb94ca876eb2c8054b1e4deb7debca7e698e1b86b0f406aa20fe9b543bf1217662b7968915f2191fd552046ef53c0c36b569f6f49d6f210e4e9b4da87a8976f55a856dde813faa1f1fb0ae08d0489c4a6f95589aa88c42d420406be6ab2afa6249ad87588ebf728f95002fb81259dde8185aef258bce82be6a1258ee7e954b023e5d2178bfedec703c452329c916d2ff89ade193c4e6d908d8c83abdfaba8e6cbb826762550bcd3a726d18fb303bf9a7a873edab505f4fa627021446365fe67adc0b11ec66b4be85612517f8933e8ab96e55856915f6ff8ff426f6e0537ef7414977f33e2da5f39478b95e81905d431de0dc0cb961b0e639b562a3ca2990df0ba7c9243a1063b1d8fa24f1f398aef24cc8ee604ba77e550ac9bd6e345ef82efddafefedb9762911e9696f6bb42031fedae594486c323d65813bd0bb5eef7c16dac6b8f07cda7f372f91bb6cd232412775b6dc228ad306aef99760dc395e261843253b9a8635cfe4b7855bb20dc7995d7458d9947381558d1a35316023ea189e342d3e9ce477c3b97abedd76a2e42e71d4919a27b3b315853cbf4d8c2f905451e8013f4863ff14ff95eea720ce71a790001bdcada3226558b0e6cb32b46aa2c4e3bc13bf1dd2c33ebddc746d91d891440b4515e33cd0497160fa890f8586d068ed788319f45a8159c2a5b6dc4f12904ac438058f0e14cd03e8109373a22dcdaedcf63596b0699678f4789cfb8be7f0e6dbd0060b77125dc7890a50d4dd572160a9ad06400c228614df2dcbf2a334fe56bb386dd598fb7de66996d1ac2339423f3dafb73cc9d1541c6a37b4c665940ccc0f3d94a7b5fb3458a92606e4ec08b01600c2e94225252aa7bc3a9414814a5a29844fd8788b5c754d4ee694f192ea9ab0f03c04ee3d5047d4d386acf35106ce6e3eb6917a4cfaa993e3498885aefe23a5009baf9c85efab7a5eebbfccf34b7dacbacf6df890d461b31077d7513636f7b1859ec0c9d3b7c1f302a3f816e6c63942a549a0d8245bcd1174618689cb2cbc53b0d0435c78eee697bcb493b8fe7ef61bd286afd6863850d1c527a6b26500550c8833db9f98ba40f9b66ccd3f95e0363c6d1fa545c1d1818425ccdb1df68e4933fec0b47824f8a1855c31192fa46987dcd02905e807bb10050caa8a56976e975a00155d6db592e3c4011db964cbc3216c628f7a652d4b859fe09f9bfd77caff8edefbd06f0e46861701a26d272289eb9c4da70ee0a4794742d0a8a4a39f6abfdd4c4aeb4692449cb57548b441ef5cabb129008e4ae5656bacd2e95ca5b8d77f02f0bac330fc6975e986c0319a3d817f3f367f4ece7f108ccc7ffd129de30d5eda0e82fe4e26f64de5601361bb5c3bae5ef6496fe9f83cd51042b849a12ff52c425e7d77d014b45b551c44e399d10fb8c83dc726980548c15e356687a2df35cb0b18a5b2fa254e789d105c7424a58e1ad302ccb6e9465dfcf973cdce301a5887a1924805826c3be4a668c33138f6f04aa6a2443e728cccc1715bc8d4af6d6de5c29033cf93a0d41498678651fa3ccdfa9787322570293c529cb5c5c78993d90b3eb78eb87c9aac3ebb8b0abfa8de218b3a4709a5ce98ede293361962e1d75d22d8c5105da15afaa27d16f850edb9768f55288ec85fc35db5e95c386ef7c56b9fb467c6640c08f7595021c8933bc300feccc91edc71c695bf6e03e12d97d527aa5b4320a6520c45d763febba37b56803fca3cb4f9e7443c66d3b10cb3401b4cfe3ce2cc97dfa6aa6fcfa193a282162f98225c127deb5b63bae1affda13c584a83ef365b1774495fdf2a9dbc147e3a2f858134dbbdf2977db41eac6962c6a01e39989871cb6efdbc57f60afebb1c696eadc70b6c2c55044795448cce71bce31f3623692352fee9fd325a6bae2dbad9a075933a2badc043c4752e89d8084e7145ea111275e8459dacff3d40a1e48b2066294c07a1d398ad280e9bb96f9c22c3613cd4b7e80a9cf3c0eaef3b7a5e3015efb5f968f1ab1be9704770fac91910cb9ad27bd81b28aadca6d6d19a52013dd987bb30ff7cb96ea3c0ad30d2ef7354e96fa9df0dcff0af4d656a7f4b62a169d66ecaa9dac1c2013188a953de132b8bf1dc0b65a21d7a7bee8d447a9e5237e7b30f1d8d8ead2748508349e9ba602a7f3a7a3c4f175a956527e003c4f5b2afed6b617a3242e8ee8fa4e3edf62b8ba481d37c6118398665c63bd20bf7f68dd7d7c552c8ebab19cd6c4b63e7bb11b2d9ac9fe14170de5ce0addb71556c6c4871436c61798b8ac800a0c61a9f185fdc41dae754914475cfbed1ca6099cd56564cc44c8ee32cd5b83c632f73f3309c3b347019104b3b3971747a6e92f9faecec9b0fd6cac75a24f6b7c25ec738bc32494eb5827e9b59fcf68fa2fd8bc61f21f7696c03fb032654b1da048dfba6f771cf580561afb2e7311ca10498cdba6b08f38859fbdd2d345589f126593c0e812667dd0fa8704980cd13d8b120ac59642fbb87d125c9cf9d112667fe11dadc236dc40d801b595cb0480b1e184e601900dce776812eec7ee19aa878a937ceeeba5db9d847762c77f639da53712c5d50e71fe87f1d755654018c8174702dd13e90008e3ae9b3e8c55679538370648fc253f1ad5fa4cef10e5c4b691a8512a439e68be976ecf3ac975d616f855652ba31010eeab6b6dbe83fbc313f59df7a0b8d11fbc8209e5d25a4fbf7b048aeb0cd0ac0c1456b67350b4ab7cc7e14e557e0248b23d7954cb3bc41f18484d30f799faad7626aa3850755734bb024d45944c76b2c04712ee0fd4a2d00c71b7f876bf64617b4a2c4ff6a57b0defca9262c41d00dc99569177c0683f28f0612dc8c629ad7da99f5d65534376ccb88c893ff54ecb36fa4245ae00702de60b95b6bda55659dee9e621aa7d638f89e64498acfa2dc11829ac012ca957c9ce893196de1e2938f851868805360fef182f1ef012622f4f06b4ab2c5521eb3a6cd5d4dc28b9594a183aa52a90591cc9854b5f665897eceb3b5abf9219f1dfce800bcfa9a4f5ca02d415869b7638b859b71e4a06aa43ba7af3f028637632f065d46d56ac9a941b9c2bd0f5257237f0cb30c1ab704230b0ffbf133e71d4420a2dd4eea9c3b6d33f2ff27469bf758a01d1e7dc03a766453e35db8ad5eaa27c4c9b2d45fe33d4eadbdf8249ca978aef9f4f0c5e94d986b795f9a6180037b631d8c6f7a203ab1950e477cdebccb87b5005dafc2088dc86433a18051334127b7dbbdc50bd9647fa30bd765d9f965eee015dc22b73f7cd34ea15f55639a743d45b2b20ca4fe8918b21935cf32a205b526c7d27414143a20191dd51c2af142f6b3d35db74f4d8c169a1f30ca167cb575833598b12257e00496612a2145eec4be7689733c4d2379d4ab0b7c2f8172b628662300d307e0d4d6e2076aba8639bf8e4f514fd88e55a5f7cd20cd5026e698d72d162d055dfbc664999cbd5fe8e1a845e95f92e0e5e03b0bec26c5a173a5bd3a90b3f74688e03906023ef5272ee964e885935f297cbff33a9f4e2d7ecdec71c604a024250470845ac88aba0ef6aed562b108881b2610fcc3b88dc31e96e4c3a1a903ba98169f33517f8fc78f45dc8ed1a00b71ad45161fa854db62b630111d31aff55ead037dd66afa9d41dc5c022e7520a9b7f86b9e7e080d2a984f5e83a5c250d5b0dd734ce763fdbdc71785ec0c51446495adfe11564f195228454483b18368fa449dc01f1898d3cad2856ae1f590878f218932a9383aaa0d7b58c086290bb7638a8d88774e5154a974e479f32acb462b5970f0106e4a9e9f76ca2270b011338c735a953eb94e281086c5445e5d1e7c6b45e08452523b3f4c15da5f241af8417ca57451e2bed0387f72e0640a10570dae5201e9ee114fbcf130a1094c1fbc80100cf716efaffa99ea40b46aa2f82aa1b87a4b2f1fbd9ff840f1ad11fd47e4b36fe9f830e26e99c6c2428f4178c69be0b1ac59d552f764901f16f840a8fadbf4eafc0d5400eddaf0e5b07ca270952d4947caef6701db3dfa661034ed89dccca9f96da4a61710297b2ed9b2081ffa11ca9d095bc13a71c979cf2977debb1a881f5857f0b35d46f7b248bdaea08464f449d5e60f88f2959fbdfa98feb7af0f10e07b40d73414e6cad2905977c82cad921f011601a06330ab2e6d0978826dffea15417c925ff4073cb9b1fa586d9addd27c8b982e20af23a83ac29fc83edbd7815e7507b1f5819952d2cca9f3801d4862ee7424fd7b3992396506e2f9dc08ba08300d2eb4bac36750200ee01b2f5bb0cc4edc7af869f99a3a96bef334b303997fd9c0b1e3064505f01e41668f62c528a99ef1368f1141070dd7f9dd7ac1bc6f639d71e8cc6e1dec4e96ec5e9abeb307cbbdd7e5a11ff25a99e952069b96e653381bf142350548c1da5c07006e30bad517bd448a61f3d52483f626967f0e8d8471e93b465b87a06ce45ffc526bb61f7f83eee55eaf51c1143709efbfbafcfae68a20caa357279cde63b447c7630c6f9ed8473075a22396252f618298879af80408db2f56da8a7598bece9a3e854633be79fe3cb082dc900bfb4bd37856c553a36d6b12fa6855907719dc4ab8151a60698e08bc4607d88e001701c14ccf3c570b8804191bc878c11f309905c074629aab23bff3034a14d18bce406f58130e8539dcfdb7ba6624842060d4c837170cea17f4853ac1446a17fc59279bcbe24062a2d5ae17e3c4e51579748e9973e748372ad8551d4bec74cba3463cfaf952a762dfa7f94cbdfa44cebd3a85ffd325688f4113fbebc963720b546de11cb54fcb85679c19b9ab2935af4848c8a33fa965ee8607f9056ff1febccd7d5be1e87edfb41898ecf8235850acef7aa7fcde2d84d3235c10040df6391529cbde3ad6b1e66a65d9ac95dac57213e3435948f97ef4a077443574ebd34480c10de21de6e20663f14aa6da8f9ead843587bdb2d209677045c4be0a34f43f43e21f13c2654beb28ed883c70d1d916375e5597ebd9076dee4f9eb92bfcc84023a840a7c695ea79aa2faec2bf77b55b0fe0ad99833826aea8c819a6c543d9f805d017b14749b39ac17b13280e1b97b72dd641b9f0190fe002bf03de5657259ee344cdc0a21d02182d43fcb16f2ce3f6a68fce5f8c94355b68dab640373df0124ace48129e13e605c6943b2c734326f2f4c07efbf38cf81689206be8ab568dfa9fb92f8db5940b3c0603125a21fc15c7be88bce5f97f1b32b2f0016661121b9627c0b84d805af09328d3747b0c16a5f933fb2a7480be97ae5b0f303aa3f5109ab2d40c6dfec190af22527374306b0976aea2ab3a047e5fef8effe0ea46e8460ea1be7a402520475ed5fbbec00aa2808cb8cb9dfcbf8b78373eb86f5e94245b09378d0b876c48ffc928d3b3061c4b86a92b60a3f1fa3249146a13304f149be078cce054cbda400016de4e2ac7a6e14673a4e0aaf9c3719447bd6603d72b807d23fd4d02a4b8160fc9c68b5caaf84ed1e3b9d78a587f7f77bc0a8e714081786af7f417961d4201d12c255d662a6458093ffd1f118739b1fda341888d1460fd68efb4920a6fb09a1252b75f58f019db2e43b8a1feb765bf79fd348fa32df81a1027c2dc59746564f2a9eed49f16f5eb4df1e0c65e5d2859567d90c74a51d4e9a034eb814aac3867cfdd677c8827d6846dd9ebb32551d2f87ec108bb2480d17f8a61554eb68be533eef880adf187f3b7fda9d16f6e1dddf8517174b7eaa075fe85e2f5f6f909dfbc067c6597f899c1018b12753c512b67e167fdd6c0da55271bd1a447dd64846c79e5c412dd9ff8c28330c67c390be9895bdac6bb287c3ac0e4976ca7146d23551e6c124bd0af8dd4527898259adfc31467da4ebc1b8e0a5ce7cc8d0cc44c45a67abd4e2a28b9b35a7009f0d86984d4770f977e7d291af13980acfd11dcfa01df73541576b89309859febe932d4230c6256eac49acbaecdf6b86a6bc6343dcbed84986699cd6b2fad0f92367c150b16d93f84662abb07a4c9be1bb6136f31060a9526fe1344ac6a6d29429ab953d0a4453ba0b2f2200eaf5c198127c611a4d637eefd61913c6ebfc2725e98be952eed542658377843cdf1791b16926f9742fa672a164010bb2dc28192afe74c75e0841108032d4505e41bdae286fbcde25a9c2daf9add322af25c242386c4b302fe20c413f7cd992aec276f3f0c9fea36d2ce2dbaaa5369215f60d282ac86b78e4a2c1408244a9852ceb82ce3fb535e328501639aaf70e07749a5ada000c5e477e2b458d06bf8d9b8caaab9ae8fe7bd733bb90d0f908c0a4156bf059ad4af45f7407ed9edbdcae79721e3d591bbca82c345b220c6628ee363c0949a3663db58f43776348986ef0df7b6717dcf41a7e5a25746af17f3b51a611b46c17d2d1c5d9e53ffe85f08264f0585a40cd73c502349ac232106b37516cb242a5dd86bb12883f64fe6e3bea874b2570a4b9e804d6befd89df7e69de9f597e4d329b3bf73277b5e7c793d7048613176ea256c988796cca59b6f27a1fb446854aac69b524dadc94c4d5f560d82836af0eded2f4de7262825d18d664c9e43fce34fd67806755daaaff432ce82d23e1aacc598d85244004174ebac0523d935361950a911d1c23e9929b220fdc87f804fc6c665cfc5206ea6834474b4398dbb01e759c625d3978897d70074e859ad439f963857c14f0d6504c0f4da816efb099f12b0682aa424cd87579315a364d1a287d9b5f7c900e61e0c03a980c749567f7fb78e598182f35d2045a3e0aeb4ed343526deaecedb7ad10744ee9d57218d0a46debfd34e859520fd8f8c49175d0233fe2ee56805714f8b2e8380f26f42ad7fefea073cfada4c57a8b7cb1cb3e1309c584caa663474073e14e2da1d8cf5c926bb186e8324874a348f0d2a08bff41405776b4718fe37bce3affb2db7f21b035e180cb4da9ea0ed31a12227eb77aeef03f512c75d894b2705b14dbb29afacc3e559d1aeb12fa51f25c18bd6df2637ff429095218186a9a222544cfe0304ba4a4f97937f2d71ab28d9ba2eeef53bdcb2822af799c7b90a759c0956bea78979fb906d9e0aa12d8d03d607aa11587389895c95372825c9a0bd64d566f917eb65bb0c4d3297f38efe1bbc424d6af86fee6087e867b66df7dea4bcf35536d8e12756cf1d50b14095ad7d7e16145b40a70e74c8cba4aa978c7d2a6d3be67f90a6f2277c6df1a8dbf82e480ac5bc24ff036394e53e5c5d10cb557c1ffc693be5cef263a59f769d213f1504eb89f215f7348154f7edcd2ca0dd948c21bb234878bceefd102d41027d438f6af6faf2e2676bb631b0fd8c9c0a32bd4579a76c3c5a99b38465a8a5403094695ebb3535fe40c6bae9563fccad0355d2b68cdd38800e3df93e6a84c67208720289a1b67780faf59c6b36ef9ebeddb3118f08ec9a6bc4403318fca01a053f4fc2feec0e7c29da0fd2d757aeb21a96a0598b5a21c611c40943742c457bae3a032df6063de8a65c78abe966024349d31205d59df01256ea2c2121e7bc5ae55ff6dbc85eada05376dca88b75a23d0b6998c158996302be78ad2bcdbf8a2e8904c4b9210416325509bffb5868c2dcf8a905513e0dc32d838ba9bc77a5aba1400eef202a01f3fb223cca50ad8b8c2fce9479fd86a67f12cfdd34ff2dc662f23cfc0babc764c0ff77198abaf192eccb4db3dbd1dfe7676b8598851ade02f4558f743560c2f345d591dd9ee81b3024cf849f0e62497e1e9b89abd38ddf2c2c89e9a2cfcb8f627c8ed5ae1a10b6a14d4315cc9b290b6ec0701034af6e5486dc0af200aa319d2bc7805305f4c5ec30d2b58d2fae65fb3b5149a2425b6789c5c2a30472578ed65291affab81eb3f212ed444f7ab746af37729c1fcb74cd496bb082b6784a75977a352ff50da0e2bdfb701b8241839dc4f04ea8a87930c5b6397e9eb7b3be210c760ad12b7807225ee51c6a0fdb545e04917d5892c6ed0f8132785cb4d46d6c440f14410e900b420dc2a6adc4efe64493254be07fe03b56062b4f7ffd16852cb1fea71b851048c303d7d23136cacc952d92c09ab22618c554f38625b88648d883fb0d5b80d5188ca7ce556ef883a75b35207c915e5ae3c3b12b916a22443a7a25f67e5112618cb3640bd95fa7ddb40c66980dda417ce57f9852c057c7da2ff0eef725be7942679ab23f3b398e37ed187b18561ba450530eeaf90e607993ee370df16123ff7348c84433410b4eeba7c0c711abd8a182a7b7064e86528f2d916e71edd583334ad623464ad13ec2965abfc0e31f65431b9ff903d0a2ba5ef58d5ef22c935fe6b89d27d9502b426cdaf2f25b32309bbb75a7d46c1e0875551c4f0428b5ae846ecb2f59b01f80ca3666a5717abc2eaf01c5dcd0bc4ae01844b49607b6562b49fc1b3ed09abb68781b7403b57775a560f169f7f6ba2013f52d75fd1e3a0238866e7360c135fa34a415a6b2ca69d0cd2719e370feb4e4c6ae6b227df71da91754889252809d554cea760939584b938c270635cdd8c5d57bee918a1a21e4480adc1aece32b2dd6cce7ae38e4bc60af7b266389ba4f51491f645ba4fdb6438e0c0c96f6b9b9f5224ca6bb7f53864f652adecc38bc095eeadea02a6ee5f8071e44a18b8602451a563a8b1fda2a42b54668182de1510177609bdad15da4583efe1d12f1b35c2955a8398917bc9ce55db82042111608c0edd5b7b5929d7f9e06f8b47ac0ad3561fb7073ba0fcb65b7ee52f4f02c430a789387aa77da052f98aeecfff9b835e99c23fddb892cc8bb607a9c6f232dbc320b28770bc791b26057906f4c2698d18099d4d74b0f2d79bbbc2c991f991a47ac684301c73de376bfeb08b79ad73de23a67dd5817cf6bda387095aac867fca5953f460a3186d71ffde2b05db14813e4ac92a7adb4e2ab87adaef646c5ff3c1659656994d46ca7bc95c86a356d8fd2dc96cbd740db84b0496f34ac284cf8a6c551339be6a622cf2a5fc7d82ca96c6fe0aee744a087a9e8aa1f8da345e86b7c9fde8a7a3dd473cf3ebe0eeb216606887372a9a6014180f649d1e12d062f67dbd5d65c71cddb95a7412a311ff43d072f5525fcfcccd6d9805e30f7369556adeed512a26a1b3c461c48b52ec084a91e7a5119b105ce12cc853d7330e980b34f8b69e7586172a6b6c8e514b8813cb18bc74193818753dd778be8a71cf72392cfd5bd4063f001a9fa3c97d490aeb254c7d2b2503e4ed71525dbd7b2cffe985ecc395aca53ae4ba0aae58e2350f8ebf6370d94b0783987796614338e52ce250d6367fbb1de4624d076ee90aa9ae23975bf08192358b5750035e6b8fd3b52b0d61f5254440fbb56e581126345eca56dc08d9f91515432a8fe13daeb4a12076e3f02af19d8382e2c1a5c62ef20be0f88214882658f4202e2620cabbc7bbcf45fe485e108ac9754bdb6948d4c8474676cfabd9d81f0b2c47b436124d75da7399419838a1dd26d0327b6e1af9292e79cd26dbf4775bffa59895eaf2e89bd1d256b201bc9ef798897ad214982f88a59862ee4e8823c3c249cb258672b39dc99ab303f2568e56e842ffb9c4bd9a698efe0a2e302c1259e9f811baafab44facfc262687f1c73f3eaa0e137418ffe6f4ddc56c5bed089da73d93a62991d477aec7d6d47b94c9cac189c98e35bc763c4c07ec19fba2270c6025559fae5117c06074c1f7b41b36ba59cb3e2db905ff0cc909acba0602cb0e950148a0c452fe5189c34f02ef8496743d0f639497f2f2e92d6c1f487719ca9b19336689b4f67e84ad64e9bfe18b467","isRememberEnabled":true,"rememberDurationInDays":0,"staticryptSaltUniqueVariableName":"731e88edaffa707c0029a6b34fd23319"};

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
