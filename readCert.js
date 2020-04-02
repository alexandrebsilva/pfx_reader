// References: https://github.com/digitalbazaar/forge/issues/338

const forge = require('node-forge')

/**
 * This function receives a bas64 string .PFX file and return if it is valid, including password, and return issue and expiration date
 * @param {String} base64File 
 * @param {String} pfxPassword 
 */
const checkCert = (base64File, pfxPassword) => {
    try {
        const b64P12 = forge.util.decode64(base64File);
        const p12Asn1 = forge.asn1.fromDer(b64P12, false);
        const p12Parsed = forge.pkcs12.pkcs12FromAsn1(p12Asn1, false, pfxPassword);

        return { isValid: true, validity: p12Parsed.safeContents[1].safeBags[0].cert.validity }

    } catch (error) {
        return { isValid: false, message: error.message }
    }
}
