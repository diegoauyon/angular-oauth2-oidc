import * as rs from 'jsrsasign';
import { AbstractValidationHandler } from '@diegoauyon/angular-oauth2-oidc';
/**
 * Validates the signature of an id_token against one
 * of the keys of an JSON Web Key Set (jwks).
 *
 * This jwks can be provided by the discovery document.
 */
export class JwksValidationHandler extends AbstractValidationHandler {
    constructor() {
        super(...arguments);
        /**
         * Allowed algorithms
         */
        this.allowedAlgorithms = [
            'HS256',
            'HS384',
            'HS512',
            'RS256',
            'RS384',
            'RS512',
            'ES256',
            'ES384',
            'PS256',
            'PS384',
            'PS512'
        ];
        /**
         * Time period in seconds the timestamp in the signature can
         * differ from the current time.
         */
        this.gracePeriodInSec = 600;
    }
    validateSignature(params, retry = false) {
        if (!params.idToken)
            throw new Error('Parameter idToken expected!');
        if (!params.idTokenHeader)
            throw new Error('Parameter idTokenHandler expected.');
        if (!params.jwks)
            throw new Error('Parameter jwks expected!');
        if (!params.jwks['keys'] ||
            !Array.isArray(params.jwks['keys']) ||
            params.jwks['keys'].length === 0) {
            throw new Error('Array keys in jwks missing!');
        }
        // console.debug('validateSignature: retry', retry);
        let kid = params.idTokenHeader['kid'];
        let keys = params.jwks['keys'];
        let key;
        let alg = params.idTokenHeader['alg'];
        if (kid) {
            key = keys.find(k => k['kid'] === kid /* && k['use'] === 'sig' */);
        }
        else {
            let kty = this.alg2kty(alg);
            let matchingKeys = keys.filter(k => k['kty'] === kty && k['use'] === 'sig');
            /*
                  if (matchingKeys.length == 0) {
                      let error = 'No matching key found.';
                      console.error(error);
                      return Promise.reject(error);
                  }*/
            if (matchingKeys.length > 1) {
                let error = 'More than one matching key found. Please specify a kid in the id_token header.';
                console.error(error);
                return Promise.reject(error);
            }
            else if (matchingKeys.length === 1) {
                key = matchingKeys[0];
            }
        }
        if (!key && !retry && params.loadKeys) {
            return params
                .loadKeys()
                .then(loadedKeys => (params.jwks = loadedKeys))
                .then(_ => this.validateSignature(params, true));
        }
        if (!key && retry && !kid) {
            let error = 'No matching key found.';
            console.error(error);
            return Promise.reject(error);
        }
        if (!key && retry && kid) {
            let error = 'expected key not found in property jwks. ' +
                'This property is most likely loaded with the ' +
                'discovery document. ' +
                'Expected key id (kid): ' +
                kid;
            console.error(error);
            return Promise.reject(error);
        }
        let keyObj = rs.KEYUTIL.getKey(key);
        let validationOptions = {
            alg: this.allowedAlgorithms,
            gracePeriod: this.gracePeriodInSec
        };
        let isValid = rs.KJUR.jws.JWS.verifyJWT(params.idToken, keyObj, validationOptions);
        if (isValid) {
            return Promise.resolve();
        }
        else {
            return Promise.reject('Signature not valid');
        }
    }
    alg2kty(alg) {
        switch (alg.charAt(0)) {
            case 'R':
                return 'RSA';
            case 'E':
                return 'EC';
            default:
                throw new Error('Cannot infer kty from alg: ' + alg);
        }
    }
    calcHash(valueToHash, algorithm) {
        let hashAlg = new rs.KJUR.crypto.MessageDigest({ alg: algorithm });
        let result = hashAlg.digestString(valueToHash);
        let byteArrayAsString = this.toByteArrayAsString(result);
        return Promise.resolve(byteArrayAsString);
    }
    toByteArrayAsString(hexString) {
        let result = '';
        for (let i = 0; i < hexString.length; i += 2) {
            let hexDigit = hexString.charAt(i) + hexString.charAt(i + 1);
            let num = parseInt(hexDigit, 16);
            result += String.fromCharCode(num);
        }
        return result;
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiandrcy12YWxpZGF0aW9uLWhhbmRsZXIuanMiLCJzb3VyY2VSb290IjoiQzovVXNlcnMvZGllZ28uYXV5b24vUHJvamVjdHMvdGVsdXMvYW5ndWxhci1vYXV0aDItb2lkYy9wcm9qZWN0cy9hbmd1bGFyLW9hdXRoMi1vaWRjLWp3a3Mvc3JjLyIsInNvdXJjZXMiOlsibGliL2p3a3MtdmFsaWRhdGlvbi1oYW5kbGVyLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBLE9BQU8sS0FBSyxFQUFFLE1BQU0sV0FBVyxDQUFDO0FBQ2hDLE9BQU8sRUFDTCx5QkFBeUIsRUFFMUIsTUFBTSxpQ0FBaUMsQ0FBQztBQUV6Qzs7Ozs7R0FLRztBQUNILE1BQU0sT0FBTyxxQkFBc0IsU0FBUSx5QkFBeUI7SUFBcEU7O1FBQ0U7O1dBRUc7UUFDSCxzQkFBaUIsR0FBYTtZQUM1QixPQUFPO1lBQ1AsT0FBTztZQUNQLE9BQU87WUFDUCxPQUFPO1lBQ1AsT0FBTztZQUNQLE9BQU87WUFDUCxPQUFPO1lBQ1AsT0FBTztZQUNQLE9BQU87WUFDUCxPQUFPO1lBQ1AsT0FBTztTQUNSLENBQUM7UUFFRjs7O1dBR0c7UUFDSCxxQkFBZ0IsR0FBRyxHQUFHLENBQUM7SUFzSHpCLENBQUM7SUFwSEMsaUJBQWlCLENBQUMsTUFBd0IsRUFBRSxLQUFLLEdBQUcsS0FBSztRQUN2RCxJQUFJLENBQUMsTUFBTSxDQUFDLE9BQU87WUFBRSxNQUFNLElBQUksS0FBSyxDQUFDLDZCQUE2QixDQUFDLENBQUM7UUFDcEUsSUFBSSxDQUFDLE1BQU0sQ0FBQyxhQUFhO1lBQ3ZCLE1BQU0sSUFBSSxLQUFLLENBQUMsb0NBQW9DLENBQUMsQ0FBQztRQUN4RCxJQUFJLENBQUMsTUFBTSxDQUFDLElBQUk7WUFBRSxNQUFNLElBQUksS0FBSyxDQUFDLDBCQUEwQixDQUFDLENBQUM7UUFFOUQsSUFDRSxDQUFDLE1BQU0sQ0FBQyxJQUFJLENBQUMsTUFBTSxDQUFDO1lBQ3BCLENBQUMsS0FBSyxDQUFDLE9BQU8s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QzVDLElBQUksUUFBUSxHQUFHLFNBQVMsQ0FBQyxNQUFNLENBQUMsQ0FBQyxDQUFDLEdBQUcsU0FBUyxDQUFDLE1BQU0sQ0FBQyxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUM7WUFDN0QsSUFBSSxHQUFHLEdBQUcsUUFBUSxDQUFDLFFBQVEsRUFBRSxFQUFFLENBQUMsQ0FBQztZQUNqQyxNQUFNLElBQUksTUFBTSxDQUFDLFlBQVksQ0FBQyxHQUFHLENBQUMsQ0FBQztTQUNwQztRQUNELE9BQU8sTUFBTSxDQUFDO0lBQ2hCLENBQUM7Q0FDRiIsInNvdXJjZXNDb250ZW50IjpbImltcG9ydCAqIGFzIHJzIGZyb20gJ2pzcnNhc2lnbic7XHJcbmltcG9ydCB7XHJcbiAgQWJzdHJhY3RWYWxpZGF0aW9uSGFuZGxlcixcclxuICBWYWxpZGF0aW9uUGFyYW1zXHJcbn0gZnJvbSAnQGRpZWdvYXV5b24vYW5ndWxhci1vYXV0aDItb2lkYyc7XHJcblxyXG4vKipcclxuICogVmFsaWRhdGVzIHRoZSBzaWduYXR1cmUgb2YgYW4gaWRfdG9rZW4gYWdhaW5zdCBvbmVcclxuICogb2YgdGhlIGtleXMgb2YgYW4gSlNPTiBXZWIgS2V5IFNldCAoandrcykuXHJcbiAqXHJcbiAqIFRoaXMgandrcyBjYW4gYmUgcHJvdmlkZWQgYnkgdGhlIGRpc2NvdmVyeSBkb2N1bWVudC5cclxuICovXHJcbmV4cG9ydCBjbGFzcyBKd2tzVmFsaWRhdGlvbkhhbmRsZXIgZXh0ZW5kcyBBYnN0cmFjdFZhbGlkYXRpb25IYW5kbGVyIHtcclxuICAvKipcclxuICAgKiBBbGxvd2VkIGFsZ29yaXRobXNcclxuICAgKi9cclxuICBhbGxvd2VkQWxnb3JpdGhtczogc3RyaW5nW10gPSBbXHJcbiAgICAnSFMyNTYnLFxyXG4gICAgJ0hTMzg0JyxcclxuICAgICdIUzUxMicsXHJcbiAgICAnUlMyNTYnLFxyXG4gICAgJ1JTMzg0JyxcclxuICAgICdSUzUxMicsXHJcbiAgICAnRVMyNTYnLFxyXG4gICAgJ0VTMzg0JyxcclxuICAgICdQUzI1NicsXHJcbiAgICAnUFMzODQnLFxyXG4gICAgJ1BTNTEyJ1xyXG4gIF07XHJcblxyXG4gIC8qKlxyXG4gICAqIFRpbWUgcGVyaW9kIGluIHNlY29uZHMgdGhlIHRpbWVzdGFtcCBpbiB0aGUgc2lnbmF0dXJlIGNhblxyXG4gICAqIGRpZmZlciBmcm9tIHRoZSBjdXJyZW50IHRpbWUuXHJcbiAgICovXHJcbiAgZ3JhY2VQZXJpb2RJblNlYyA9IDYwMDtcclxuXHJcbiAgdmFsaWRhdGVTaWduYXR1cmUocGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zLCByZXRyeSA9IGZhbHNlKTogUHJvbWlzZTxhbnk+IHtcclxuICAgIGlmICghcGFyYW1zLmlkVG9rZW4pIHRocm93IG5ldyBFcnJvcignUGFyYW1ldGVyIGlkVG9rZW4gZXhwZWN0ZWQhJyk7XHJcbiAgICBpZiAoIXBhcmFtcy5pZFRva2VuSGVhZGVyKVxyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ1BhcmFtZXRlciBpZFRva2VuSGFuZGxlciBleHBlY3RlZC4nKTtcclxuICAgIGlmICghcGFyYW1zLmp3a3MpIHRocm93IG5ldyBFcnJvcignUGFyYW1ldGVyIGp3a3MgZXhwZWN0ZWQhJyk7XHJcblxyXG4gICAgaWYgKFxyXG4gICAgICAhcGFyYW1zLmp3a3NbJ2tleXMnXSB8fFxyXG4gICAgICAhQXJyYXkuaXNBcnJheShwYXJhbXMuandrc1sna2V5cyddKSB8fFxyXG4gICAgICBwYXJhbXMuandrc1sna2V5cyddLmxlbmd0aCA9PT0gMFxyXG4gICAgKSB7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcignQXJyYXkga2V5cyBpbiBqd2tzIG1pc3NpbmchJyk7XHJcbiAgICB9XHJcblxyXG4gICAgLy8gY29uc29sZS5kZWJ1ZygndmFsaWRhdGVTaWduYXR1cmU6IHJldHJ5JywgcmV0cnkpO1xyXG5cclxuICAgIGxldCBraWQ6IHN0cmluZyA9IHBhcmFtcy5pZFRva2VuSGVhZGVyWydraWQnXTtcclxuICAgIGxldCBrZXlzOiBvYmplY3RbXSA9IHBhcmFtcy5qd2tzWydrZXlzJ107XHJcbiAgICBsZXQga2V5OiBvYmplY3Q7XHJcblxyXG4gICAgbGV0IGFsZyA9IHBhcmFtcy5pZFRva2VuSGVhZGVyWydhbGcnXTtcclxuXHJcbiAgICBpZiAoa2lkKSB7XHJcbiAgICAgIGtleSA9IGtleXMuZmluZChrID0+IGtbJ2tpZCddID09PSBraWQgLyogJiYga1sndXNlJ10gPT09ICdzaWcnICovKTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIGxldCBrdHkgPSB0aGlzLmFsZzJrdHkoYWxnKTtcclxuICAgICAgbGV0IG1hdGNoaW5nS2V5cyA9IGtleXMuZmlsdGVyKFxyXG4gICAgICAgIGsgPT4ga1sna3R5J10gPT09IGt0eSAmJiBrWyd1c2UnXSA9PT0gJ3NpZydcclxuICAgICAgKTtcclxuXHJcbiAgICAgIC8qXHJcbiAgICAgICAgICAgIGlmIChtYXRjaGluZ0tleXMubGVuZ3RoID09IDApIHtcclxuICAgICAgICAgICAgICAgIGxldCBlcnJvciA9ICdObyBtYXRjaGluZyBrZXkgZm91bmQuJztcclxuICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoZXJyb3IpO1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcclxuICAgICAgICAgICAgfSovXHJcbiAgICAgIGlmIChtYXRjaGluZ0tleXMubGVuZ3RoID4gMSkge1xyXG4gICAgICAgIGxldCBlcnJvciA9XHJcbiAgICAgICAgICAnTW9yZSB0aGFuIG9uZSBtYXRjaGluZyBrZXkgZm91bmQuIFBsZWFzZSBzcGVjaWZ5IGEga2lkIGluIHRoZSBpZF90b2tlbiBoZWFkZXIuJztcclxuICAgICAgICBjb25zb2xlLmVycm9yKGVycm9yKTtcclxuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyb3IpO1xyXG4gICAgICB9IGVsc2UgaWYgKG1hdGNoaW5nS2V5cy5sZW5ndGggPT09IDEpIHtcclxuICAgICAgICBrZXkgPSBtYXRjaGluZ0tleXNbMF07XHJcbiAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBpZiAoIWtleSAmJiAhcmV0cnkgJiYgcGFyYW1zLmxvYWRLZXlzKSB7XHJcbiAgICAgIHJldHVybiBwYXJhbXNcclxuICAgICAgICAubG9hZEtleXMoKVxyXG4gICAgICAgIC50aGVuKGxvYWRlZEtleXMgPT4gKHBhcmFtcy5qd2tzID0gbG9hZGVkS2V5cykpXHJcbiAgICAgICAgLnRoZW4oXyA9PiB0aGlzLnZhbGlkYXRlU2lnbmF0dXJlKHBhcmFtcywgdHJ1ZSkpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICgha2V5ICYmIHJldHJ5ICYmICFraWQpIHtcclxuICAgICAgbGV0IGVycm9yID0gJ05vIG1hdGNoaW5nIGtleSBmb3VuZC4nO1xyXG4gICAgICBjb25zb2xlLmVycm9yKGVycm9yKTtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycm9yKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIWtleSAmJiByZXRyeSAmJiBraWQpIHtcclxuICAgICAgbGV0IGVycm9yID1cclxuICAgICAgICAnZXhwZWN0ZWQga2V5IG5vdCBmb3VuZCBpbiBwcm9wZXJ0eSBqd2tzLiAnICtcclxuICAgICAgICAnVGhpcyBwcm9wZXJ0eSBpcyBtb3N0IGxpa2VseSBsb2FkZWQgd2l0aCB0aGUgJyArXHJcbiAgICAgICAgJ2Rpc2NvdmVyeSBkb2N1bWVudC4gJyArXHJcbiAgICAgICAgJ0V4cGVjdGVkIGtleSBpZCAoa2lkKTogJyArXHJcbiAgICAgICAga2lkO1xyXG5cclxuICAgICAgY29uc29sZS5lcnJvcihlcnJvcik7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnJvcik7XHJcbiAgICB9XHJcblxyXG4gICAgbGV0IGtleU9iaiA9IHJzLktFWVVUSUwuZ2V0S2V5KGtleSk7XHJcbiAgICBsZXQgdmFsaWRhdGlvbk9wdGlvbnMgPSB7XHJcbiAgICAgIGFsZzogdGhpcy5hbGxvd2VkQWxnb3JpdGhtcyxcclxuICAgICAgZ3JhY2VQZXJpb2Q6IHRoaXMuZ3JhY2VQZXJpb2RJblNlY1xyXG4gICAgfTtcclxuICAgIGxldCBpc1ZhbGlkID0gcnMuS0pVUi5qd3MuSldTLnZlcmlmeUpXVChcclxuICAgICAgcGFyYW1zLmlkVG9rZW4sXHJcbiAgICAgIGtleU9iaixcclxuICAgICAgdmFsaWRhdGlvbk9wdGlvbnNcclxuICAgICk7XHJcblxyXG4gICAgaWYgKGlzVmFsaWQpIHtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KCdTaWduYXR1cmUgbm90IHZhbGlkJyk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIGFsZzJrdHkoYWxnOiBzdHJpbmcpIHtcclxuICAgIHN3aXRjaCAoYWxnLmNoYXJBdCgwKSkge1xyXG4gICAgICBjYXNlICdSJzpcclxuICAgICAgICByZXR1cm4gJ1JTQSc7XHJcbiAgICAgIGNhc2UgJ0UnOlxyXG4gICAgICAgIHJldHVybiAnRUMnO1xyXG4gICAgICBkZWZhdWx0OlxyXG4gICAgICAgIHRocm93IG5ldyBFcnJvcignQ2Fubm90IGluZmVyIGt0eSBmcm9tIGFsZzogJyArIGFsZyk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBjYWxjSGFzaCh2YWx1ZVRvSGFzaDogc3RyaW5nLCBhbGdvcml0aG06IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XHJcbiAgICBsZXQgaGFzaEFsZyA9IG5ldyBycy5LSlVSLmNyeXB0by5NZXNzYWdlRGlnZXN0KHsgYWxnOiBhbGdvcml0aG0gfSk7XHJcbiAgICBsZXQgcmVzdWx0ID0gaGFzaEFsZy5kaWdlc3RTdHJpbmcodmFsdWVUb0hhc2gpO1xyXG4gICAgbGV0IGJ5dGVBcnJheUFzU3RyaW5nID0gdGhpcy50b0J5dGVBcnJheUFzU3RyaW5nKHJlc3VsdCk7XHJcbiAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGJ5dGVBcnJheUFzU3RyaW5nKTtcclxuICB9XHJcblxyXG4gIHRvQnl0ZUFycmF5QXNTdHJpbmcoaGV4U3RyaW5nOiBzdHJpbmcpIHtcclxuICAgIGxldCByZXN1bHQgPSAnJztcclxuICAgIGZvciAobGV0IGkgPSAwOyBpIDwgaGV4U3RyaW5nLmxlbmd0aDsgaSArPSAyKSB7XHJcbiAgICAgIGxldCBoZXhEaWdpdCA9IGhleFN0cmluZy5jaGFyQXQoaSkgKyBoZXhTdHJpbmcuY2hhckF0KGkgKyAxKTtcclxuICAgICAgbGV0IG51bSA9IHBhcnNlSW50KGhleERpZ2l0LCAxNik7XHJcbiAgICAgIHJlc3VsdCArPSBTdHJpbmcuZnJvbUNoYXJDb2RlKG51bSk7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gcmVzdWx0O1xyXG4gIH1cclxufVxyXG4iXX0=