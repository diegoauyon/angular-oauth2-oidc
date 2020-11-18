import { __awaiter } from "tslib";
import { Inject, Injectable, NgZone, Optional } from '@angular/core';
import { HttpClient, HttpHeaders, HttpParams } from '@angular/common/http';
import { combineLatest, from, of, race, Subject, throwError } from 'rxjs';
import { catchError, debounceTime, delay, filter, first, map, switchMap, tap } from 'rxjs/operators';
import { DOCUMENT } from '@angular/common';
import { ValidationHandler } from './token-validation/validation-handler';
import { UrlHelperService } from './url-helper.service';
import { OAuthErrorEvent, OAuthInfoEvent, OAuthSuccessEvent } from './events';
import { OAuthLogger, OAuthStorage } from './types';
import { b64DecodeUnicode, base64UrlEncode } from './base64-helper';
import { AuthConfig } from './auth.config';
import { WebHttpUrlEncodingCodec } from './encoder';
import { HashHandler } from './token-validation/hash-handler';
/**
 * Service for logging in and logging out with
 * OIDC and OAuth2. Supports implicit flow and
 * password flow.
 */
export class OAuthService extends AuthConfig {
    constructor(ngZone, http, storage, tokenValidationHandler, config, urlHelper, logger, crypto, document) {
        var _a;
        super();
        this.ngZone = ngZone;
        this.http = http;
        this.config = config;
        this.urlHelper = urlHelper;
        this.logger = logger;
        this.crypto = crypto;
        /**
         * @internal
         * Deprecated:  use property events instead
         */
        this.discoveryDocumentLoaded = false;
        /**
         * The received (passed around) state, when logging
         * in with implicit flow.
         */
        this.state = '';
        this.eventsSubject = new Subject();
        this.discoveryDocumentLoadedSubject = new Subject();
        this.grantTypesSupported = [];
        this.inImplicitFlow = false;
        this.saveNoncesInLocalStorage = false;
        this.debug('angular-oauth2-oidc v8-beta');
        // See https://github.com/manfredsteyer/angular-oauth2-oidc/issues/773 for why this is needed
        this.document = document;
        this.discoveryDocumentLoaded$ = this.discoveryDocumentLoadedSubject.asObservable();
        this.events = this.eventsSubject.asObservable();
        if (tokenValidationHandler) {
            this.tokenValidationHandler = tokenValidationHandler;
        }
        if (config) {
            this.configure(config);
        }
        try {
            if (storage) {
                this.setStorage(storage);
            }
            else if (typeof sessionStorage !== 'undefined') {
                this.setStorage(sessionStorage);
            }
        }
        catch (e) {
            console.error('No OAuthStorage provided and cannot access default (sessionStorage).' +
                'Consider providing a custom OAuthStorage implementation in your module.', e);
        }
        // in IE, sessionStorage does not always survive a redirect
        if (typeof window !== 'undefined' &&
            typeof window['localStorage'] !== 'undefined') {
            const ua = (_a = window === null || window === void 0 ? void 0 : window.navigator) === null || _a === void 0 ? void 0 : _a.userAgent;
            const msie = (ua === null || ua === void 0 ? void 0 : ua.includes('MSIE ')) || (ua === null || ua === void 0 ? void 0 : ua.includes('Trident'));
            if (msie) {
                this.saveNoncesInLocalStorage = true;
            }
        }
        this.setupRefreshTimer();
    }
    /**
     * Use this method to configure the service
     * @param config the configuration
     */
    configure(config) {
        // For the sake of downward compatibility with
        // original configuration API
        Object.assign(this, new AuthConfig(), config);
        this.config = Object.assign({}, new AuthConfig(), config);
        if (this.sessionChecksEnabled) {
            this.setupSessionCheck();
        }
        this.configChanged();
    }
    configChanged() {
        this.setupRefreshTimer();
    }
    restartSessionChecksIfStillLoggedIn() {
        if (this.hasValidIdToken()) {
            this.initSessionCheck();
        }
    }
    restartRefreshTimerIfStillLoggedIn() {
        this.clearAccessTokenTimer();
        this.clearIdTokenTimer();
        this.setupExpirationTimers();
    }
    setupSessionCheck() {
        this.events.pipe(filter(e => e.type === 'token_received')).subscribe(e => {
            this.initSessionCheck();
        });
    }
    /**
     * Will setup up silent refreshing for when the token is
     * about to expire. When the user is logged out via this.logOut method, the
     * silent refreshing will pause and not refresh the tokens until the user is
     * logged back in via receiving a new token.
     * @param params Additional parameter to pass
     * @param listenTo Setup automatic refresh of a specific token type
     */
    setupAutomaticSilentRefresh(params = {}, listenTo, noPrompt = true) {
        let shouldRunSilentRefresh = true;
        this.events
            .pipe(tap(e => {
            if (e.type === 'token_received') {
                shouldRunSilentRefresh = true;
            }
            else if (e.type === 'logout') {
                shouldRunSilentRefresh = false;
            }
        }), filter(e => e.type === 'token_expires'), debounceTime(1000))
            .subscribe(e => {
            const event = e;
            if ((listenTo == null || listenTo === 'any' || event.info === listenTo) &&
                shouldRunSilentRefresh) {
                // this.silentRefresh(params, noPrompt).catch(_ => {
                this.refreshInternal(params, noPrompt).catch(_ => {
                    this.debug('Automatic silent refresh did not work');
                });
            }
        });
        this.restartRefreshTimerIfStillLoggedIn();
    }
    refreshInternal(params, noPrompt) {
        if (!this.useSilentRefresh && this.responseType === 'code') {
            return this.refreshToken();
        }
        else {
            return this.silentRefresh(params, noPrompt);
        }
    }
    /**
     * Convenience method that first calls `loadDiscoveryDocument(...)` and
     * directly chains using the `then(...)` part of the promise to call
     * the `tryLogin(...)` method.
     *
     * @param options LoginOptions to pass through to `tryLogin(...)`
     */
    loadDiscoveryDocumentAndTryLogin(options = null) {
        return this.loadDiscoveryDocument().then(doc => {
            return this.tryLogin(options);
        });
    }
    /**
     * Convenience method that first calls `loadDiscoveryDocumentAndTryLogin(...)`
     * and if then chains to `initLoginFlow()`, but only if there is no valid
     * IdToken or no valid AccessToken.
     *
     * @param options LoginOptions to pass through to `tryLogin(...)`
     */
    loadDiscoveryDocumentAndLogin(options = null) {
        options = options || {};
        return this.loadDiscoveryDocumentAndTryLogin(options).then(_ => {
            if (!this.hasValidIdToken() || !this.hasValidAccessToken()) {
                const state = typeof options.state === 'string' ? options.state : '';
                this.initLoginFlow(state);
                return false;
            }
            else {
                return true;
            }
        });
    }
    debug(...args) {
        if (this.showDebugInformation) {
            this.logger.debug.apply(this.logger, args);
        }
    }
    validateUrlFromDiscoveryDocument(url) {
        const errors = [];
        const httpsCheck = this.validateUrlForHttps(url);
        const issuerCheck = this.validateUrlAgainstIssuer(url);
        if (!httpsCheck) {
            errors.push('https for all urls required. Also for urls received by discovery.');
        }
        if (!issuerCheck) {
            errors.push('Every url in discovery document has to start with the issuer url.' +
                'Also see property strictDiscoveryDocumentValidation.');
        }
        return errors;
    }
    validateUrlForHttps(url) {
        if (!url) {
            return true;
        }
        const lcUrl = url.toLowerCase();
        if (this.requireHttps === false) {
            return true;
        }
        if ((lcUrl.match(/^http:\/\/localhost($|[:\/])/) ||
            lcUrl.match(/^http:\/\/localhost($|[:\/])/)) &&
            this.requireHttps === 'remoteOnly') {
            return true;
        }
        return lcUrl.startsWith('https://');
    }
    assertUrlNotNullAndCorrectProtocol(url, description) {
        if (!url) {
            throw new Error(`'${description}' should not be null`);
        }
        if (!this.validateUrlForHttps(url)) {
            throw new Error(`'${description}' must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).`);
        }
    }
    validateUrlAgainstIssuer(url) {
        if (!this.strictDiscoveryDocumentValidation) {
            return true;
        }
        if (!url) {
            return true;
        }
        return url.toLowerCase().startsWith(this.issuer.toLowerCase());
    }
    setupRefreshTimer() {
        if (typeof window === 'undefined') {
            this.debug('timer not supported on this plattform');
            return;
        }
        if (this.hasValidIdToken() || this.hasValidAccessToken()) {
            this.clearAccessTokenTimer();
            this.clearIdTokenTimer();
            this.setupExpirationTimers();
        }
        if (this.tokenReceivedSubscription)
            this.tokenReceivedSubscription.unsubscribe();
        this.tokenReceivedSubscription = this.events
            .pipe(filter(e => e.type === 'token_received'))
            .subscribe(_ => {
            this.clearAccessTokenTimer();
            this.clearIdTokenTimer();
            this.setupExpirationTimers();
        });
    }
    setupExpirationTimers() {
        if (this.hasValidAccessToken()) {
            this.setupAccessTokenTimer();
        }
        if (this.hasValidIdToken()) {
            this.setupIdTokenTimer();
        }
    }
    setupAccessTokenTimer() {
        const expiration = this.getAccessTokenExpiration();
        const storedAt = this.getAccessTokenStoredAt();
        const timeout = this.calcTimeout(storedAt, expiration);
        this.ngZone.runOutsideAngular(() => {
            this.accessTokenTimeoutSubscription = of(new OAuthInfoEvent('token_expires', 'access_token'))
                .pipe(delay(timeout))
                .subscribe(e => {
                this.ngZone.run(() => {
                    this.eventsSubject.next(e);
                });
            });
        });
    }
    setupIdTokenTimer() {
        const expiration = this.getIdTokenExpiration();
        const storedAt = this.getIdTokenStoredAt();
        const timeout = this.calcTimeout(storedAt, expiration);
        this.ngZone.runOutsideAngular(() => {
            this.idTokenTimeoutSubscription = of(new OAuthInfoEvent('token_expires', 'id_token'))
                .pipe(delay(timeout))
                .subscribe(e => {
                this.ngZone.run(() => {
                    this.eventsSubject.next(e);
                });
            });
        });
    }
    /**
     * Stops timers for automatic refresh.
     * To restart it, call setupAutomaticSilentRefresh again.
     */
    stopAutomaticRefresh() {
        this.clearAccessTokenTimer();
        this.clearIdTokenTimer();
    }
    clearAccessTokenTimer() {
        if (this.accessTokenTimeoutSubscription) {
            this.accessTokenTimeoutSubscription.unsubscribe();
        }
    }
    clearIdTokenTimer() {
        if (this.idTokenTimeoutSubscription) {
            this.idTokenTimeoutSubscription.unsubscribe();
        }
    }
    calcTimeout(storedAt, expiration) {
        const now = Date.now();
        const delta = (expiration - storedAt) * this.timeoutFactor - (now - storedAt);
        return Math.max(0, delta);
    }
    /**
     * DEPRECATED. Use a provider for OAuthStorage instead:
     *
     * { provide: OAuthStorage, useFactory: oAuthStorageFactory }
     * export function oAuthStorageFactory(): OAuthStorage { return localStorage; }
     * Sets a custom storage used to store the received
     * tokens on client side. By default, the browser's
     * sessionStorage is used.
     * @ignore
     *
     * @param storage
     */
    setStorage(storage) {
        this._storage = storage;
        this.configChanged();
    }
    /**
     * Loads the discovery document to configure most
     * properties of this service. The url of the discovery
     * document is infered from the issuer's url according
     * to the OpenId Connect spec. To use another url you
     * can pass it to to optional parameter fullUrl.
     *
     * @param fullUrl
     */
    loadDiscoveryDocument(fullUrl = null) {
        return new Promise((resolve, reject) => {
            if (!fullUrl) {
                fullUrl = this.issuer || '';
                if (!fullUrl.endsWith('/')) {
                    fullUrl += '/';
                }
                fullUrl += '.well-known/openid-configuration';
            }
            if (!this.validateUrlForHttps(fullUrl)) {
                reject("issuer  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
                return;
            }
            this.http.get(fullUrl).subscribe(doc => {
                if (!this.validateDiscoveryDocument(doc)) {
                    this.eventsSubject.next(new OAuthErrorEvent('discovery_document_validation_error', null));
                    reject('discovery_document_validation_error');
                    return;
                }
                this.loginUrl = doc.authorization_endpoint;
                this.logoutUrl = doc.end_session_endpoint || this.logoutUrl;
                this.grantTypesSupported = doc.grant_types_supported;
                this.issuer = doc.issuer;
                this.tokenEndpoint = this.tokenEndpoint
                    ? this.tokenEndpoint
                    : doc.token_endpoint;
                this.userinfoEndpoint =
                    doc.userinfo_endpoint || this.userinfoEndpoint;
                this.jwksUri = doc.jwks_uri;
                this.sessionCheckIFrameUrl =
                    doc.check_session_iframe || this.sessionCheckIFrameUrl;
                this.discoveryDocumentLoaded = true;
                this.discoveryDocumentLoadedSubject.next(doc);
                this.revocationEndpoint = doc.revocation_endpoint;
                if (this.sessionChecksEnabled) {
                    this.restartSessionChecksIfStillLoggedIn();
                }
                this.loadJwks()
                    .then(jwks => {
                    const result = {
                        discoveryDocument: doc,
                        jwks: jwks
                    };
                    const event = new OAuthSuccessEvent('discovery_document_loaded', result);
                    this.eventsSubject.next(event);
                    resolve(event);
                    return;
                })
                    .catch(err => {
                    this.eventsSubject.next(new OAuthErrorEvent('discovery_document_load_error', err));
                    reject(err);
                    return;
                });
            }, err => {
                this.logger.error('error loading discovery document', err);
                this.eventsSubject.next(new OAuthErrorEvent('discovery_document_load_error', err));
                reject(err);
            });
        });
    }
    loadJwks() {
        return new Promise((resolve, reject) => {
            if (this.jwksUri) {
                this.http.get(this.jwksUri).subscribe(jwks => {
                    this.jwks = jwks;
                    this.eventsSubject.next(new OAuthSuccessEvent('discovery_document_loaded'));
                    resolve(jwks);
                }, err => {
                    this.logger.error('error loading jwks', err);
                    this.eventsSubject.next(new OAuthErrorEvent('jwks_load_error', err));
                    reject(err);
                });
            }
            else {
                resolve(null);
            }
        });
    }
    validateDiscoveryDocument(doc) {
        let errors;
        if (!this.skipIssuerCheck && doc.issuer !== this.issuer) {
            this.logger.error('invalid issuer in discovery document', 'expected: ' + this.issuer, 'current: ' + doc.issuer);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.authorization_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating authorization_endpoint in discovery document', errors);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.end_session_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating end_session_endpoint in discovery document', errors);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.token_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating token_endpoint in discovery document', errors);
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.revocation_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating revocation_endpoint in discovery document', errors);
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.userinfo_endpoint);
        if (errors.length > 0) {
            this.logger.error('error validating userinfo_endpoint in discovery document', errors);
            return false;
        }
        errors = this.validateUrlFromDiscoveryDocument(doc.jwks_uri);
        if (errors.length > 0) {
            this.logger.error('error validating jwks_uri in discovery document', errors);
            return false;
        }
        if (this.sessionChecksEnabled && !doc.check_session_iframe) {
            this.logger.warn('sessionChecksEnabled is activated but discovery document' +
                ' does not contain a check_session_iframe field');
        }
        return true;
    }
    /**
     * Uses password flow to exchange userName and password for an
     * access_token. After receiving the access_token, this method
     * uses it to query the userinfo endpoint in order to get information
     * about the user in question.
     *
     * When using this, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation
     * fail.
     *
     * @param userName
     * @param password
     * @param headers Optional additional http-headers.
     */
    fetchTokenUsingPasswordFlowAndLoadUserProfile(userName, password, headers = new HttpHeaders()) {
        return this.fetchTokenUsingPasswordFlow(userName, password, headers).then(() => this.loadUserProfile());
    }
    /**
     * Loads the user profile by accessing the user info endpoint defined by OpenId Connect.
     *
     * When using this with OAuth2 password flow, make sure that the property oidc is set to false.
     * Otherwise stricter validations take place that make this operation fail.
     */
    loadUserProfile() {
        if (!this.hasValidAccessToken()) {
            throw new Error('Can not load User Profile without access_token');
        }
        if (!this.validateUrlForHttps(this.userinfoEndpoint)) {
            throw new Error("userinfoEndpoint must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        return new Promise((resolve, reject) => {
            const headers = new HttpHeaders().set('Authorization', 'Bearer ' + this.getAccessToken());
            this.http
                .get(this.userinfoEndpoint, { headers })
                .subscribe(info => {
                this.debug('userinfo received', info);
                const existingClaims = this.getIdentityClaims() || {};
                if (!this.skipSubjectCheck) {
                    if (this.oidc &&
                        (!existingClaims['sub'] || info.sub !== existingClaims['sub'])) {
                        const err = 'if property oidc is true, the received user-id (sub) has to be the user-id ' +
                            'of the user that has logged in with oidc.\n' +
                            'if you are not using oidc but just oauth2 password flow set oidc to false';
                        reject(err);
                        return;
                    }
                }
                info = Object.assign({}, existingClaims, info);
                this._storage.setItem('id_token_claims_obj', JSON.stringify(info));
                this.eventsSubject.next(new OAuthSuccessEvent('user_profile_loaded'));
                resolve(info);
            }, err => {
                this.logger.error('error loading user info', err);
                this.eventsSubject.next(new OAuthErrorEvent('user_profile_load_error', err));
                reject(err);
            });
        });
    }
    /**
     * Uses password flow to exchange userName and password for an access_token.
     * @param userName
     * @param password
     * @param headers Optional additional http-headers.
     */
    fetchTokenUsingPasswordFlow(userName, password, headers = new HttpHeaders()) {
        this.assertUrlNotNullAndCorrectProtocol(this.tokenEndpoint, 'tokenEndpoint');
        return new Promise((resolve, reject) => {
            /**
             * A `HttpParameterCodec` that uses `encodeURIComponent` and `decodeURIComponent` to
             * serialize and parse URL parameter keys and values.
             *
             * @stable
             */
            let params = new HttpParams({ encoder: new WebHttpUrlEncodingCodec() })
                .set('grant_type', 'password')
                .set('scope', this.scope)
                .set('username', userName)
                .set('password', password);
            if (this.useHttpBasicAuth) {
                const header = btoa(`${this.clientId}:${this.dummyClientSecret}`);
                headers = headers.set('Authorization', 'Basic ' + header);
            }
            if (!this.useHttpBasicAuth) {
                params = params.set('client_id', this.clientId);
            }
            if (!this.useHttpBasicAuth && this.dummyClientSecret) {
                params = params.set('client_secret', this.dummyClientSecret);
            }
            if (this.customQueryParams) {
                for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            headers = headers.set('Content-Type', 'application/x-www-form-urlencoded');
            this.http
                .post(this.tokenEndpoint, params, { headers })
                .subscribe(tokenResponse => {
                this.debug('tokenResponse', tokenResponse);
                this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in ||
                    this.fallbackAccessTokenExpirationTimeInSec, tokenResponse.scope, this.extractRecognizedCustomParameters(tokenResponse));
                this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                resolve(tokenResponse);
            }, err => {
                this.logger.error('Error performing password flow', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_error', err));
                reject(err);
            });
        });
    }
    /**
     * Refreshes the token using a refresh_token.
     * This does not work for implicit flow, b/c
     * there is no refresh_token in this flow.
     * A solution for this is provided by the
     * method silentRefresh.
     */
    refreshToken() {
        this.assertUrlNotNullAndCorrectProtocol(this.tokenEndpoint, 'tokenEndpoint');
        return new Promise((resolve, reject) => {
            let params = new HttpParams()
                .set('grant_type', 'refresh_token')
                .set('scope', this.scope)
                .set('refresh_token', this._storage.getItem('refresh_token'));
            let headers = new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded');
            if (this.useHttpBasicAuth) {
                const header = btoa(`${this.clientId}:${this.dummyClientSecret}`);
                headers = headers.set('Authorization', 'Basic ' + header);
            }
            if (!this.useHttpBasicAuth) {
                params = params.set('client_id', this.clientId);
            }
            if (!this.useHttpBasicAuth && this.dummyClientSecret) {
                params = params.set('client_secret', this.dummyClientSecret);
            }
            if (this.customQueryParams) {
                for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            this.http
                .post(this.tokenEndpoint, params, { headers })
                .pipe(switchMap(tokenResponse => {
                if (tokenResponse.id_token) {
                    return from(this.processIdToken(tokenResponse.id_token, tokenResponse.access_token, true)).pipe(tap(result => this.storeIdToken(result)), map(_ => tokenResponse));
                }
                else {
                    return of(tokenResponse);
                }
            }))
                .subscribe(tokenResponse => {
                this.debug('refresh tokenResponse', tokenResponse);
                this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in ||
                    this.fallbackAccessTokenExpirationTimeInSec, tokenResponse.scope, this.extractRecognizedCustomParameters(tokenResponse));
                this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                resolve(tokenResponse);
            }, err => {
                this.logger.error('Error refreshing token', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                reject(err);
            });
        });
    }
    removeSilentRefreshEventListener() {
        if (this.silentRefreshPostMessageEventListener) {
            window.removeEventListener('message', this.silentRefreshPostMessageEventListener);
            this.silentRefreshPostMessageEventListener = null;
        }
    }
    setupSilentRefreshEventListener() {
        this.removeSilentRefreshEventListener();
        this.silentRefreshPostMessageEventListener = (e) => {
            const message = this.processMessageEventMessage(e);
            this.tryLogin({
                customHashFragment: message,
                preventClearHashAfterLogin: true,
                customRedirectUri: this.silentRefreshRedirectUri || this.redirectUri
            }).catch(err => this.debug('tryLogin during silent refresh failed', err));
        };
        window.addEventListener('message', this.silentRefreshPostMessageEventListener);
    }
    /**
     * Performs a silent refresh for implicit flow.
     * Use this method to get new tokens when/before
     * the existing tokens expire.
     */
    silentRefresh(params = {}, noPrompt = true) {
        const claims = this.getIdentityClaims() || {};
        if (this.useIdTokenHintForSilentRefresh && this.hasValidIdToken()) {
            params['id_token_hint'] = this.getIdToken();
        }
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error("loginUrl  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        if (typeof this.document === 'undefined') {
            throw new Error('silent refresh is not supported on this platform');
        }
        const existingIframe = this.document.getElementById(this.silentRefreshIFrameName);
        if (existingIframe) {
            this.document.body.removeChild(existingIframe);
        }
        this.silentRefreshSubject = claims['sub'];
        const iframe = this.document.createElement('iframe');
        iframe.id = this.silentRefreshIFrameName;
        this.setupSilentRefreshEventListener();
        const redirectUri = this.silentRefreshRedirectUri || this.redirectUri;
        this.createLoginUrl(null, null, redirectUri, noPrompt, params).then(url => {
            iframe.setAttribute('src', url);
            if (!this.silentRefreshShowIFrame) {
                iframe.style['display'] = 'none';
            }
            this.document.body.appendChild(iframe);
        });
        const errors = this.events.pipe(filter(e => e instanceof OAuthErrorEvent), first());
        const success = this.events.pipe(filter(e => e.type === 'token_received'), first());
        const timeout = of(new OAuthErrorEvent('silent_refresh_timeout', null)).pipe(delay(this.silentRefreshTimeout));
        return race([errors, success, timeout])
            .pipe(map(e => {
            if (e instanceof OAuthErrorEvent) {
                if (e.type === 'silent_refresh_timeout') {
                    this.eventsSubject.next(e);
                }
                else {
                    e = new OAuthErrorEvent('silent_refresh_error', e);
                    this.eventsSubject.next(e);
                }
                throw e;
            }
            else if (e.type === 'token_received') {
                e = new OAuthSuccessEvent('silently_refreshed');
                this.eventsSubject.next(e);
            }
            return e;
        }))
            .toPromise();
    }
    /**
     * This method exists for backwards compatibility.
     * {@link OAuthService#initLoginFlowInPopup} handles both code
     * and implicit flows.
     */
    initImplicitFlowInPopup(options) {
        return this.initLoginFlowInPopup(options);
    }
    initLoginFlowInPopup(options) {
        options = options || {};
        return this.createLoginUrl(null, null, this.silentRefreshRedirectUri, false, {
            display: 'popup'
        }).then(url => {
            return new Promise((resolve, reject) => {
                /**
                 * Error handling section
                 */
                const checkForPopupClosedInterval = 500;
                let windowRef = window.open(url, '_blank', this.calculatePopupFeatures(options));
                let checkForPopupClosedTimer;
                const checkForPopupClosed = () => {
                    if (!windowRef || windowRef.closed) {
                        cleanup();
                        reject(new OAuthErrorEvent('popup_closed', {}));
                    }
                };
                if (!windowRef) {
                    reject(new OAuthErrorEvent('popup_blocked', {}));
                }
                else {
                    checkForPopupClosedTimer = window.setInterval(checkForPopupClosed, checkForPopupClosedInterval);
                }
                const cleanup = () => {
                    window.clearInterval(checkForPopupClosedTimer);
                    window.removeEventListener('message', listener);
                    if (windowRef !== null) {
                        windowRef.close();
                    }
                    windowRef = null;
                };
                const listener = (e) => {
                    const message = this.processMessageEventMessage(e);
                    if (message && message !== null) {
                        this.tryLogin({
                            customHashFragment: message,
                            preventClearHashAfterLogin: true,
                            customRedirectUri: this.silentRefreshRedirectUri
                        }).then(() => {
                            cleanup();
                            resolve();
                        }, err => {
                            cleanup();
                            reject(err);
                        });
                    }
                    else {
                        console.log('false event firing');
                    }
                };
                window.addEventListener('message', listener);
            });
        });
    }
    calculatePopupFeatures(options) {
        // Specify an static height and width and calculate centered position
        const height = options.height || 470;
        const width = options.width || 500;
        const left = window.screenLeft + (window.outerWidth - width) / 2;
        const top = window.screenTop + (window.outerHeight - height) / 2;
        return `location=no,toolbar=no,width=${width},height=${height},top=${top},left=${left}`;
    }
    processMessageEventMessage(e) {
        let expectedPrefix = '#';
        if (this.silentRefreshMessagePrefix) {
            expectedPrefix += this.silentRefreshMessagePrefix;
        }
        if (!e || !e.data || typeof e.data !== 'string') {
            return;
        }
        const prefixedMessage = e.data;
        if (!prefixedMessage.startsWith(expectedPrefix)) {
            return;
        }
        return '#' + prefixedMessage.substr(expectedPrefix.length);
    }
    canPerformSessionCheck() {
        if (!this.sessionChecksEnabled) {
            return false;
        }
        if (!this.sessionCheckIFrameUrl) {
            console.warn('sessionChecksEnabled is activated but there is no sessionCheckIFrameUrl');
            return false;
        }
        const sessionState = this.getSessionState();
        if (!sessionState) {
            console.warn('sessionChecksEnabled is activated but there is no session_state');
            return false;
        }
        if (typeof this.document === 'undefined') {
            return false;
        }
        return true;
    }
    setupSessionCheckEventListener() {
        this.removeSessionCheckEventListener();
        this.sessionCheckEventListener = (e) => {
            const origin = e.origin.toLowerCase();
            const issuer = this.issuer.toLowerCase();
            this.debug('sessionCheckEventListener');
            if (!issuer.startsWith(origin)) {
                this.debug('sessionCheckEventListener', 'wrong origin', origin, 'expected', issuer, 'event', e);
                return;
            }
            // only run in Angular zone if it is 'changed' or 'error'
            switch (e.data) {
                case 'unchanged':
                    this.handleSessionUnchanged();
                    break;
                case 'changed':
                    this.ngZone.run(() => {
                        this.handleSessionChange();
                    });
                    break;
                case 'error':
                    this.ngZone.run(() => {
                        this.handleSessionError();
                    });
                    break;
            }
            this.debug('got info from session check inframe', e);
        };
        // prevent Angular from refreshing the view on every message (runs in intervals)
        this.ngZone.runOutsideAngular(() => {
            window.addEventListener('message', this.sessionCheckEventListener);
        });
    }
    handleSessionUnchanged() {
        this.debug('session check', 'session unchanged');
    }
    handleSessionChange() {
        this.eventsSubject.next(new OAuthInfoEvent('session_changed'));
        this.stopSessionCheckTimer();
        if (!this.useSilentRefresh && this.responseType === 'code') {
            this.refreshToken()
                .then(_ => {
                this.debug('token refresh after session change worked');
            })
                .catch(_ => {
                this.debug('token refresh did not work after session changed');
                this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
                this.logOut(true);
            });
        }
        else if (this.silentRefreshRedirectUri) {
            this.silentRefresh().catch(_ => this.debug('silent refresh failed after session changed'));
            this.waitForSilentRefreshAfterSessionChange();
        }
        else {
            this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
            this.logOut(true);
        }
    }
    waitForSilentRefreshAfterSessionChange() {
        this.events
            .pipe(filter((e) => e.type === 'silently_refreshed' ||
            e.type === 'silent_refresh_timeout' ||
            e.type === 'silent_refresh_error'), first())
            .subscribe(e => {
            if (e.type !== 'silently_refreshed') {
                this.debug('silent refresh did not work after session changed');
                this.eventsSubject.next(new OAuthInfoEvent('session_terminated'));
                this.logOut(true);
            }
        });
    }
    handleSessionError() {
        this.stopSessionCheckTimer();
        this.eventsSubject.next(new OAuthInfoEvent('session_error'));
    }
    removeSessionCheckEventListener() {
        if (this.sessionCheckEventListener) {
            window.removeEventListener('message', this.sessionCheckEventListener);
            this.sessionCheckEventListener = null;
        }
    }
    initSessionCheck() {
        if (!this.canPerformSessionCheck()) {
            return;
        }
        const existingIframe = this.document.getElementById(this.sessionCheckIFrameName);
        if (existingIframe) {
            this.document.body.removeChild(existingIframe);
        }
        const iframe = this.document.createElement('iframe');
        iframe.id = this.sessionCheckIFrameName;
        this.setupSessionCheckEventListener();
        const url = this.sessionCheckIFrameUrl;
        iframe.setAttribute('src', url);
        iframe.style.display = 'none';
        this.document.body.appendChild(iframe);
        this.startSessionCheckTimer();
    }
    startSessionCheckTimer() {
        this.stopSessionCheckTimer();
        this.ngZone.runOutsideAngular(() => {
            this.sessionCheckTimer = setInterval(this.checkSession.bind(this), this.sessionCheckIntervall);
        });
    }
    stopSessionCheckTimer() {
        if (this.sessionCheckTimer) {
            clearInterval(this.sessionCheckTimer);
            this.sessionCheckTimer = null;
        }
    }
    checkSession() {
        const iframe = this.document.getElementById(this.sessionCheckIFrameName);
        if (!iframe) {
            this.logger.warn('checkSession did not find iframe', this.sessionCheckIFrameName);
        }
        const sessionState = this.getSessionState();
        if (!sessionState) {
            this.stopSessionCheckTimer();
        }
        const message = this.clientId + ' ' + sessionState;
        iframe.contentWindow.postMessage(message, this.issuer);
    }
    createLoginUrl(state = '', loginHint = '', customRedirectUri = '', noPrompt = false, params = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            const that = this;
            let redirectUri;
            if (customRedirectUri) {
                redirectUri = customRedirectUri;
            }
            else {
                redirectUri = this.redirectUri;
            }
            const nonce = yield this.createAndSaveNonce();
            if (state) {
                state =
                    nonce + this.config.nonceStateSeparator + encodeURIComponent(state);
            }
            else {
                state = nonce;
            }
            if (!this.requestAccessToken && !this.oidc) {
                throw new Error('Either requestAccessToken or oidc or both must be true');
            }
            if (this.config.responseType) {
                this.responseType = this.config.responseType;
            }
            else {
                if (this.oidc && this.requestAccessToken) {
                    this.responseType = 'id_token token';
                }
                else if (this.oidc && !this.requestAccessToken) {
                    this.responseType = 'id_token';
                }
                else {
                    this.responseType = 'token';
                }
            }
            const seperationChar = that.loginUrl.indexOf('?') > -1 ? '&' : '?';
            let scope = that.scope;
            if (this.oidc && !scope.match(/(^|\s)openid($|\s)/)) {
                scope = 'openid ' + scope;
            }
            let url = that.loginUrl +
                seperationChar +
                'response_type=' +
                encodeURIComponent(that.responseType) +
                '&client_id=' +
                encodeURIComponent(that.clientId) +
                '&state=' +
                encodeURIComponent(state) +
                '&redirect_uri=' +
                encodeURIComponent(redirectUri) +
                '&scope=' +
                encodeURIComponent(scope);
            if (this.responseType.includes('code') && !this.disablePKCE) {
                const [challenge, verifier] = yield this.createChallangeVerifierPairForPKCE();
                if (this.saveNoncesInLocalStorage &&
                    typeof window['localStorage'] !== 'undefined') {
                    localStorage.setItem('PKCE_verifier', verifier);
                }
                else {
                    this._storage.setItem('PKCE_verifier', verifier);
                }
                url += '&code_challenge=' + challenge;
                url += '&code_challenge_method=S256';
            }
            if (loginHint) {
                url += '&login_hint=' + encodeURIComponent(loginHint);
            }
            if (that.resource) {
                url += '&resource=' + encodeURIComponent(that.resource);
            }
            if (that.oidc) {
                url += '&nonce=' + encodeURIComponent(nonce);
            }
            if (noPrompt) {
                url += '&prompt=none';
            }
            for (const key of Object.keys(params)) {
                url +=
                    '&' + encodeURIComponent(key) + '=' + encodeURIComponent(params[key]);
            }
            if (this.customQueryParams) {
                for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    url +=
                        '&' + key + '=' + encodeURIComponent(this.customQueryParams[key]);
                }
            }
            return url;
        });
    }
    initImplicitFlowInternal(additionalState = '', params = '') {
        if (this.inImplicitFlow) {
            return;
        }
        this.inImplicitFlow = true;
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error("loginUrl  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        let addParams = {};
        let loginHint = null;
        if (typeof params === 'string') {
            loginHint = params;
        }
        else if (typeof params === 'object') {
            addParams = params;
        }
        this.createLoginUrl(additionalState, loginHint, null, false, addParams)
            .then(this.config.openUri)
            .catch(error => {
            console.error('Error in initImplicitFlow', error);
            this.inImplicitFlow = false;
        });
    }
    /**
     * Starts the implicit flow and redirects to user to
     * the auth servers' login url.
     *
     * @param additionalState Optional state that is passed around.
     *  You'll find this state in the property `state` after `tryLogin` logged in the user.
     * @param params Hash with additional parameter. If it is a string, it is used for the
     *               parameter loginHint (for the sake of compatibility with former versions)
     */
    initImplicitFlow(additionalState = '', params = '') {
        if (this.loginUrl !== '') {
            this.initImplicitFlowInternal(additionalState, params);
        }
        else {
            this.events
                .pipe(filter(e => e.type === 'discovery_document_loaded'))
                .subscribe(_ => this.initImplicitFlowInternal(additionalState, params));
        }
    }
    /**
     * Reset current implicit flow
     *
     * @description This method allows resetting the current implict flow in order to be initialized again.
     */
    resetImplicitFlow() {
        this.inImplicitFlow = false;
    }
    callOnTokenReceivedIfExists(options) {
        const that = this;
        if (options.onTokenReceived) {
            const tokenParams = {
                idClaims: that.getIdentityClaims(),
                idToken: that.getIdToken(),
                accessToken: that.getAccessToken(),
                state: that.state
            };
            options.onTokenReceived(tokenParams);
        }
    }
    storeAccessTokenResponse(accessToken, refreshToken, expiresIn, grantedScopes, customParameters) {
        this._storage.setItem('access_token', accessToken);
        if (grantedScopes && !Array.isArray(grantedScopes)) {
            this._storage.setItem('granted_scopes', JSON.stringify(grantedScopes.split('+')));
        }
        else if (grantedScopes && Array.isArray(grantedScopes)) {
            this._storage.setItem('granted_scopes', JSON.stringify(grantedScopes));
        }
        this._storage.setItem('access_token_stored_at', '' + Date.now());
        if (expiresIn) {
            const expiresInMilliSeconds = expiresIn * 1000;
            const now = new Date();
            const expiresAt = now.getTime() + expiresInMilliSeconds;
            this._storage.setItem('expires_at', '' + expiresAt);
        }
        if (refreshToken) {
            this._storage.setItem('refresh_token', refreshToken);
        }
        if (customParameters) {
            customParameters.forEach((value, key) => {
                this._storage.setItem(key, value);
            });
        }
    }
    /**
     * Delegates to tryLoginImplicitFlow for the sake of competability
     * @param options Optional options.
     */
    tryLogin(options = null) {
        if (this.config.responseType === 'code') {
            return this.tryLoginCodeFlow(options).then(_ => true);
        }
        else {
            return this.tryLoginImplicitFlow(options);
        }
    }
    parseQueryString(queryString) {
        if (!queryString || queryString.length === 0) {
            return {};
        }
        if (queryString.charAt(0) === '?') {
            queryString = queryString.substr(1);
        }
        return this.urlHelper.parseQueryString(queryString);
    }
    tryLoginCodeFlow(options = null) {
        options = options || {};
        const querySource = options.customHashFragment
            ? options.customHashFragment.substring(1)
            : window.location.search;
        const parts = this.getCodePartsFromUrl(querySource);
        const code = parts['code'];
        const state = parts['state'];
        const sessionState = parts['session_state'];
        if (!options.preventClearHashAfterLogin) {
            const href = location.href
                .replace(/[&\?]code=[^&\$]*/, '')
                .replace(/[&\?]scope=[^&\$]*/, '')
                .replace(/[&\?]state=[^&\$]*/, '')
                .replace(/[&\?]session_state=[^&\$]*/, '');
            history.replaceState(null, window.name, href);
        }
        let [nonceInState, userState] = this.parseState(state);
        this.state = userState;
        if (parts['error']) {
            this.debug('error trying to login');
            this.handleLoginError({}, parts);
            const err = new OAuthErrorEvent('code_error', {}, parts);
            this.eventsSubject.next(err);
            return Promise.reject(err);
        }
        if (!nonceInState) {
            return Promise.resolve();
        }
        const success = this.validateNonce(nonceInState);
        if (!success) {
            const event = new OAuthErrorEvent('invalid_nonce_in_state', null);
            this.eventsSubject.next(event);
            return Promise.reject(event);
        }
        this.storeSessionState(sessionState);
        if (code) {
            return this.getTokenFromCode(code, options).then(_ => null);
        }
        else {
            return Promise.resolve();
        }
    }
    /**
     * Retrieve the returned auth code from the redirect uri that has been called.
     * If required also check hash, as we could use hash location strategy.
     */
    getCodePartsFromUrl(queryString) {
        if (!queryString || queryString.length === 0) {
            return this.urlHelper.getHashFragmentParams();
        }
        // normalize query string
        if (queryString.charAt(0) === '?') {
            queryString = queryString.substr(1);
        }
        return this.urlHelper.parseQueryString(queryString);
    }
    /**
     * Get token using an intermediate code. Works for the Authorization Code flow.
     */
    getTokenFromCode(code, options) {
        let params = new HttpParams()
            .set('grant_type', 'authorization_code')
            .set('code', code)
            .set('redirect_uri', options.customRedirectUri || this.redirectUri);
        if (!this.disablePKCE) {
            let PKCEVerifier;
            if (this.saveNoncesInLocalStorage &&
                typeof window['localStorage'] !== 'undefined') {
                PKCEVerifier = localStorage.getItem('PKCE_verifier');
            }
            else {
                PKCEVerifier = this._storage.getItem('PKCE_verifier');
            }
            if (!PKCEVerifier) {
                console.warn('No PKCE verifier found in oauth storage!');
            }
            else {
                params = params.set('code_verifier', PKCEVerifier);
            }
        }
        return this.fetchAndProcessToken(params);
    }
    fetchAndProcessToken(params) {
        this.assertUrlNotNullAndCorrectProtocol(this.tokenEndpoint, 'tokenEndpoint');
        let headers = new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded');
        if (this.useHttpBasicAuth) {
            const header = btoa(`${this.clientId}:${this.dummyClientSecret}`);
            headers = headers.set('Authorization', 'Basic ' + header);
        }
        if (!this.useHttpBasicAuth) {
            params = params.set('client_id', this.clientId);
        }
        if (!this.useHttpBasicAuth && this.dummyClientSecret) {
            params = params.set('client_secret', this.dummyClientSecret);
        }
        return new Promise((resolve, reject) => {
            if (this.customQueryParams) {
                for (let key of Object.getOwnPropertyNames(this.customQueryParams)) {
                    params = params.set(key, this.customQueryParams[key]);
                }
            }
            this.http
                .post(this.tokenEndpoint, params, { headers })
                .subscribe(tokenResponse => {
                this.debug('refresh tokenResponse', tokenResponse);
                this.storeAccessTokenResponse(tokenResponse.access_token, tokenResponse.refresh_token, tokenResponse.expires_in ||
                    this.fallbackAccessTokenExpirationTimeInSec, tokenResponse.scope, this.extractRecognizedCustomParameters(tokenResponse));
                if (this.oidc && tokenResponse.id_token) {
                    this.processIdToken(tokenResponse.id_token, tokenResponse.access_token)
                        .then(result => {
                        this.storeIdToken(result);
                        this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                        this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                        resolve(tokenResponse);
                    })
                        .catch(reason => {
                        this.eventsSubject.next(new OAuthErrorEvent('token_validation_error', reason));
                        console.error('Error validating tokens');
                        console.error(reason);
                        reject(reason);
                    });
                }
                else {
                    this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
                    this.eventsSubject.next(new OAuthSuccessEvent('token_refreshed'));
                    resolve(tokenResponse);
                }
            }, err => {
                console.error('Error getting token', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_refresh_error', err));
                reject(err);
            });
        });
    }
    /**
     * Checks whether there are tokens in the hash fragment
     * as a result of the implicit flow. These tokens are
     * parsed, validated and used to sign the user in to the
     * current client.
     *
     * @param options Optional options.
     */
    tryLoginImplicitFlow(options = null) {
        options = options || {};
        let parts;
        if (options.customHashFragment) {
            parts = this.urlHelper.getHashFragmentParams(options.customHashFragment);
        }
        else {
            parts = this.urlHelper.getHashFragmentParams();
        }
        this.debug('parsed url', parts);
        const state = parts['state'];
        let [nonceInState, userState] = this.parseState(state);
        this.state = userState;
        if (parts['error']) {
            this.debug('error trying to login');
            this.handleLoginError(options, parts);
            const err = new OAuthErrorEvent('token_error', {}, parts);
            this.eventsSubject.next(err);
            return Promise.reject(err);
        }
        const accessToken = parts['access_token'];
        const idToken = parts['id_token'];
        const sessionState = parts['session_state'];
        const grantedScopes = parts['scope'];
        if (!this.requestAccessToken && !this.oidc) {
            return Promise.reject('Either requestAccessToken or oidc (or both) must be true.');
        }
        if (this.requestAccessToken && !accessToken) {
            return Promise.resolve(false);
        }
        if (this.requestAccessToken && !options.disableOAuth2StateCheck && !state) {
            return Promise.resolve(false);
        }
        if (this.oidc && !idToken) {
            return Promise.resolve(false);
        }
        if (this.sessionChecksEnabled && !sessionState) {
            this.logger.warn('session checks (Session Status Change Notification) ' +
                'were activated in the configuration but the id_token ' +
                'does not contain a session_state claim');
        }
        if (this.requestAccessToken && !options.disableOAuth2StateCheck) {
            const success = this.validateNonce(nonceInState);
            if (!success) {
                const event = new OAuthErrorEvent('invalid_nonce_in_state', null);
                this.eventsSubject.next(event);
                return Promise.reject(event);
            }
        }
        if (this.requestAccessToken) {
            this.storeAccessTokenResponse(accessToken, null, parts['expires_in'] || this.fallbackAccessTokenExpirationTimeInSec, grantedScopes);
        }
        if (!this.oidc) {
            this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
            if (this.clearHashAfterLogin && !options.preventClearHashAfterLogin) {
                location.hash = '';
            }
            this.callOnTokenReceivedIfExists(options);
            return Promise.resolve(true);
        }
        return this.processIdToken(idToken, accessToken)
            .then(result => {
            if (options.validationHandler) {
                return options
                    .validationHandler({
                    accessToken: accessToken,
                    idClaims: result.idTokenClaims,
                    idToken: result.idToken,
                    state: state
                })
                    .then(_ => result);
            }
            return result;
        })
            .then(result => {
            this.storeIdToken(result);
            this.storeSessionState(sessionState);
            if (this.clearHashAfterLogin && !options.preventClearHashAfterLogin) {
                location.hash = '';
            }
            this.eventsSubject.next(new OAuthSuccessEvent('token_received'));
            this.callOnTokenReceivedIfExists(options);
            this.inImplicitFlow = false;
            return true;
        })
            .catch(reason => {
            this.eventsSubject.next(new OAuthErrorEvent('token_validation_error', reason));
            this.logger.error('Error validating tokens');
            this.logger.error(reason);
            return Promise.reject(reason);
        });
    }
    parseState(state) {
        let nonce = state;
        let userState = '';
        if (state) {
            const idx = state.indexOf(this.config.nonceStateSeparator);
            if (idx > -1) {
                nonce = state.substr(0, idx);
                userState = state.substr(idx + this.config.nonceStateSeparator.length);
            }
        }
        return [nonce, userState];
    }
    validateNonce(nonceInState) {
        let savedNonce;
        if (this.saveNoncesInLocalStorage &&
            typeof window['localStorage'] !== 'undefined') {
            savedNonce = localStorage.getItem('nonce');
        }
        else {
            savedNonce = this._storage.getItem('nonce');
        }
        if (savedNonce !== nonceInState) {
            const err = 'Validating access_token failed, wrong state/nonce.';
            console.error(err, savedNonce, nonceInState);
            return false;
        }
        return true;
    }
    storeIdToken(idToken) {
        this._storage.setItem('id_token', idToken.idToken);
        this._storage.setItem('id_token_claims_obj', idToken.idTokenClaimsJson);
        this._storage.setItem('id_token_expires_at', '' + idToken.idTokenExpiresAt);
        this._storage.setItem('id_token_stored_at', '' + Date.now());
    }
    storeSessionState(sessionState) {
        this._storage.setItem('session_state', sessionState);
    }
    getSessionState() {
        return this._storage.getItem('session_state');
    }
    handleLoginError(options, parts) {
        if (options.onLoginError) {
            options.onLoginError(parts);
        }
        if (this.clearHashAfterLogin && !options.preventClearHashAfterLogin) {
            location.hash = '';
        }
    }
    /**
     * @ignore
     */
    processIdToken(idToken, accessToken, skipNonceCheck = false) {
        const tokenParts = idToken.split('.');
        const headerBase64 = this.padBase64(tokenParts[0]);
        const headerJson = b64DecodeUnicode(headerBase64);
        const header = JSON.parse(headerJson);
        const claimsBase64 = this.padBase64(tokenParts[1]);
        const claimsJson = b64DecodeUnicode(claimsBase64);
        const claims = JSON.parse(claimsJson);
        let savedNonce;
        if (this.saveNoncesInLocalStorage &&
            typeof window['localStorage'] !== 'undefined') {
            savedNonce = localStorage.getItem('nonce');
        }
        else {
            savedNonce = this._storage.getItem('nonce');
        }
        if (Array.isArray(claims.aud)) {
            if (claims.aud.every(v => v !== this.clientId)) {
                const err = 'Wrong audience: ' + claims.aud.join(',');
                this.logger.warn(err);
                return Promise.reject(err);
            }
        }
        else {
            if (claims.aud !== this.clientId) {
                const err = 'Wrong audience: ' + claims.aud;
                this.logger.warn(err);
                return Promise.reject(err);
            }
        }
        if (!claims.sub) {
            const err = 'No sub claim in id_token';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        /* For now, we only check whether the sub against
         * silentRefreshSubject when sessionChecksEnabled is on
         * We will reconsider in a later version to do this
         * in every other case too.
         */
        if (this.sessionChecksEnabled &&
            this.silentRefreshSubject &&
            this.silentRefreshSubject !== claims['sub']) {
            const err = 'After refreshing, we got an id_token for another user (sub). ' +
                `Expected sub: ${this.silentRefreshSubject}, received sub: ${claims['sub']}`;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!claims.iat) {
            const err = 'No iat claim in id_token';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!this.skipIssuerCheck && claims.iss !== this.issuer) {
            const err = 'Wrong issuer: ' + claims.iss;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        if (!skipNonceCheck && claims.nonce !== savedNonce) {
            const err = 'Wrong nonce: ' + claims.nonce;
            this.logger.warn(err);
            return Promise.reject(err);
        }
        // at_hash is not applicable to authorization code flow
        // addressing https://github.com/manfredsteyer/angular-oauth2-oidc/issues/661
        // i.e. Based on spec the at_hash check is only true for implicit code flow on Ping Federate
        // https://www.pingidentity.com/developer/en/resources/openid-connect-developers-guide.html
        if (this.hasOwnProperty('responseType') &&
            (this.responseType === 'code' || this.responseType === 'id_token')) {
            this.disableAtHashCheck = true;
        }
        if (!this.disableAtHashCheck &&
            this.requestAccessToken &&
            !claims['at_hash']) {
            const err = 'An at_hash is needed!';
            this.logger.warn(err);
            return Promise.reject(err);
        }
        const now = Date.now();
        const issuedAtMSec = claims.iat * 1000;
        const expiresAtMSec = claims.exp * 1000;
        const clockSkewInMSec = (this.clockSkewInSec || 600) * 1000;
        if (issuedAtMSec - clockSkewInMSec >= now ||
            expiresAtMSec + clockSkewInMSec <= now) {
            const err = 'Token has expired';
            console.error(err);
            console.error({
                now: now,
                issuedAtMSec: issuedAtMSec,
                expiresAtMSec: expiresAtMSec
            });
            return Promise.reject(err);
        }
        const validationParams = {
            accessToken: accessToken,
            idToken: idToken,
            jwks: this.jwks,
            idTokenClaims: claims,
            idTokenHeader: header,
            loadKeys: () => this.loadJwks()
        };
        if (this.disableAtHashCheck) {
            return this.checkSignature(validationParams).then(_ => {
                const result = {
                    idToken: idToken,
                    idTokenClaims: claims,
                    idTokenClaimsJson: claimsJson,
                    idTokenHeader: header,
                    idTokenHeaderJson: headerJson,
                    idTokenExpiresAt: expiresAtMSec
                };
                return result;
            });
        }
        return this.checkAtHash(validationParams).then(atHashValid => {
            if (!this.disableAtHashCheck && this.requestAccessToken && !atHashValid) {
                const err = 'Wrong at_hash';
                this.logger.warn(err);
                return Promise.reject(err);
            }
            return this.checkSignature(validationParams).then(_ => {
                const atHashCheckEnabled = !this.disableAtHashCheck;
                const result = {
                    idToken: idToken,
                    idTokenClaims: claims,
                    idTokenClaimsJson: claimsJson,
                    idTokenHeader: header,
                    idTokenHeaderJson: headerJson,
                    idTokenExpiresAt: expiresAtMSec
                };
                if (atHashCheckEnabled) {
                    return this.checkAtHash(validationParams).then(atHashValid1 => {
                        if (this.requestAccessToken && !atHashValid1) {
                            const err = 'Wrong at_hash';
                            this.logger.warn(err);
                            return Promise.reject(err);
                        }
                        else {
                            return result;
                        }
                    });
                }
                else {
                    return result;
                }
            });
        });
    }
    /**
     * Returns the received claims about the user.
     */
    getIdentityClaims() {
        const claims = this._storage.getItem('id_token_claims_obj');
        if (!claims) {
            return null;
        }
        return JSON.parse(claims);
    }
    /**
     * Returns the granted scopes from the server.
     */
    getGrantedScopes() {
        const scopes = this._storage.getItem('granted_scopes');
        if (!scopes) {
            return null;
        }
        return JSON.parse(scopes);
    }
    /**
     * Returns the current id_token.
     */
    getIdToken() {
        return this._storage ? this._storage.getItem('id_token') : null;
    }
    padBase64(base64data) {
        while (base64data.length % 4 !== 0) {
            base64data += '=';
        }
        return base64data;
    }
    /**
     * Returns the current access_token.
     */
    getAccessToken() {
        return this._storage ? this._storage.getItem('access_token') : null;
    }
    getRefreshToken() {
        return this._storage ? this._storage.getItem('refresh_token') : null;
    }
    /**
     * Returns the expiration date of the access_token
     * as milliseconds since 1970.
     */
    getAccessTokenExpiration() {
        if (!this._storage.getItem('expires_at')) {
            return null;
        }
        return parseInt(this._storage.getItem('expires_at'), 10);
    }
    getAccessTokenStoredAt() {
        return parseInt(this._storage.getItem('access_token_stored_at'), 10);
    }
    getIdTokenStoredAt() {
        return parseInt(this._storage.getItem('id_token_stored_at'), 10);
    }
    /**
     * Returns the expiration date of the id_token
     * as milliseconds since 1970.
     */
    getIdTokenExpiration() {
        if (!this._storage.getItem('id_token_expires_at')) {
            return null;
        }
        return parseInt(this._storage.getItem('id_token_expires_at'), 10);
    }
    /**
     * Checkes, whether there is a valid access_token.
     */
    hasValidAccessToken() {
        if (this.getAccessToken()) {
            const expiresAt = this._storage.getItem('expires_at');
            const now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }
            return true;
        }
        return false;
    }
    /**
     * Checks whether there is a valid id_token.
     */
    hasValidIdToken() {
        if (this.getIdToken()) {
            const expiresAt = this._storage.getItem('id_token_expires_at');
            const now = new Date();
            if (expiresAt && parseInt(expiresAt, 10) < now.getTime()) {
                return false;
            }
            return true;
        }
        return false;
    }
    /**
     * Retrieve a saved custom property of the TokenReponse object. Only if predefined in authconfig.
     */
    getCustomTokenResponseProperty(requestedProperty) {
        return this._storage &&
            this.config.customTokenParameters &&
            this.config.customTokenParameters.indexOf(requestedProperty) >= 0 &&
            this._storage.getItem(requestedProperty) !== null
            ? JSON.parse(this._storage.getItem(requestedProperty))
            : null;
    }
    /**
     * Returns the auth-header that can be used
     * to transmit the access_token to a service
     */
    authorizationHeader() {
        return 'Bearer ' + this.getAccessToken();
    }
    logOut(customParameters = {}, state = '') {
        let noRedirectToLogoutUrl = false;
        if (typeof customParameters === 'boolean') {
            noRedirectToLogoutUrl = customParameters;
            customParameters = {};
        }
        const id_token = this.getIdToken();
        this._storage.removeItem('access_token');
        this._storage.removeItem('id_token');
        this._storage.removeItem('refresh_token');
        if (this.saveNoncesInLocalStorage) {
            localStorage.removeItem('nonce');
            localStorage.removeItem('PKCE_verifier');
        }
        else {
            this._storage.removeItem('nonce');
            this._storage.removeItem('PKCE_verifier');
        }
        this._storage.removeItem('expires_at');
        this._storage.removeItem('id_token_claims_obj');
        this._storage.removeItem('id_token_expires_at');
        this._storage.removeItem('id_token_stored_at');
        this._storage.removeItem('access_token_stored_at');
        this._storage.removeItem('granted_scopes');
        this._storage.removeItem('session_state');
        if (this.config.customTokenParameters) {
            this.config.customTokenParameters.forEach(customParam => this._storage.removeItem(customParam));
        }
        this.silentRefreshSubject = null;
        this.eventsSubject.next(new OAuthInfoEvent('logout'));
        if (!this.logoutUrl) {
            return;
        }
        if (noRedirectToLogoutUrl) {
            return;
        }
        if (!id_token && !this.postLogoutRedirectUri) {
            return;
        }
        let logoutUrl;
        if (!this.validateUrlForHttps(this.logoutUrl)) {
            throw new Error("logoutUrl  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        // For backward compatibility
        if (this.logoutUrl.indexOf('{{') > -1) {
            logoutUrl = this.logoutUrl
                .replace(/\{\{id_token\}\}/, id_token)
                .replace(/\{\{client_id\}\}/, this.clientId);
        }
        else {
            let params = new HttpParams();
            if (id_token) {
                params = params.set('id_token_hint', id_token);
            }
            const postLogoutUrl = this.postLogoutRedirectUri || this.redirectUri;
            if (postLogoutUrl) {
                params = params.set('post_logout_redirect_uri', postLogoutUrl);
                if (state) {
                    params = params.set('state', state);
                }
            }
            for (let key in customParameters) {
                params = params.set(key, customParameters[key]);
            }
            logoutUrl =
                this.logoutUrl +
                    (this.logoutUrl.indexOf('?') > -1 ? '&' : '?') +
                    params.toString();
        }
        this.config.openUri(logoutUrl);
    }
    /**
     * @ignore
     */
    createAndSaveNonce() {
        const that = this;
        return this.createNonce().then(function (nonce) {
            // Use localStorage for nonce if possible
            // localStorage is the only storage who survives a
            // redirect in ALL browsers (also IE)
            // Otherwiese we'd force teams who have to support
            // IE into using localStorage for everything
            if (that.saveNoncesInLocalStorage &&
                typeof window['localStorage'] !== 'undefined') {
                localStorage.setItem('nonce', nonce);
            }
            else {
                that._storage.setItem('nonce', nonce);
            }
            return nonce;
        });
    }
    /**
     * @ignore
     */
    ngOnDestroy() {
        this.clearAccessTokenTimer();
        this.clearIdTokenTimer();
        this.removeSilentRefreshEventListener();
        const silentRefreshFrame = this.document.getElementById(this.silentRefreshIFrameName);
        if (silentRefreshFrame) {
            silentRefreshFrame.remove();
        }
        this.stopSessionCheckTimer();
        this.removeSessionCheckEventListener();
        const sessionCheckFrame = this.document.getElementById(this.sessionCheckIFrameName);
        if (sessionCheckFrame) {
            sessionCheckFrame.remove();
        }
    }
    createNonce() {
        return new Promise(resolve => {
            if (this.rngUrl) {
                throw new Error('createNonce with rng-web-api has not been implemented so far');
            }
            /*
             * This alphabet is from:
             * https://tools.ietf.org/html/rfc7636#section-4.1
             *
             * [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
             */
            const unreserved = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
            let size = 45;
            let id = '';
            const crypto = typeof self === 'undefined' ? null : self.crypto || self['msCrypto'];
            if (crypto) {
                let bytes = new Uint8Array(size);
                crypto.getRandomValues(bytes);
                // Needed for IE
                if (!bytes.map) {
                    bytes.map = Array.prototype.map;
                }
                bytes = bytes.map(x => unreserved.charCodeAt(x % unreserved.length));
                id = String.fromCharCode.apply(null, bytes);
            }
            else {
                while (0 < size--) {
                    id += unreserved[(Math.random() * unreserved.length) | 0];
                }
            }
            resolve(base64UrlEncode(id));
        });
    }
    checkAtHash(params) {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.tokenValidationHandler) {
                this.logger.warn('No tokenValidationHandler configured. Cannot check at_hash.');
                return true;
            }
            return this.tokenValidationHandler.validateAtHash(params);
        });
    }
    checkSignature(params) {
        if (!this.tokenValidationHandler) {
            this.logger.warn('No tokenValidationHandler configured. Cannot check signature.');
            return Promise.resolve(null);
        }
        return this.tokenValidationHandler.validateSignature(params);
    }
    /**
     * Start the implicit flow or the code flow,
     * depending on your configuration.
     */
    initLoginFlow(additionalState = '', params = {}) {
        if (this.responseType === 'code') {
            return this.initCodeFlow(additionalState, params);
        }
        else {
            return this.initImplicitFlow(additionalState, params);
        }
    }
    /**
     * Starts the authorization code flow and redirects to user to
     * the auth servers login url.
     */
    initCodeFlow(additionalState = '', params = {}) {
        if (this.loginUrl !== '') {
            this.initCodeFlowInternal(additionalState, params);
        }
        else {
            this.events
                .pipe(filter(e => e.type === 'discovery_document_loaded'))
                .subscribe(_ => this.initCodeFlowInternal(additionalState, params));
        }
    }
    initCodeFlowInternal(additionalState = '', params = {}) {
        if (!this.validateUrlForHttps(this.loginUrl)) {
            throw new Error("loginUrl  must use HTTPS (with TLS), or config value for property 'requireHttps' must be set to 'false' and allow HTTP (without TLS).");
        }
        this.createLoginUrl(additionalState, '', null, false, params)
            .then(this.config.openUri)
            .catch(error => {
            console.error('Error in initAuthorizationCodeFlow');
            console.error(error);
        });
    }
    createChallangeVerifierPairForPKCE() {
        return __awaiter(this, void 0, void 0, function* () {
            if (!this.crypto) {
                throw new Error('PKCE support for code flow needs a CryptoHander. Did you import the OAuthModule using forRoot() ?');
            }
            const verifier = yield this.createNonce();
            const challengeRaw = yield this.crypto.calcHash(verifier, 'sha-256');
            const challenge = base64UrlEncode(challengeRaw);
            return [challenge, verifier];
        });
    }
    extractRecognizedCustomParameters(tokenResponse) {
        let foundParameters = new Map();
        if (!this.config.customTokenParameters) {
            return foundParameters;
        }
        this.config.customTokenParameters.forEach((recognizedParameter) => {
            if (tokenResponse[recognizedParameter]) {
                foundParameters.set(recognizedParameter, JSON.stringify(tokenResponse[recognizedParameter]));
            }
        });
        return foundParameters;
    }
    /**
     * Revokes the auth token to secure the vulnarability
     * of the token issued allowing the authorization server to clean
     * up any security credentials associated with the authorization
     */
    revokeTokenAndLogout(customParameters = {}, ignoreCorsIssues = false) {
        let revokeEndpoint = this.revocationEndpoint;
        let accessToken = this.getAccessToken();
        let refreshToken = this.getRefreshToken();
        if (!accessToken) {
            return;
        }
        let params = new HttpParams();
        let headers = new HttpHeaders().set('Content-Type', 'application/x-www-form-urlencoded');
        if (this.useHttpBasicAuth) {
            const header = btoa(`${this.clientId}:${this.dummyClientSecret}`);
            headers = headers.set('Authorization', 'Basic ' + header);
        }
        if (!this.useHttpBasicAuth) {
            params = params.set('client_id', this.clientId);
        }
        if (!this.useHttpBasicAuth && this.dummyClientSecret) {
            params = params.set('client_secret', this.dummyClientSecret);
        }
        if (this.customQueryParams) {
            for (const key of Object.getOwnPropertyNames(this.customQueryParams)) {
                params = params.set(key, this.customQueryParams[key]);
            }
        }
        return new Promise((resolve, reject) => {
            let revokeAccessToken;
            let revokeRefreshToken;
            if (accessToken) {
                let revokationParams = params
                    .set('token', accessToken)
                    .set('token_type_hint', 'access_token');
                revokeAccessToken = this.http.post(revokeEndpoint, revokationParams, { headers });
            }
            else {
                revokeAccessToken = of(null);
            }
            if (refreshToken) {
                let revokationParams = params
                    .set('token', refreshToken)
                    .set('token_type_hint', 'refresh_token');
                revokeRefreshToken = this.http.post(revokeEndpoint, revokationParams, { headers });
            }
            else {
                revokeRefreshToken = of(null);
            }
            if (ignoreCorsIssues) {
                revokeAccessToken = revokeAccessToken.pipe(catchError((err) => {
                    if (err.status === 0) {
                        return of(null);
                    }
                    return throwError(err);
                }));
                revokeRefreshToken = revokeRefreshToken.pipe(catchError((err) => {
                    if (err.status === 0) {
                        return of(null);
                    }
                    return throwError(err);
                }));
            }
            combineLatest([revokeAccessToken, revokeRefreshToken]).subscribe(res => {
                this.logOut(customParameters);
                resolve(res);
                this.logger.info('Token successfully revoked');
            }, err => {
                this.logger.error('Error revoking token', err);
                this.eventsSubject.next(new OAuthErrorEvent('token_revoke_error', err));
                reject(err);
            });
        });
    }
}
OAuthService.decorators = [
    { type: Injectable }
];
OAuthService.ctorParameters = () => [
    { type: NgZone },
    { type: HttpClient },
    { type: OAuthStorage, decorators: [{ type: Optional }] },
    { type: ValidationHandler, decorators: [{ type: Optional }] },
    { type: AuthConfig, decorators: [{ type: Optional }] },
    { type: UrlHelperService },
    { type: OAuthLogger },
    { type: HashHandler, decorators: [{ type: Optional }] },
    { type: undefined, decorators: [{ type: Inject, args: [DOCUMENT,] }] }
];
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2F1dGgtc2VydmljZS5qcyIsInNvdXJjZVJvb3QiOiJDOi9Vc2Vycy9kaWVnby5hdXlvbi9Qcm9qZWN0cy90ZWx1cy9hbmd1bGFyLW9hdXRoMi1vaWRjL3Byb2plY3RzL2xpYi9zcmMvIiwic291cmNlcyI6WyJvYXV0aC1zZXJ2aWNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSxPQUFPLEVBQUUsTUFBTSxFQUFFLFVBQVUsRUFBRSxNQUFNLEVBQWEsUUFBUSxFQUFFLE1BQU0sZUFBZSxDQUFDO0FBQ2hGLE9BQU8sRUFDTCxVQUFVLEVBRVYsV0FBVyxFQUNYLFVBQVUsRUFDWCxNQUFNLHNCQUFzQixDQUFDO0FBQzlCLE9BQU8sRUFDTCxhQUFhLEVBQ2IsSUFBSSxFQUVKLEVBQUUsRUFDRixJQUFJLEVBQ0osT0FBTyxFQUVQLFVBQVUsRUFDWCxNQUFNLE1BQU0sQ0FBQztBQUNkLE9BQU8sRUFDTCxVQUFVLEVBQ1YsWUFBWSxFQUNaLEtBQUssRUFDTCxNQUFNLEVBQ04sS0FBSyxFQUNMLEdBQUcsRUFDSCxTQUFTLEVBQ1QsR0FBRyxFQUNKLE1BQU0sZ0JBQWdCLENBQUM7QUFDeEIsT0FBTyxFQUFFLFFBQVEsRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBRTNDLE9BQU8sRUFDTCxpQkFBaUIsRUFFbEIsTUFBTSx1Q0FBdUMsQ0FBQztBQUMvQyxPQUFPLEVBQUUsZ0JBQWdCLEVBQUUsTUFBTSxzQkFBc0IsQ0FBQztBQUN4RCxPQUFPLEVBQ0wsZUFBZSxFQUVmLGNBQWMsRUFDZCxpQkFBaUIsRUFDbEIsTUFBTSxVQUFVLENBQUM7QUFDbEIsT0FBTyxFQUVMLFdBQVcsRUFDWCxZQUFZLEVBS2IsTUFBTSxTQUFTLENBQUM7QUFDakIsT0FBTyxFQUFFLGdCQUFnQixFQUFFLGVBQWUsRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBQ3BFLE9BQU8sRUFBRSxVQUFVLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFDM0MsT0FBTyxFQUFFLHVCQUF1QixFQUFFLE1BQU0sV0FB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RSxrQkFBa0IsQ0FBQyxDQUFDLENBQUMsU0FBUyxDQUM5RCxHQUFHLENBQUMsRUFBRTtnQkFDSixJQUFJLENBQUMsTUFBTSxDQUFDLGdCQUFnQixDQUFDLENBQUM7Z0JBQzlCLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztnQkFDYixJQUFJLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyw0QkFBNEIsQ0FBQyxDQUFDO1lBQ2pELENBQUMsRUFDRCxHQUFHLENBQUMsRUFBRTtnQkFDSixJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxzQkFBc0IsRUFBRSxHQUFHLENBQUMsQ0FBQztnQkFDL0MsSUFBSSxDQUFDLGFBQWEsQ0FBQyxJQUFJLENBQ3JCLElBQUksZUFBZSxDQUFDLG9CQUFvQixFQUFFLEdBQUcsQ0FBQyxDQUMvQyxDQUFDO2dCQUNGLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQztZQUNkLENBQUMsQ0FDRixDQUFDO1FBQ0osQ0FBQyxDQUFDLENBQUM7SUFDTCxDQUFDOzs7WUFqbEZGLFVBQVU7OztZQTNEa0IsTUFBTTtZQUVqQyxVQUFVO1lBeUNWLFlBQVksdUJBeUVULFFBQVE7WUF0RlgsaUJBQWlCLHVCQXVGZCxRQUFRO1lBbkVKLFVBQVUsdUJBb0VkLFFBQVE7WUFyRkosZ0JBQWdCO1lBU3ZCLFdBQVc7WUFVSixXQUFXLHVCQXFFZixRQUFROzRDQUNSLE1BQU0sU0FBQyxRQUFRIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0LCBJbmplY3RhYmxlLCBOZ1pvbmUsIE9uRGVzdHJveSwgT3B0aW9uYWwgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcclxuaW1wb3J0IHtcclxuICBIdHRwQ2xpZW50LFxyXG4gIEh0dHBFcnJvclJlc3BvbnNlLFxyXG4gIEh0dHBIZWFkZXJzLFxyXG4gIEh0dHBQYXJhbXNcclxufSBmcm9tICdAYW5ndWxhci9jb21tb24vaHR0cCc7XHJcbmltcG9ydCB7XHJcbiAgY29tYmluZUxhdGVzdCxcclxuICBmcm9tLFxyXG4gIE9ic2VydmFibGUsXHJcbiAgb2YsXHJcbiAgcmFjZSxcclxuICBTdWJqZWN0LFxyXG4gIFN1YnNjcmlwdGlvbixcclxuICB0aHJvd0Vycm9yXHJcbn0gZnJvbSAncnhqcyc7XHJcbmltcG9ydCB7XHJcbiAgY2F0Y2hFcnJvcixcclxuICBkZWJvdW5jZVRpbWUsXHJcbiAgZGVsYXksXHJcbiAgZmlsdGVyLFxyXG4gIGZpcnN0LFxyXG4gIG1hcCxcclxuICBzd2l0Y2hNYXAsXHJcbiAgdGFwXHJcbn0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xyXG5pbXBvcnQgeyBET0NVTUVOVCB9IGZyb20gJ0Bhbmd1bGFyL2NvbW1vbic7XHJcblxyXG5pbXBvcnQge1xyXG4gIFZhbGlkYXRpb25IYW5kbGVyLFxyXG4gIFZhbGlkYXRpb25QYXJhbXNcclxufSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vdmFsaWRhdGlvbi1oYW5kbGVyJztcclxuaW1wb3J0IHsgVXJsSGVscGVyU2VydmljZSB9IGZyb20gJy4vdXJsLWhlbHBlci5zZXJ2aWNlJztcclxuaW1wb3J0IHtcclxuICBPQXV0aEVycm9yRXZlbnQsXHJcbiAgT0F1dGhFdmVudCxcclxuICBPQXV0aEluZm9FdmVudCxcclxuICBPQXV0aFN1Y2Nlc3NFdmVudFxyXG59IGZyb20gJy4vZXZlbnRzJztcclxuaW1wb3J0IHtcclxuICBMb2dpbk9wdGlvbnMsXHJcbiAgT0F1dGhMb2dnZXIsXHJcbiAgT0F1dGhTdG9yYWdlLFxyXG4gIE9pZGNEaXNjb3ZlcnlEb2MsXHJcbiAgUGFyc2VkSWRUb2tlbixcclxuICBUb2tlblJlc3BvbnNlLFxyXG4gIFVzZXJJbmZvXHJcbn0gZnJvbSAnLi90eXBlcyc7XHJcbmltcG9ydCB7IGI2NERlY29kZVVuaWNvZGUsIGJhc2U2NFVybEVuY29kZSB9IGZyb20gJy4vYmFzZTY0LWhlbHBlcic7XHJcbmltcG9ydCB7IEF1dGhDb25maWcgfSBmcm9tICcuL2F1dGguY29uZmlnJztcclxuaW1wb3J0IHsgV2ViSHR0cFVybEVuY29kaW5nQ29kZWMgfSBmcm9tICcuL2VuY29kZXInO1xyXG5pbXBvcnQgeyBIYXNoSGFuZGxlciB9IGZyb20gJy4vdG9rZW4tdmFsaWRhdGlvbi9oYXNoLWhhbmRsZXInO1xyXG5cclxuLyoqXHJcbiAqIFNlcnZpY2UgZm9yIGxvZ2dpbmcgaW4gYW5kIGxvZ2dpbmcgb3V0IHdpdGhcclxuICogT0lEQyBhbmQgT0F1dGgyLiBTdXBwb3J0cyBpbXBsaWNpdCBmbG93IGFuZFxyXG4gKiBwYXNzd29yZCBmbG93LlxyXG4gKi9cclxuQEluamVjdGFibGUoKVxyXG5leHBvcnQgY2xhc3MgT0F1dGhTZXJ2aWNlIGV4dGVuZHMgQXV0aENvbmZpZyBpbXBsZW1lbnRzIE9uRGVzdHJveSB7XHJcbiAgLy8gRXh0ZW5kaW5nIEF1dGhDb25maWcgaXN0IGp1c3QgZm9yIExFR0FDWSByZWFzb25zXHJcbiAgLy8gdG8gbm90IGJyZWFrIGV4aXN0aW5nIGNvZGUuXHJcblxyXG4gIC8qKlxyXG4gICAqIFRoZSBWYWxpZGF0aW9uSGFuZGxlciB1c2VkIHRvIHZhbGlkYXRlIHJlY2VpdmVkXHJcbiAgICogaWRfdG9rZW5zLlxyXG4gICAqL1xyXG4gIHB1YmxpYyB0b2tlblZhbGlkYXRpb25IYW5kbGVyOiBWYWxpZGF0aW9uSGFuZGxlcjtcclxuXHJcbiAgLyoqXHJcbiAgICogQGludGVybmFsXHJcbiAgICogRGVwcmVjYXRlZDogIHVzZSBwcm9wZXJ0eSBldmVudHMgaW5zdGVhZFxyXG4gICAqL1xyXG4gIHB1YmxpYyBkaXNjb3ZlcnlEb2N1bWVudExvYWRlZCA9IGZhbHNlO1xyXG5cclxuICAvKipcclxuICAgKiBAaW50ZXJuYWxcclxuICAgKiBEZXByZWNhdGVkOiAgdXNlIHByb3BlcnR5IGV2ZW50cyBpbnN0ZWFkXHJcbiAgICovXHJcbiAgcHVibGljIGRpc2NvdmVyeURvY3VtZW50TG9hZGVkJDogT2JzZXJ2YWJsZTxPaWRjRGlzY292ZXJ5RG9jPjtcclxuXHJcbiAgLyoqXHJcbiAgICogSW5mb3JtcyBhYm91dCBldmVudHMsIGxpa2UgdG9rZW5fcmVjZWl2ZWQgb3IgdG9rZW5fZXhwaXJlcy5cclxuICAgKiBTZWUgdGhlIHN0cmluZyBlbnVtIEV2ZW50VHlwZSBmb3IgYSBmdWxsIGxpc3Qgb2YgZXZlbnQgdHlwZXMuXHJcbiAgICovXHJcbiAgcHVibGljIGV2ZW50czogT2JzZXJ2YWJsZTxPQXV0aEV2ZW50PjtcclxuXHJcbiAgLyoqXHJcbiAgICogVGhlIHJlY2VpdmVkIChwYXNzZWQgYXJvdW5kKSBzdGF0ZSwgd2hlbiBsb2dnaW5nXHJcbiAgICogaW4gd2l0aCBpbXBsaWNpdCBmbG93LlxyXG4gICAqL1xyXG4gIHB1YmxpYyBzdGF0ZT8gPSAnJztcclxuXHJcbiAgcHJvdGVjdGVkIGV2ZW50c1N1YmplY3Q6IFN1YmplY3Q8T0F1dGhFdmVudD4gPSBuZXcgU3ViamVjdDxPQXV0aEV2ZW50PigpO1xyXG4gIHByb3RlY3RlZCBkaXNjb3ZlcnlEb2N1bWVudExvYWRlZFN1YmplY3Q6IFN1YmplY3Q8XHJcbiAgICBPaWRjRGlzY292ZXJ5RG9jXHJcbiAgPiA9IG5ldyBTdWJqZWN0PE9pZGNEaXNjb3ZlcnlEb2M+KCk7XHJcbiAgcHJvdGVjdGVkIHNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXI6IEV2ZW50TGlzdGVuZXI7XHJcbiAgcHJvdGVjdGVkIGdyYW50VHlwZXNTdXBwb3J0ZWQ6IEFycmF5PHN0cmluZz4gPSBbXTtcclxuICBwcm90ZWN0ZWQgX3N0b3JhZ2U6IE9BdXRoU3RvcmFnZTtcclxuICBwcm90ZWN0ZWQgYWNjZXNzVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uOiBTdWJzY3JpcHRpb247XHJcbiAgcHJvdGVjdGVkIGlkVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uOiBTdWJzY3JpcHRpb247XHJcbiAgcHJvdGVjdGVkIHRva2VuUmVjZWl2ZWRTdWJzY3JpcHRpb246IFN1YnNjcmlwdGlvbjtcclxuICBwcm90ZWN0ZWQgc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcjogRXZlbnRMaXN0ZW5lcjtcclxuICBwcm90ZWN0ZWQgandrc1VyaTogc3RyaW5nO1xyXG4gIHByb3RlY3RlZCBzZXNzaW9uQ2hlY2tUaW1lcjogYW55O1xyXG4gIHByb3RlY3RlZCBzaWxlbnRSZWZyZXNoU3ViamVjdDogc3RyaW5nO1xyXG4gIHByb3RlY3RlZCBpbkltcGxpY2l0RmxvdyA9IGZhbHNlO1xyXG5cclxuICBwcm90ZWN0ZWQgc2F2ZU5vbmNlc0luTG9jYWxTdG9yYWdlID0gZmFsc2U7XHJcbiAgcHJpdmF0ZSBkb2N1bWVudDogRG9jdW1lbnQ7XHJcblxyXG4gIGNvbnN0cnVjdG9yKFxyXG4gICAgcHJvdGVjdGVkIG5nWm9uZTogTmdab25lLFxyXG4gICAgcHJvdGVjdGVkIGh0dHA6IEh0dHBDbGllbnQsXHJcbiAgICBAT3B0aW9uYWwoKSBzdG9yYWdlOiBPQXV0aFN0b3JhZ2UsXHJcbiAgICBAT3B0aW9uYWwoKSB0b2tlblZhbGlkYXRpb25IYW5kbGVyOiBWYWxpZGF0aW9uSGFuZGxlcixcclxuICAgIEBPcHRpb25hbCgpIHByb3RlY3RlZCBjb25maWc6IEF1dGhDb25maWcsXHJcbiAgICBwcm90ZWN0ZWQgdXJsSGVscGVyOiBVcmxIZWxwZXJTZXJ2aWNlLFxyXG4gICAgcHJvdGVjdGVkIGxvZ2dlcjogT0F1dGhMb2dnZXIsXHJcbiAgICBAT3B0aW9uYWwoKSBwcm90ZWN0ZWQgY3J5cHRvOiBIYXNoSGFuZGxlcixcclxuICAgIEBJbmplY3QoRE9DVU1FTlQpIGRvY3VtZW50OiBhbnlcclxuICApIHtcclxuICAgIHN1cGVyKCk7XHJcblxyXG4gICAgdGhpcy5kZWJ1ZygnYW5ndWxhci1vYXV0aDItb2lkYyB2OC1iZXRhJyk7XHJcblxyXG4gICAgLy8gU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9tYW5mcmVkc3RleWVyL2FuZ3VsYXItb2F1dGgyLW9pZGMvaXNzdWVzLzc3MyBmb3Igd2h5IHRoaXMgaXMgbmVlZGVkXHJcbiAgICB0aGlzLmRvY3VtZW50ID0gZG9jdW1lbnQ7XHJcblxyXG4gICAgdGhpcy5kaXNjb3ZlcnlEb2N1bWVudExvYWRlZCQgPSB0aGlzLmRpc2NvdmVyeURvY3VtZW50TG9hZGVkU3ViamVjdC5hc09ic2VydmFibGUoKTtcclxuICAgIHRoaXMuZXZlbnRzID0gdGhpcy5ldmVudHNTdWJqZWN0LmFzT2JzZXJ2YWJsZSgpO1xyXG5cclxuICAgIGlmICh0b2tlblZhbGlkYXRpb25IYW5kbGVyKSB7XHJcbiAgICAgIHRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlciA9IHRva2VuVmFsaWRhdGlvbkhhbmRsZXI7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKGNvbmZpZykge1xyXG4gICAgICB0aGlzLmNvbmZpZ3VyZShjb25maWcpO1xyXG4gICAgfVxyXG5cclxuICAgIHRyeSB7XHJcbiAgICAgIGlmIChzdG9yYWdlKSB7XHJcbiAgICAgICAgdGhpcy5zZXRTdG9yYWdlKHN0b3JhZ2UpO1xyXG4gICAgICB9IGVsc2UgaWYgKHR5cGVvZiBzZXNzaW9uU3RvcmFnZSAhPT0gJ3VuZGVmaW5lZCcpIHtcclxuICAgICAgICB0aGlzLnNldFN0b3JhZ2Uoc2Vzc2lvblN0b3JhZ2UpO1xyXG4gICAgICB9XHJcbiAgICB9IGNhdGNoIChlKSB7XHJcbiAgICAgIGNvbnNvbGUuZXJyb3IoXHJcbiAgICAgICAgJ05vIE9BdXRoU3RvcmFnZSBwcm92aWRlZCBhbmQgY2Fubm90IGFjY2VzcyBkZWZhdWx0IChzZXNzaW9uU3RvcmFnZSkuJyArXHJcbiAgICAgICAgICAnQ29uc2lkZXIgcHJvdmlkaW5nIGEgY3VzdG9tIE9BdXRoU3RvcmFnZSBpbXBsZW1lbnRhdGlvbiBpbiB5b3VyIG1vZHVsZS4nLFxyXG4gICAgICAgIGVcclxuICAgICAgKTtcclxuICAgIH1cclxuXHJcbiAgICAvLyBpbiBJRSwgc2Vzc2lvblN0b3JhZ2UgZG9lcyBub3QgYWx3YXlzIHN1cnZpdmUgYSByZWRpcmVjdFxyXG4gICAgaWYgKFxyXG4gICAgICB0eXBlb2Ygd2luZG93ICE9PSAndW5kZWZpbmVkJyAmJlxyXG4gICAgICB0eXBlb2Ygd2luZG93Wydsb2NhbFN0b3JhZ2UnXSAhPT0gJ3VuZGVmaW5lZCdcclxuICAgICkge1xyXG4gICAgICBjb25zdCB1YSA9IHdpbmRvdz8ubmF2aWdhdG9yPy51c2VyQWdlbnQ7XHJcbiAgICAgIGNvbnN0IG1zaWUgPSB1YT8uaW5jbHVkZXMoJ01TSUUgJykgfHwgdWE/LmluY2x1ZGVzKCdUcmlkZW50Jyk7XHJcblxyXG4gICAgICBpZiAobXNpZSkge1xyXG4gICAgICAgIHRoaXMuc2F2ZU5vbmNlc0luTG9jYWxTdG9yYWdlID0gdHJ1ZTtcclxuICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIHRoaXMuc2V0dXBSZWZyZXNoVGltZXIoKTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFVzZSB0aGlzIG1ldGhvZCB0byBjb25maWd1cmUgdGhlIHNlcnZpY2VcclxuICAgKiBAcGFyYW0gY29uZmlnIHRoZSBjb25maWd1cmF0aW9uXHJcbiAgICovXHJcbiAgcHVibGljIGNvbmZpZ3VyZShjb25maWc6IEF1dGhDb25maWcpOiB2b2lkIHtcclxuICAgIC8vIEZvciB0aGUgc2FrZSBvZiBkb3dud2FyZCBjb21wYXRpYmlsaXR5IHdpdGhcclxuICAgIC8vIG9yaWdpbmFsIGNvbmZpZ3VyYXRpb24gQVBJXHJcbiAgICBPYmplY3QuYXNzaWduKHRoaXMsIG5ldyBBdXRoQ29uZmlnKCksIGNvbmZpZyk7XHJcblxyXG4gICAgdGhpcy5jb25maWcgPSBPYmplY3QuYXNzaWduKHt9IGFzIEF1dGhDb25maWcsIG5ldyBBdXRoQ29uZmlnKCksIGNvbmZpZyk7XHJcblxyXG4gICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQpIHtcclxuICAgICAgdGhpcy5zZXR1cFNlc3Npb25DaGVjaygpO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMuY29uZmlnQ2hhbmdlZCgpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGNvbmZpZ0NoYW5nZWQoKTogdm9pZCB7XHJcbiAgICB0aGlzLnNldHVwUmVmcmVzaFRpbWVyKCk7XHJcbiAgfVxyXG5cclxuICBwdWJsaWMgcmVzdGFydFNlc3Npb25DaGVja3NJZlN0aWxsTG9nZ2VkSW4oKTogdm9pZCB7XHJcbiAgICBpZiAodGhpcy5oYXNWYWxpZElkVG9rZW4oKSkge1xyXG4gICAgICB0aGlzLmluaXRTZXNzaW9uQ2hlY2soKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCByZXN0YXJ0UmVmcmVzaFRpbWVySWZTdGlsbExvZ2dlZEluKCk6IHZvaWQge1xyXG4gICAgdGhpcy5jbGVhckFjY2Vzc1Rva2VuVGltZXIoKTtcclxuICAgIHRoaXMuY2xlYXJJZFRva2VuVGltZXIoKTtcclxuICAgIHRoaXMuc2V0dXBFeHBpcmF0aW9uVGltZXJzKCk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgc2V0dXBTZXNzaW9uQ2hlY2soKTogdm9pZCB7XHJcbiAgICB0aGlzLmV2ZW50cy5waXBlKGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ3Rva2VuX3JlY2VpdmVkJykpLnN1YnNjcmliZShlID0+IHtcclxuICAgICAgdGhpcy5pbml0U2Vzc2lvbkNoZWNrKCk7XHJcbiAgICB9KTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFdpbGwgc2V0dXAgdXAgc2lsZW50IHJlZnJlc2hpbmcgZm9yIHdoZW4gdGhlIHRva2VuIGlzXHJcbiAgICogYWJvdXQgdG8gZXhwaXJlLiBXaGVuIHRoZSB1c2VyIGlzIGxvZ2dlZCBvdXQgdmlhIHRoaXMubG9nT3V0IG1ldGhvZCwgdGhlXHJcbiAgICogc2lsZW50IHJlZnJlc2hpbmcgd2lsbCBwYXVzZSBhbmQgbm90IHJlZnJlc2ggdGhlIHRva2VucyB1bnRpbCB0aGUgdXNlciBpc1xyXG4gICAqIGxvZ2dlZCBiYWNrIGluIHZpYSByZWNlaXZpbmcgYSBuZXcgdG9rZW4uXHJcbiAgICogQHBhcmFtIHBhcmFtcyBBZGRpdGlvbmFsIHBhcmFtZXRlciB0byBwYXNzXHJcbiAgICogQHBhcmFtIGxpc3RlblRvIFNldHVwIGF1dG9tYXRpYyByZWZyZXNoIG9mIGEgc3BlY2lmaWMgdG9rZW4gdHlwZVxyXG4gICAqL1xyXG4gIHB1YmxpYyBzZXR1cEF1dG9tYXRpY1NpbGVudFJlZnJlc2goXHJcbiAgICBwYXJhbXM6IG9iamVjdCA9IHt9LFxyXG4gICAgbGlzdGVuVG8/OiAnYWNjZXNzX3Rva2VuJyB8ICdpZF90b2tlbicgfCAnYW55JyxcclxuICAgIG5vUHJvbXB0ID0gdHJ1ZVxyXG4gICk6IHZvaWQge1xyXG4gICAgbGV0IHNob3VsZFJ1blNpbGVudFJlZnJlc2ggPSB0cnVlO1xyXG4gICAgdGhpcy5ldmVudHNcclxuICAgICAgLnBpcGUoXHJcbiAgICAgICAgdGFwKGUgPT4ge1xyXG4gICAgICAgICAgaWYgKGUudHlwZSA9PT0gJ3Rva2VuX3JlY2VpdmVkJykge1xyXG4gICAgICAgICAgICBzaG91bGRSdW5TaWxlbnRSZWZyZXNoID0gdHJ1ZTtcclxuICAgICAgICAgIH0gZWxzZSBpZiAoZS50eXBlID09PSAnbG9nb3V0Jykge1xyXG4gICAgICAgICAgICBzaG91bGRSdW5TaWxlbnRSZWZyZXNoID0gZmFsc2U7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgfSksXHJcbiAgICAgICAgZmlsdGVyKGUgPT4gZS50eXBlID09PSAndG9rZW5fZXhwaXJlcycpLFxyXG4gICAgICAgIGRlYm91bmNlVGltZSgxMDAwKVxyXG4gICAgICApXHJcbiAgICAgIC5zdWJzY3JpYmUoZSA9PiB7XHJcbiAgICAgICAgY29uc3QgZXZlbnQgPSBlIGFzIE9BdXRoSW5mb0V2ZW50O1xyXG4gICAgICAgIGlmIChcclxuICAgICAgICAgIChsaXN0ZW5UbyA9PSBudWxsIHx8IGxpc3RlblRvID09PSAnYW55JyB8fCBldmVudC5pbmZvID09PSBsaXN0ZW5UbykgJiZcclxuICAgICAgICAgIHNob3VsZFJ1blNpbGVudFJlZnJlc2hcclxuICAgICAgICApIHtcclxuICAgICAgICAgIC8vIHRoaXMuc2lsZW50UmVmcmVzaChwYXJhbXMsIG5vUHJvbXB0KS5jYXRjaChfID0+IHtcclxuICAgICAgICAgIHRoaXMucmVmcmVzaEludGVybmFsKHBhcmFtcywgbm9Qcm9tcHQpLmNhdGNoKF8gPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmRlYnVnKCdBdXRvbWF0aWMgc2lsZW50IHJlZnJlc2ggZGlkIG5vdCB3b3JrJyk7XHJcbiAgICAgICAgICB9KTtcclxuICAgICAgICB9XHJcbiAgICAgIH0pO1xyXG5cclxuICAgIHRoaXMucmVzdGFydFJlZnJlc2hUaW1lcklmU3RpbGxMb2dnZWRJbigpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHJlZnJlc2hJbnRlcm5hbChcclxuICAgIHBhcmFtcyxcclxuICAgIG5vUHJvbXB0XHJcbiAgKTogUHJvbWlzZTxUb2tlblJlc3BvbnNlIHwgT0F1dGhFdmVudD4ge1xyXG4gICAgaWYgKCF0aGlzLnVzZVNpbGVudFJlZnJlc2ggJiYgdGhpcy5yZXNwb25zZVR5cGUgPT09ICdjb2RlJykge1xyXG4gICAgICByZXR1cm4gdGhpcy5yZWZyZXNoVG9rZW4oKTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIHJldHVybiB0aGlzLnNpbGVudFJlZnJlc2gocGFyYW1zLCBub1Byb21wdCk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBDb252ZW5pZW5jZSBtZXRob2QgdGhhdCBmaXJzdCBjYWxscyBgbG9hZERpc2NvdmVyeURvY3VtZW50KC4uLilgIGFuZFxyXG4gICAqIGRpcmVjdGx5IGNoYWlucyB1c2luZyB0aGUgYHRoZW4oLi4uKWAgcGFydCBvZiB0aGUgcHJvbWlzZSB0byBjYWxsXHJcbiAgICogdGhlIGB0cnlMb2dpbiguLi4pYCBtZXRob2QuXHJcbiAgICpcclxuICAgKiBAcGFyYW0gb3B0aW9ucyBMb2dpbk9wdGlvbnMgdG8gcGFzcyB0aHJvdWdoIHRvIGB0cnlMb2dpbiguLi4pYFxyXG4gICAqL1xyXG4gIHB1YmxpYyBsb2FkRGlzY292ZXJ5RG9jdW1lbnRBbmRUcnlMb2dpbihcclxuICAgIG9wdGlvbnM6IExvZ2luT3B0aW9ucyA9IG51bGxcclxuICApOiBQcm9taXNlPGJvb2xlYW4+IHtcclxuICAgIHJldHVybiB0aGlzLmxvYWREaXNjb3ZlcnlEb2N1bWVudCgpLnRoZW4oZG9jID0+IHtcclxuICAgICAgcmV0dXJuIHRoaXMudHJ5TG9naW4ob3B0aW9ucyk7XHJcbiAgICB9KTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIENvbnZlbmllbmNlIG1ldGhvZCB0aGF0IGZpcnN0IGNhbGxzIGBsb2FkRGlzY292ZXJ5RG9jdW1lbnRBbmRUcnlMb2dpbiguLi4pYFxyXG4gICAqIGFuZCBpZiB0aGVuIGNoYWlucyB0byBgaW5pdExvZ2luRmxvdygpYCwgYnV0IG9ubHkgaWYgdGhlcmUgaXMgbm8gdmFsaWRcclxuICAgKiBJZFRva2VuIG9yIG5vIHZhbGlkIEFjY2Vzc1Rva2VuLlxyXG4gICAqXHJcbiAgICogQHBhcmFtIG9wdGlvbnMgTG9naW5PcHRpb25zIHRvIHBhc3MgdGhyb3VnaCB0byBgdHJ5TG9naW4oLi4uKWBcclxuICAgKi9cclxuICBwdWJsaWMgbG9hZERpc2NvdmVyeURvY3VtZW50QW5kTG9naW4oXHJcbiAgICBvcHRpb25zOiBMb2dpbk9wdGlvbnMgJiB7IHN0YXRlPzogc3RyaW5nIH0gPSBudWxsXHJcbiAgKTogUHJvbWlzZTxib29sZWFuPiB7XHJcbiAgICBvcHRpb25zID0gb3B0aW9ucyB8fCB7fTtcclxuICAgIHJldHVybiB0aGlzLmxvYWREaXNjb3ZlcnlEb2N1bWVudEFuZFRyeUxvZ2luKG9wdGlvbnMpLnRoZW4oXyA9PiB7XHJcbiAgICAgIGlmICghdGhpcy5oYXNWYWxpZElkVG9rZW4oKSB8fCAhdGhpcy5oYXNWYWxpZEFjY2Vzc1Rva2VuKCkpIHtcclxuICAgICAgICBjb25zdCBzdGF0ZSA9IHR5cGVvZiBvcHRpb25zLnN0YXRlID09PSAnc3RyaW5nJyA/IG9wdGlvbnMuc3RhdGUgOiAnJztcclxuICAgICAgICB0aGlzLmluaXRMb2dpbkZsb3coc3RhdGUpO1xyXG4gICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgfSBlbHNlIHtcclxuICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICAgfVxyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgZGVidWcoLi4uYXJncyk6IHZvaWQge1xyXG4gICAgaWYgKHRoaXMuc2hvd0RlYnVnSW5mb3JtYXRpb24pIHtcclxuICAgICAgdGhpcy5sb2dnZXIuZGVidWcuYXBwbHkodGhpcy5sb2dnZXIsIGFyZ3MpO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KHVybDogc3RyaW5nKTogc3RyaW5nW10ge1xyXG4gICAgY29uc3QgZXJyb3JzOiBzdHJpbmdbXSA9IFtdO1xyXG4gICAgY29uc3QgaHR0cHNDaGVjayA9IHRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh1cmwpO1xyXG4gICAgY29uc3QgaXNzdWVyQ2hlY2sgPSB0aGlzLnZhbGlkYXRlVXJsQWdhaW5zdElzc3Vlcih1cmwpO1xyXG5cclxuICAgIGlmICghaHR0cHNDaGVjaykge1xyXG4gICAgICBlcnJvcnMucHVzaChcclxuICAgICAgICAnaHR0cHMgZm9yIGFsbCB1cmxzIHJlcXVpcmVkLiBBbHNvIGZvciB1cmxzIHJlY2VpdmVkIGJ5IGRpc2NvdmVyeS4nXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCFpc3N1ZXJDaGVjaykge1xyXG4gICAgICBlcnJvcnMucHVzaChcclxuICAgICAgICAnRXZlcnkgdXJsIGluIGRpc2NvdmVyeSBkb2N1bWVudCBoYXMgdG8gc3RhcnQgd2l0aCB0aGUgaXNzdWVyIHVybC4nICtcclxuICAgICAgICAgICdBbHNvIHNlZSBwcm9wZXJ0eSBzdHJpY3REaXNjb3ZlcnlEb2N1bWVudFZhbGlkYXRpb24uJ1xyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiBlcnJvcnM7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgdmFsaWRhdGVVcmxGb3JIdHRwcyh1cmw6IHN0cmluZyk6IGJvb2xlYW4ge1xyXG4gICAgaWYgKCF1cmwpIHtcclxuICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgbGNVcmwgPSB1cmwudG9Mb3dlckNhc2UoKTtcclxuXHJcbiAgICBpZiAodGhpcy5yZXF1aXJlSHR0cHMgPT09IGZhbHNlKSB7XHJcbiAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgfVxyXG5cclxuICAgIGlmIChcclxuICAgICAgKGxjVXJsLm1hdGNoKC9eaHR0cDpcXC9cXC9sb2NhbGhvc3QoJHxbOlxcL10pLykgfHxcclxuICAgICAgICBsY1VybC5tYXRjaCgvXmh0dHA6XFwvXFwvbG9jYWxob3N0KCR8WzpcXC9dKS8pKSAmJlxyXG4gICAgICB0aGlzLnJlcXVpcmVIdHRwcyA9PT0gJ3JlbW90ZU9ubHknXHJcbiAgICApIHtcclxuICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIGxjVXJsLnN0YXJ0c1dpdGgoJ2h0dHBzOi8vJyk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgYXNzZXJ0VXJsTm90TnVsbEFuZENvcnJlY3RQcm90b2NvbChcclxuICAgIHVybDogc3RyaW5nIHwgdW5kZWZpbmVkLFxyXG4gICAgZGVzY3JpcHRpb246IHN0cmluZ1xyXG4gICkge1xyXG4gICAgaWYgKCF1cmwpIHtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKGAnJHtkZXNjcmlwdGlvbn0nIHNob3VsZCBub3QgYmUgbnVsbGApO1xyXG4gICAgfVxyXG4gICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModXJsKSkge1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXHJcbiAgICAgICAgYCcke2Rlc2NyaXB0aW9ufScgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSAncmVxdWlyZUh0dHBzJyBtdXN0IGJlIHNldCB0byAnZmFsc2UnIGFuZCBhbGxvdyBIVFRQICh3aXRob3V0IFRMUykuYFxyXG4gICAgICApO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHZhbGlkYXRlVXJsQWdhaW5zdElzc3Vlcih1cmw6IHN0cmluZykge1xyXG4gICAgaWYgKCF0aGlzLnN0cmljdERpc2NvdmVyeURvY3VtZW50VmFsaWRhdGlvbikge1xyXG4gICAgICByZXR1cm4gdHJ1ZTtcclxuICAgIH1cclxuICAgIGlmICghdXJsKSB7XHJcbiAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIHVybC50b0xvd2VyQ2FzZSgpLnN0YXJ0c1dpdGgodGhpcy5pc3N1ZXIudG9Mb3dlckNhc2UoKSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgc2V0dXBSZWZyZXNoVGltZXIoKTogdm9pZCB7XHJcbiAgICBpZiAodHlwZW9mIHdpbmRvdyA9PT0gJ3VuZGVmaW5lZCcpIHtcclxuICAgICAgdGhpcy5kZWJ1ZygndGltZXIgbm90IHN1cHBvcnRlZCBvbiB0aGlzIHBsYXR0Zm9ybScpO1xyXG4gICAgICByZXR1cm47XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHRoaXMuaGFzVmFsaWRJZFRva2VuKCkgfHwgdGhpcy5oYXNWYWxpZEFjY2Vzc1Rva2VuKCkpIHtcclxuICAgICAgdGhpcy5jbGVhckFjY2Vzc1Rva2VuVGltZXIoKTtcclxuICAgICAgdGhpcy5jbGVhcklkVG9rZW5UaW1lcigpO1xyXG4gICAgICB0aGlzLnNldHVwRXhwaXJhdGlvblRpbWVycygpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICh0aGlzLnRva2VuUmVjZWl2ZWRTdWJzY3JpcHRpb24pXHJcbiAgICAgIHRoaXMudG9rZW5SZWNlaXZlZFN1YnNjcmlwdGlvbi51bnN1YnNjcmliZSgpO1xyXG5cclxuICAgIHRoaXMudG9rZW5SZWNlaXZlZFN1YnNjcmlwdGlvbiA9IHRoaXMuZXZlbnRzXHJcbiAgICAgIC5waXBlKGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ3Rva2VuX3JlY2VpdmVkJykpXHJcbiAgICAgIC5zdWJzY3JpYmUoXyA9PiB7XHJcbiAgICAgICAgdGhpcy5jbGVhckFjY2Vzc1Rva2VuVGltZXIoKTtcclxuICAgICAgICB0aGlzLmNsZWFySWRUb2tlblRpbWVyKCk7XHJcbiAgICAgICAgdGhpcy5zZXR1cEV4cGlyYXRpb25UaW1lcnMoKTtcclxuICAgICAgfSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgc2V0dXBFeHBpcmF0aW9uVGltZXJzKCk6IHZvaWQge1xyXG4gICAgaWYgKHRoaXMuaGFzVmFsaWRBY2Nlc3NUb2tlbigpKSB7XHJcbiAgICAgIHRoaXMuc2V0dXBBY2Nlc3NUb2tlblRpbWVyKCk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHRoaXMuaGFzVmFsaWRJZFRva2VuKCkpIHtcclxuICAgICAgdGhpcy5zZXR1cElkVG9rZW5UaW1lcigpO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHNldHVwQWNjZXNzVG9rZW5UaW1lcigpOiB2b2lkIHtcclxuICAgIGNvbnN0IGV4cGlyYXRpb24gPSB0aGlzLmdldEFjY2Vzc1Rva2VuRXhwaXJhdGlvbigpO1xyXG4gICAgY29uc3Qgc3RvcmVkQXQgPSB0aGlzLmdldEFjY2Vzc1Rva2VuU3RvcmVkQXQoKTtcclxuICAgIGNvbnN0IHRpbWVvdXQgPSB0aGlzLmNhbGNUaW1lb3V0KHN0b3JlZEF0LCBleHBpcmF0aW9uKTtcclxuXHJcbiAgICB0aGlzLm5nWm9uZS5ydW5PdXRzaWRlQW5ndWxhcigoKSA9PiB7XHJcbiAgICAgIHRoaXMuYWNjZXNzVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uID0gb2YoXHJcbiAgICAgICAgbmV3IE9BdXRoSW5mb0V2ZW50KCd0b2tlbl9leHBpcmVzJywgJ2FjY2Vzc190b2tlbicpXHJcbiAgICAgIClcclxuICAgICAgICAucGlwZShkZWxheSh0aW1lb3V0KSlcclxuICAgICAgICAuc3Vic2NyaWJlKGUgPT4ge1xyXG4gICAgICAgICAgdGhpcy5uZ1pvbmUucnVuKCgpID0+IHtcclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZSk7XHJcbiAgICAgICAgICB9KTtcclxuICAgICAgICB9KTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHNldHVwSWRUb2tlblRpbWVyKCk6IHZvaWQge1xyXG4gICAgY29uc3QgZXhwaXJhdGlvbiA9IHRoaXMuZ2V0SWRUb2tlbkV4cGlyYXRpb24oKTtcclxuICAgIGNvbnN0IHN0b3JlZEF0ID0gdGhpcy5nZXRJZFRva2VuU3RvcmVkQXQoKTtcclxuICAgIGNvbnN0IHRpbWVvdXQgPSB0aGlzLmNhbGNUaW1lb3V0KHN0b3JlZEF0LCBleHBpcmF0aW9uKTtcclxuXHJcbiAgICB0aGlzLm5nWm9uZS5ydW5PdXRzaWRlQW5ndWxhcigoKSA9PiB7XHJcbiAgICAgIHRoaXMuaWRUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24gPSBvZihcclxuICAgICAgICBuZXcgT0F1dGhJbmZvRXZlbnQoJ3Rva2VuX2V4cGlyZXMnLCAnaWRfdG9rZW4nKVxyXG4gICAgICApXHJcbiAgICAgICAgLnBpcGUoZGVsYXkodGltZW91dCkpXHJcbiAgICAgICAgLnN1YnNjcmliZShlID0+IHtcclxuICAgICAgICAgIHRoaXMubmdab25lLnJ1bigoKSA9PiB7XHJcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xyXG4gICAgICAgICAgfSk7XHJcbiAgICAgICAgfSk7XHJcbiAgICB9KTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFN0b3BzIHRpbWVycyBmb3IgYXV0b21hdGljIHJlZnJlc2guXHJcbiAgICogVG8gcmVzdGFydCBpdCwgY2FsbCBzZXR1cEF1dG9tYXRpY1NpbGVudFJlZnJlc2ggYWdhaW4uXHJcbiAgICovXHJcbiAgcHVibGljIHN0b3BBdXRvbWF0aWNSZWZyZXNoKCkge1xyXG4gICAgdGhpcy5jbGVhckFjY2Vzc1Rva2VuVGltZXIoKTtcclxuICAgIHRoaXMuY2xlYXJJZFRva2VuVGltZXIoKTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBjbGVhckFjY2Vzc1Rva2VuVGltZXIoKTogdm9pZCB7XHJcbiAgICBpZiAodGhpcy5hY2Nlc3NUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24pIHtcclxuICAgICAgdGhpcy5hY2Nlc3NUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24udW5zdWJzY3JpYmUoKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBjbGVhcklkVG9rZW5UaW1lcigpOiB2b2lkIHtcclxuICAgIGlmICh0aGlzLmlkVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uKSB7XHJcbiAgICAgIHRoaXMuaWRUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24udW5zdWJzY3JpYmUoKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBjYWxjVGltZW91dChzdG9yZWRBdDogbnVtYmVyLCBleHBpcmF0aW9uOiBudW1iZXIpOiBudW1iZXIge1xyXG4gICAgY29uc3Qgbm93ID0gRGF0ZS5ub3coKTtcclxuICAgIGNvbnN0IGRlbHRhID1cclxuICAgICAgKGV4cGlyYXRpb24gLSBzdG9yZWRBdCkgKiB0aGlzLnRpbWVvdXRGYWN0b3IgLSAobm93IC0gc3RvcmVkQXQpO1xyXG4gICAgcmV0dXJuIE1hdGgubWF4KDAsIGRlbHRhKTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIERFUFJFQ0FURUQuIFVzZSBhIHByb3ZpZGVyIGZvciBPQXV0aFN0b3JhZ2UgaW5zdGVhZDpcclxuICAgKlxyXG4gICAqIHsgcHJvdmlkZTogT0F1dGhTdG9yYWdlLCB1c2VGYWN0b3J5OiBvQXV0aFN0b3JhZ2VGYWN0b3J5IH1cclxuICAgKiBleHBvcnQgZnVuY3Rpb24gb0F1dGhTdG9yYWdlRmFjdG9yeSgpOiBPQXV0aFN0b3JhZ2UgeyByZXR1cm4gbG9jYWxTdG9yYWdlOyB9XHJcbiAgICogU2V0cyBhIGN1c3RvbSBzdG9yYWdlIHVzZWQgdG8gc3RvcmUgdGhlIHJlY2VpdmVkXHJcbiAgICogdG9rZW5zIG9uIGNsaWVudCBzaWRlLiBCeSBkZWZhdWx0LCB0aGUgYnJvd3NlcidzXHJcbiAgICogc2Vzc2lvblN0b3JhZ2UgaXMgdXNlZC5cclxuICAgKiBAaWdub3JlXHJcbiAgICpcclxuICAgKiBAcGFyYW0gc3RvcmFnZVxyXG4gICAqL1xyXG4gIHB1YmxpYyBzZXRTdG9yYWdlKHN0b3JhZ2U6IE9BdXRoU3RvcmFnZSk6IHZvaWQge1xyXG4gICAgdGhpcy5fc3RvcmFnZSA9IHN0b3JhZ2U7XHJcbiAgICB0aGlzLmNvbmZpZ0NoYW5nZWQoKTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIExvYWRzIHRoZSBkaXNjb3ZlcnkgZG9jdW1lbnQgdG8gY29uZmlndXJlIG1vc3RcclxuICAgKiBwcm9wZXJ0aWVzIG9mIHRoaXMgc2VydmljZS4gVGhlIHVybCBvZiB0aGUgZGlzY292ZXJ5XHJcbiAgICogZG9jdW1lbnQgaXMgaW5mZXJlZCBmcm9tIHRoZSBpc3N1ZXIncyB1cmwgYWNjb3JkaW5nXHJcbiAgICogdG8gdGhlIE9wZW5JZCBDb25uZWN0IHNwZWMuIFRvIHVzZSBhbm90aGVyIHVybCB5b3VcclxuICAgKiBjYW4gcGFzcyBpdCB0byB0byBvcHRpb25hbCBwYXJhbWV0ZXIgZnVsbFVybC5cclxuICAgKlxyXG4gICAqIEBwYXJhbSBmdWxsVXJsXHJcbiAgICovXHJcbiAgcHVibGljIGxvYWREaXNjb3ZlcnlEb2N1bWVudChcclxuICAgIGZ1bGxVcmw6IHN0cmluZyA9IG51bGxcclxuICApOiBQcm9taXNlPE9BdXRoU3VjY2Vzc0V2ZW50PiB7XHJcbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xyXG4gICAgICBpZiAoIWZ1bGxVcmwpIHtcclxuICAgICAgICBmdWxsVXJsID0gdGhpcy5pc3N1ZXIgfHwgJyc7XHJcbiAgICAgICAgaWYgKCFmdWxsVXJsLmVuZHNXaXRoKCcvJykpIHtcclxuICAgICAgICAgIGZ1bGxVcmwgKz0gJy8nO1xyXG4gICAgICAgIH1cclxuICAgICAgICBmdWxsVXJsICs9ICcud2VsbC1rbm93bi9vcGVuaWQtY29uZmlndXJhdGlvbic7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKGZ1bGxVcmwpKSB7XHJcbiAgICAgICAgcmVqZWN0KFxyXG4gICAgICAgICAgXCJpc3N1ZXIgIG11c3QgdXNlIEhUVFBTICh3aXRoIFRMUyksIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgJ3JlcXVpcmVIdHRwcycgbXVzdCBiZSBzZXQgdG8gJ2ZhbHNlJyBhbmQgYWxsb3cgSFRUUCAod2l0aG91dCBUTFMpLlwiXHJcbiAgICAgICAgKTtcclxuICAgICAgICByZXR1cm47XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIHRoaXMuaHR0cC5nZXQ8T2lkY0Rpc2NvdmVyeURvYz4oZnVsbFVybCkuc3Vic2NyaWJlKFxyXG4gICAgICAgIGRvYyA9PiB7XHJcbiAgICAgICAgICBpZiAoIXRoaXMudmFsaWRhdGVEaXNjb3ZlcnlEb2N1bWVudChkb2MpKSB7XHJcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxyXG4gICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ2Rpc2NvdmVyeV9kb2N1bWVudF92YWxpZGF0aW9uX2Vycm9yJywgbnVsbClcclxuICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgcmVqZWN0KCdkaXNjb3ZlcnlfZG9jdW1lbnRfdmFsaWRhdGlvbl9lcnJvcicpO1xyXG4gICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgdGhpcy5sb2dpblVybCA9IGRvYy5hdXRob3JpemF0aW9uX2VuZHBvaW50O1xyXG4gICAgICAgICAgdGhpcy5sb2dvdXRVcmwgPSBkb2MuZW5kX3Nlc3Npb25fZW5kcG9pbnQgfHwgdGhpcy5sb2dvdXRVcmw7XHJcbiAgICAgICAgICB0aGlzLmdyYW50VHlwZXNTdXBwb3J0ZWQgPSBkb2MuZ3JhbnRfdHlwZXNfc3VwcG9ydGVkO1xyXG4gICAgICAgICAgdGhpcy5pc3N1ZXIgPSBkb2MuaXNzdWVyO1xyXG4gICAgICAgICAgdGhpcy50b2tlbkVuZHBvaW50ID0gdGhpcy50b2tlbkVuZHBvaW50XHJcbiAgICAgICAgICAgID8gdGhpcy50b2tlbkVuZHBvaW50XHJcbiAgICAgICAgICAgIDogZG9jLnRva2VuX2VuZHBvaW50O1xyXG4gICAgICAgICAgdGhpcy51c2VyaW5mb0VuZHBvaW50ID1cclxuICAgICAgICAgICAgZG9jLnVzZXJpbmZvX2VuZHBvaW50IHx8IHRoaXMudXNlcmluZm9FbmRwb2ludDtcclxuICAgICAgICAgIHRoaXMuandrc1VyaSA9IGRvYy5qd2tzX3VyaTtcclxuICAgICAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lVXJsID1cclxuICAgICAgICAgICAgZG9jLmNoZWNrX3Nlc3Npb25faWZyYW1lIHx8IHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lVXJsO1xyXG5cclxuICAgICAgICAgIHRoaXMuZGlzY292ZXJ5RG9jdW1lbnRMb2FkZWQgPSB0cnVlO1xyXG4gICAgICAgICAgdGhpcy5kaXNjb3ZlcnlEb2N1bWVudExvYWRlZFN1YmplY3QubmV4dChkb2MpO1xyXG4gICAgICAgICAgdGhpcy5yZXZvY2F0aW9uRW5kcG9pbnQgPSBkb2MucmV2b2NhdGlvbl9lbmRwb2ludDtcclxuXHJcbiAgICAgICAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCkge1xyXG4gICAgICAgICAgICB0aGlzLnJlc3RhcnRTZXNzaW9uQ2hlY2tzSWZTdGlsbExvZ2dlZEluKCk7XHJcbiAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgdGhpcy5sb2FkSndrcygpXHJcbiAgICAgICAgICAgIC50aGVuKGp3a3MgPT4ge1xyXG4gICAgICAgICAgICAgIGNvbnN0IHJlc3VsdDogb2JqZWN0ID0ge1xyXG4gICAgICAgICAgICAgICAgZGlzY292ZXJ5RG9jdW1lbnQ6IGRvYyxcclxuICAgICAgICAgICAgICAgIGp3a3M6IGp3a3NcclxuICAgICAgICAgICAgICB9O1xyXG5cclxuICAgICAgICAgICAgICBjb25zdCBldmVudCA9IG5ldyBPQXV0aFN1Y2Nlc3NFdmVudChcclxuICAgICAgICAgICAgICAgICdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJyxcclxuICAgICAgICAgICAgICAgIHJlc3VsdFxyXG4gICAgICAgICAgICAgICk7XHJcbiAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZXZlbnQpO1xyXG4gICAgICAgICAgICAgIHJlc29sdmUoZXZlbnQpO1xyXG4gICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgfSlcclxuICAgICAgICAgICAgLmNhdGNoKGVyciA9PiB7XHJcbiAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXHJcbiAgICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZF9lcnJvcicsIGVycilcclxuICAgICAgICAgICAgICApO1xyXG4gICAgICAgICAgICAgIHJlamVjdChlcnIpO1xyXG4gICAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgICAgfSk7XHJcbiAgICAgICAgfSxcclxuICAgICAgICBlcnIgPT4ge1xyXG4gICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ2Vycm9yIGxvYWRpbmcgZGlzY292ZXJ5IGRvY3VtZW50JywgZXJyKTtcclxuICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxyXG4gICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZF9lcnJvcicsIGVycilcclxuICAgICAgICAgICk7XHJcbiAgICAgICAgICByZWplY3QoZXJyKTtcclxuICAgICAgICB9XHJcbiAgICAgICk7XHJcbiAgICB9KTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBsb2FkSndrcygpOiBQcm9taXNlPG9iamVjdD4ge1xyXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlPG9iamVjdD4oKHJlc29sdmUsIHJlamVjdCkgPT4ge1xyXG4gICAgICBpZiAodGhpcy5qd2tzVXJpKSB7XHJcbiAgICAgICAgdGhpcy5odHRwLmdldCh0aGlzLmp3a3NVcmkpLnN1YnNjcmliZShcclxuICAgICAgICAgIGp3a3MgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmp3a3MgPSBqd2tzO1xyXG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcclxuICAgICAgICAgICAgICBuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkZWQnKVxyXG4gICAgICAgICAgICApO1xyXG4gICAgICAgICAgICByZXNvbHZlKGp3a3MpO1xyXG4gICAgICAgICAgfSxcclxuICAgICAgICAgIGVyciA9PiB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdlcnJvciBsb2FkaW5nIGp3a3MnLCBlcnIpO1xyXG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcclxuICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCdqd2tzX2xvYWRfZXJyb3InLCBlcnIpXHJcbiAgICAgICAgICAgICk7XHJcbiAgICAgICAgICAgIHJlamVjdChlcnIpO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICk7XHJcbiAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgcmVzb2x2ZShudWxsKTtcclxuICAgICAgfVxyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgdmFsaWRhdGVEaXNjb3ZlcnlEb2N1bWVudChkb2M6IE9pZGNEaXNjb3ZlcnlEb2MpOiBib29sZWFuIHtcclxuICAgIGxldCBlcnJvcnM6IHN0cmluZ1tdO1xyXG5cclxuICAgIGlmICghdGhpcy5za2lwSXNzdWVyQ2hlY2sgJiYgZG9jLmlzc3VlciAhPT0gdGhpcy5pc3N1ZXIpIHtcclxuICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXHJcbiAgICAgICAgJ2ludmFsaWQgaXNzdWVyIGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXHJcbiAgICAgICAgJ2V4cGVjdGVkOiAnICsgdGhpcy5pc3N1ZXIsXHJcbiAgICAgICAgJ2N1cnJlbnQ6ICcgKyBkb2MuaXNzdWVyXHJcbiAgICAgICk7XHJcbiAgICAgIHJldHVybiBmYWxzZTtcclxuICAgIH1cclxuXHJcbiAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy5hdXRob3JpemF0aW9uX2VuZHBvaW50KTtcclxuICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xyXG4gICAgICB0aGlzLmxvZ2dlci5lcnJvcihcclxuICAgICAgICAnZXJyb3IgdmFsaWRhdGluZyBhdXRob3JpemF0aW9uX2VuZHBvaW50IGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXHJcbiAgICAgICAgZXJyb3JzXHJcbiAgICAgICk7XHJcbiAgICAgIHJldHVybiBmYWxzZTtcclxuICAgIH1cclxuXHJcbiAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy5lbmRfc2Vzc2lvbl9lbmRwb2ludCk7XHJcbiAgICBpZiAoZXJyb3JzLmxlbmd0aCA+IDApIHtcclxuICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXHJcbiAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgZW5kX3Nlc3Npb25fZW5kcG9pbnQgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcclxuICAgICAgICBlcnJvcnNcclxuICAgICAgKTtcclxuICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgfVxyXG5cclxuICAgIGVycm9ycyA9IHRoaXMudmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQoZG9jLnRva2VuX2VuZHBvaW50KTtcclxuICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xyXG4gICAgICB0aGlzLmxvZ2dlci5lcnJvcihcclxuICAgICAgICAnZXJyb3IgdmFsaWRhdGluZyB0b2tlbl9lbmRwb2ludCBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxyXG4gICAgICAgIGVycm9yc1xyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIGVycm9ycyA9IHRoaXMudmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQoZG9jLnJldm9jYXRpb25fZW5kcG9pbnQpO1xyXG4gICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XHJcbiAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxyXG4gICAgICAgICdlcnJvciB2YWxpZGF0aW5nIHJldm9jYXRpb25fZW5kcG9pbnQgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcclxuICAgICAgICBlcnJvcnNcclxuICAgICAgKTtcclxuICAgIH1cclxuXHJcbiAgICBlcnJvcnMgPSB0aGlzLnZhbGlkYXRlVXJsRnJvbURpc2NvdmVyeURvY3VtZW50KGRvYy51c2VyaW5mb19lbmRwb2ludCk7XHJcbiAgICBpZiAoZXJyb3JzLmxlbmd0aCA+IDApIHtcclxuICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXHJcbiAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgdXNlcmluZm9fZW5kcG9pbnQgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcclxuICAgICAgICBlcnJvcnNcclxuICAgICAgKTtcclxuICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgfVxyXG5cclxuICAgIGVycm9ycyA9IHRoaXMudmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQoZG9jLmp3a3NfdXJpKTtcclxuICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xyXG4gICAgICB0aGlzLmxvZ2dlci5lcnJvcihcclxuICAgICAgICAnZXJyb3IgdmFsaWRhdGluZyBqd2tzX3VyaSBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxyXG4gICAgICAgIGVycm9yc1xyXG4gICAgICApO1xyXG4gICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQgJiYgIWRvYy5jaGVja19zZXNzaW9uX2lmcmFtZSkge1xyXG4gICAgICB0aGlzLmxvZ2dlci53YXJuKFxyXG4gICAgICAgICdzZXNzaW9uQ2hlY2tzRW5hYmxlZCBpcyBhY3RpdmF0ZWQgYnV0IGRpc2NvdmVyeSBkb2N1bWVudCcgK1xyXG4gICAgICAgICAgJyBkb2VzIG5vdCBjb250YWluIGEgY2hlY2tfc2Vzc2lvbl9pZnJhbWUgZmllbGQnXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHRydWU7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBVc2VzIHBhc3N3b3JkIGZsb3cgdG8gZXhjaGFuZ2UgdXNlck5hbWUgYW5kIHBhc3N3b3JkIGZvciBhblxyXG4gICAqIGFjY2Vzc190b2tlbi4gQWZ0ZXIgcmVjZWl2aW5nIHRoZSBhY2Nlc3NfdG9rZW4sIHRoaXMgbWV0aG9kXHJcbiAgICogdXNlcyBpdCB0byBxdWVyeSB0aGUgdXNlcmluZm8gZW5kcG9pbnQgaW4gb3JkZXIgdG8gZ2V0IGluZm9ybWF0aW9uXHJcbiAgICogYWJvdXQgdGhlIHVzZXIgaW4gcXVlc3Rpb24uXHJcbiAgICpcclxuICAgKiBXaGVuIHVzaW5nIHRoaXMsIG1ha2Ugc3VyZSB0aGF0IHRoZSBwcm9wZXJ0eSBvaWRjIGlzIHNldCB0byBmYWxzZS5cclxuICAgKiBPdGhlcndpc2Ugc3RyaWN0ZXIgdmFsaWRhdGlvbnMgdGFrZSBwbGFjZSB0aGF0IG1ha2UgdGhpcyBvcGVyYXRpb25cclxuICAgKiBmYWlsLlxyXG4gICAqXHJcbiAgICogQHBhcmFtIHVzZXJOYW1lXHJcbiAgICogQHBhcmFtIHBhc3N3b3JkXHJcbiAgICogQHBhcmFtIGhlYWRlcnMgT3B0aW9uYWwgYWRkaXRpb25hbCBodHRwLWhlYWRlcnMuXHJcbiAgICovXHJcbiAgcHVibGljIGZldGNoVG9rZW5Vc2luZ1Bhc3N3b3JkRmxvd0FuZExvYWRVc2VyUHJvZmlsZShcclxuICAgIHVzZXJOYW1lOiBzdHJpbmcsXHJcbiAgICBwYXNzd29yZDogc3RyaW5nLFxyXG4gICAgaGVhZGVyczogSHR0cEhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKVxyXG4gICk6IFByb21pc2U8VXNlckluZm8+IHtcclxuICAgIHJldHVybiB0aGlzLmZldGNoVG9rZW5Vc2luZ1Bhc3N3b3JkRmxvdyhcclxuICAgICAgdXNlck5hbWUsXHJcbiAgICAgIHBhc3N3b3JkLFxyXG4gICAgICBoZWFkZXJzXHJcbiAgICApLnRoZW4oKCkgPT4gdGhpcy5sb2FkVXNlclByb2ZpbGUoKSk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBMb2FkcyB0aGUgdXNlciBwcm9maWxlIGJ5IGFjY2Vzc2luZyB0aGUgdXNlciBpbmZvIGVuZHBvaW50IGRlZmluZWQgYnkgT3BlbklkIENvbm5lY3QuXHJcbiAgICpcclxuICAgKiBXaGVuIHVzaW5nIHRoaXMgd2l0aCBPQXV0aDIgcGFzc3dvcmQgZmxvdywgbWFrZSBzdXJlIHRoYXQgdGhlIHByb3BlcnR5IG9pZGMgaXMgc2V0IHRvIGZhbHNlLlxyXG4gICAqIE90aGVyd2lzZSBzdHJpY3RlciB2YWxpZGF0aW9ucyB0YWtlIHBsYWNlIHRoYXQgbWFrZSB0aGlzIG9wZXJhdGlvbiBmYWlsLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBsb2FkVXNlclByb2ZpbGUoKTogUHJvbWlzZTxVc2VySW5mbz4ge1xyXG4gICAgaWYgKCF0aGlzLmhhc1ZhbGlkQWNjZXNzVG9rZW4oKSkge1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoJ0NhbiBub3QgbG9hZCBVc2VyIFByb2ZpbGUgd2l0aG91dCBhY2Nlc3NfdG9rZW4nKTtcclxuICAgIH1cclxuICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMudXNlcmluZm9FbmRwb2ludCkpIHtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKFxyXG4gICAgICAgIFwidXNlcmluZm9FbmRwb2ludCBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5ICdyZXF1aXJlSHR0cHMnIG11c3QgYmUgc2V0IHRvICdmYWxzZScgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS5cIlxyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XHJcbiAgICAgIGNvbnN0IGhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKS5zZXQoXHJcbiAgICAgICAgJ0F1dGhvcml6YXRpb24nLFxyXG4gICAgICAgICdCZWFyZXIgJyArIHRoaXMuZ2V0QWNjZXNzVG9rZW4oKVxyXG4gICAgICApO1xyXG5cclxuICAgICAgdGhpcy5odHRwXHJcbiAgICAgICAgLmdldDxVc2VySW5mbz4odGhpcy51c2VyaW5mb0VuZHBvaW50LCB7IGhlYWRlcnMgfSlcclxuICAgICAgICAuc3Vic2NyaWJlKFxyXG4gICAgICAgICAgaW5mbyA9PiB7XHJcbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ3VzZXJpbmZvIHJlY2VpdmVkJywgaW5mbyk7XHJcblxyXG4gICAgICAgICAgICBjb25zdCBleGlzdGluZ0NsYWltcyA9IHRoaXMuZ2V0SWRlbnRpdHlDbGFpbXMoKSB8fCB7fTtcclxuXHJcbiAgICAgICAgICAgIGlmICghdGhpcy5za2lwU3ViamVjdENoZWNrKSB7XHJcbiAgICAgICAgICAgICAgaWYgKFxyXG4gICAgICAgICAgICAgICAgdGhpcy5vaWRjICYmXHJcbiAgICAgICAgICAgICAgICAoIWV4aXN0aW5nQ2xhaW1zWydzdWInXSB8fCBpbmZvLnN1YiAhPT0gZXhpc3RpbmdDbGFpbXNbJ3N1YiddKVxyXG4gICAgICAgICAgICAgICkge1xyXG4gICAgICAgICAgICAgICAgY29uc3QgZXJyID1cclxuICAgICAgICAgICAgICAgICAgJ2lmIHByb3BlcnR5IG9pZGMgaXMgdHJ1ZSwgdGhlIHJlY2VpdmVkIHVzZXItaWQgKHN1YikgaGFzIHRvIGJlIHRoZSB1c2VyLWlkICcgK1xyXG4gICAgICAgICAgICAgICAgICAnb2YgdGhlIHVzZXIgdGhhdCBoYXMgbG9nZ2VkIGluIHdpdGggb2lkYy5cXG4nICtcclxuICAgICAgICAgICAgICAgICAgJ2lmIHlvdSBhcmUgbm90IHVzaW5nIG9pZGMgYnV0IGp1c3Qgb2F1dGgyIHBhc3N3b3JkIGZsb3cgc2V0IG9pZGMgdG8gZmFsc2UnO1xyXG5cclxuICAgICAgICAgICAgICAgIHJlamVjdChlcnIpO1xyXG4gICAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgfVxyXG5cclxuICAgICAgICAgICAgaW5mbyA9IE9iamVjdC5hc3NpZ24oe30sIGV4aXN0aW5nQ2xhaW1zLCBpbmZvKTtcclxuXHJcbiAgICAgICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnaWRfdG9rZW5fY2xhaW1zX29iaicsIEpTT04uc3RyaW5naWZ5KGluZm8pKTtcclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXHJcbiAgICAgICAgICAgICAgbmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd1c2VyX3Byb2ZpbGVfbG9hZGVkJylcclxuICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgcmVzb2x2ZShpbmZvKTtcclxuICAgICAgICAgIH0sXHJcbiAgICAgICAgICBlcnIgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignZXJyb3IgbG9hZGluZyB1c2VyIGluZm8nLCBlcnIpO1xyXG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcclxuICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd1c2VyX3Byb2ZpbGVfbG9hZF9lcnJvcicsIGVycilcclxuICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgcmVqZWN0KGVycik7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgKTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogVXNlcyBwYXNzd29yZCBmbG93IHRvIGV4Y2hhbmdlIHVzZXJOYW1lIGFuZCBwYXNzd29yZCBmb3IgYW4gYWNjZXNzX3Rva2VuLlxyXG4gICAqIEBwYXJhbSB1c2VyTmFtZVxyXG4gICAqIEBwYXJhbSBwYXNzd29yZFxyXG4gICAqIEBwYXJhbSBoZWFkZXJzIE9wdGlvbmFsIGFkZGl0aW9uYWwgaHR0cC1oZWFkZXJzLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBmZXRjaFRva2VuVXNpbmdQYXNzd29yZEZsb3coXHJcbiAgICB1c2VyTmFtZTogc3RyaW5nLFxyXG4gICAgcGFzc3dvcmQ6IHN0cmluZyxcclxuICAgIGhlYWRlcnM6IEh0dHBIZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKClcclxuICApOiBQcm9taXNlPFRva2VuUmVzcG9uc2U+IHtcclxuICAgIHRoaXMuYXNzZXJ0VXJsTm90TnVsbEFuZENvcnJlY3RQcm90b2NvbChcclxuICAgICAgdGhpcy50b2tlbkVuZHBvaW50LFxyXG4gICAgICAndG9rZW5FbmRwb2ludCdcclxuICAgICk7XHJcblxyXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcclxuICAgICAgLyoqXHJcbiAgICAgICAqIEEgYEh0dHBQYXJhbWV0ZXJDb2RlY2AgdGhhdCB1c2VzIGBlbmNvZGVVUklDb21wb25lbnRgIGFuZCBgZGVjb2RlVVJJQ29tcG9uZW50YCB0b1xyXG4gICAgICAgKiBzZXJpYWxpemUgYW5kIHBhcnNlIFVSTCBwYXJhbWV0ZXIga2V5cyBhbmQgdmFsdWVzLlxyXG4gICAgICAgKlxyXG4gICAgICAgKiBAc3RhYmxlXHJcbiAgICAgICAqL1xyXG4gICAgICBsZXQgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoeyBlbmNvZGVyOiBuZXcgV2ViSHR0cFVybEVuY29kaW5nQ29kZWMoKSB9KVxyXG4gICAgICAgIC5zZXQoJ2dyYW50X3R5cGUnLCAncGFzc3dvcmQnKVxyXG4gICAgICAgIC5zZXQoJ3Njb3BlJywgdGhpcy5zY29wZSlcclxuICAgICAgICAuc2V0KCd1c2VybmFtZScsIHVzZXJOYW1lKVxyXG4gICAgICAgIC5zZXQoJ3Bhc3N3b3JkJywgcGFzc3dvcmQpO1xyXG5cclxuICAgICAgaWYgKHRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xyXG4gICAgICAgIGNvbnN0IGhlYWRlciA9IGJ0b2EoYCR7dGhpcy5jbGllbnRJZH06JHt0aGlzLmR1bW15Q2xpZW50U2VjcmV0fWApO1xyXG4gICAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldCgnQXV0aG9yaXphdGlvbicsICdCYXNpYyAnICsgaGVhZGVyKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgaWYgKCF0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcclxuICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfaWQnLCB0aGlzLmNsaWVudElkKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgaWYgKCF0aGlzLnVzZUh0dHBCYXNpY0F1dGggJiYgdGhpcy5kdW1teUNsaWVudFNlY3JldCkge1xyXG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9zZWNyZXQnLCB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KTtcclxuICAgICAgfVxyXG5cclxuICAgICAgaWYgKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpIHtcclxuICAgICAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xyXG4gICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldChrZXksIHRoaXMuY3VzdG9tUXVlcnlQYXJhbXNba2V5XSk7XHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcblxyXG4gICAgICBoZWFkZXJzID0gaGVhZGVycy5zZXQoXHJcbiAgICAgICAgJ0NvbnRlbnQtVHlwZScsXHJcbiAgICAgICAgJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCdcclxuICAgICAgKTtcclxuXHJcbiAgICAgIHRoaXMuaHR0cFxyXG4gICAgICAgIC5wb3N0PFRva2VuUmVzcG9uc2U+KHRoaXMudG9rZW5FbmRwb2ludCwgcGFyYW1zLCB7IGhlYWRlcnMgfSlcclxuICAgICAgICAuc3Vic2NyaWJlKFxyXG4gICAgICAgICAgdG9rZW5SZXNwb25zZSA9PiB7XHJcbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ3Rva2VuUmVzcG9uc2UnLCB0b2tlblJlc3BvbnNlKTtcclxuICAgICAgICAgICAgdGhpcy5zdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXHJcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5hY2Nlc3NfdG9rZW4sXHJcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5yZWZyZXNoX3Rva2VuLFxyXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuZXhwaXJlc19pbiB8fFxyXG4gICAgICAgICAgICAgICAgdGhpcy5mYWxsYmFja0FjY2Vzc1Rva2VuRXhwaXJhdGlvblRpbWVJblNlYyxcclxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnNjb3BlLFxyXG4gICAgICAgICAgICAgIHRoaXMuZXh0cmFjdFJlY29nbml6ZWRDdXN0b21QYXJhbWV0ZXJzKHRva2VuUmVzcG9uc2UpXHJcbiAgICAgICAgICAgICk7XHJcblxyXG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xyXG4gICAgICAgICAgICByZXNvbHZlKHRva2VuUmVzcG9uc2UpO1xyXG4gICAgICAgICAgfSxcclxuICAgICAgICAgIGVyciA9PiB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdFcnJvciBwZXJmb3JtaW5nIHBhc3N3b3JkIGZsb3cnLCBlcnIpO1xyXG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9lcnJvcicsIGVycikpO1xyXG4gICAgICAgICAgICByZWplY3QoZXJyKTtcclxuICAgICAgICAgIH1cclxuICAgICAgICApO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBSZWZyZXNoZXMgdGhlIHRva2VuIHVzaW5nIGEgcmVmcmVzaF90b2tlbi5cclxuICAgKiBUaGlzIGRvZXMgbm90IHdvcmsgZm9yIGltcGxpY2l0IGZsb3csIGIvY1xyXG4gICAqIHRoZXJlIGlzIG5vIHJlZnJlc2hfdG9rZW4gaW4gdGhpcyBmbG93LlxyXG4gICAqIEEgc29sdXRpb24gZm9yIHRoaXMgaXMgcHJvdmlkZWQgYnkgdGhlXHJcbiAgICogbWV0aG9kIHNpbGVudFJlZnJlc2guXHJcbiAgICovXHJcbiAgcHVibGljIHJlZnJlc2hUb2tlbigpOiBQcm9taXNlPFRva2VuUmVzcG9uc2U+IHtcclxuICAgIHRoaXMuYXNzZXJ0VXJsTm90TnVsbEFuZENvcnJlY3RQcm90b2NvbChcclxuICAgICAgdGhpcy50b2tlbkVuZHBvaW50LFxyXG4gICAgICAndG9rZW5FbmRwb2ludCdcclxuICAgICk7XHJcblxyXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcclxuICAgICAgbGV0IHBhcmFtcyA9IG5ldyBIdHRwUGFyYW1zKClcclxuICAgICAgICAuc2V0KCdncmFudF90eXBlJywgJ3JlZnJlc2hfdG9rZW4nKVxyXG4gICAgICAgIC5zZXQoJ3Njb3BlJywgdGhpcy5zY29wZSlcclxuICAgICAgICAuc2V0KCdyZWZyZXNoX3Rva2VuJywgdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdyZWZyZXNoX3Rva2VuJykpO1xyXG5cclxuICAgICAgbGV0IGhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKS5zZXQoXHJcbiAgICAgICAgJ0NvbnRlbnQtVHlwZScsXHJcbiAgICAgICAgJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCdcclxuICAgICAgKTtcclxuXHJcbiAgICAgIGlmICh0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcclxuICAgICAgICBjb25zdCBoZWFkZXIgPSBidG9hKGAke3RoaXMuY2xpZW50SWR9OiR7dGhpcy5kdW1teUNsaWVudFNlY3JldH1gKTtcclxuICAgICAgICBoZWFkZXJzID0gaGVhZGVycy5zZXQoJ0F1dGhvcml6YXRpb24nLCAnQmFzaWMgJyArIGhlYWRlcik7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XHJcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X2lkJywgdGhpcy5jbGllbnRJZCk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoICYmIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpIHtcclxuICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfc2VjcmV0JywgdGhpcy5kdW1teUNsaWVudFNlY3JldCk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGlmICh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSB7XHJcbiAgICAgICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGhpcy5jdXN0b21RdWVyeVBhcmFtcykpIHtcclxuICAgICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoa2V5LCB0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xyXG4gICAgICAgIH1cclxuICAgICAgfVxyXG5cclxuICAgICAgdGhpcy5odHRwXHJcbiAgICAgICAgLnBvc3Q8VG9rZW5SZXNwb25zZT4odGhpcy50b2tlbkVuZHBvaW50LCBwYXJhbXMsIHsgaGVhZGVycyB9KVxyXG4gICAgICAgIC5waXBlKFxyXG4gICAgICAgICAgc3dpdGNoTWFwKHRva2VuUmVzcG9uc2UgPT4ge1xyXG4gICAgICAgICAgICBpZiAodG9rZW5SZXNwb25zZS5pZF90b2tlbikge1xyXG4gICAgICAgICAgICAgIHJldHVybiBmcm9tKFxyXG4gICAgICAgICAgICAgICAgdGhpcy5wcm9jZXNzSWRUb2tlbihcclxuICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5pZF90b2tlbixcclxuICAgICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5hY2Nlc3NfdG9rZW4sXHJcbiAgICAgICAgICAgICAgICAgIHRydWVcclxuICAgICAgICAgICAgICAgIClcclxuICAgICAgICAgICAgICApLnBpcGUoXHJcbiAgICAgICAgICAgICAgICB0YXAocmVzdWx0ID0+IHRoaXMuc3RvcmVJZFRva2VuKHJlc3VsdCkpLFxyXG4gICAgICAgICAgICAgICAgbWFwKF8gPT4gdG9rZW5SZXNwb25zZSlcclxuICAgICAgICAgICAgICApO1xyXG4gICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgIHJldHVybiBvZih0b2tlblJlc3BvbnNlKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgfSlcclxuICAgICAgICApXHJcbiAgICAgICAgLnN1YnNjcmliZShcclxuICAgICAgICAgIHRva2VuUmVzcG9uc2UgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmRlYnVnKCdyZWZyZXNoIHRva2VuUmVzcG9uc2UnLCB0b2tlblJlc3BvbnNlKTtcclxuICAgICAgICAgICAgdGhpcy5zdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXHJcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5hY2Nlc3NfdG9rZW4sXHJcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5yZWZyZXNoX3Rva2VuLFxyXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuZXhwaXJlc19pbiB8fFxyXG4gICAgICAgICAgICAgICAgdGhpcy5mYWxsYmFja0FjY2Vzc1Rva2VuRXhwaXJhdGlvblRpbWVJblNlYyxcclxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnNjb3BlLFxyXG4gICAgICAgICAgICAgIHRoaXMuZXh0cmFjdFJlY29nbml6ZWRDdXN0b21QYXJhbWV0ZXJzKHRva2VuUmVzcG9uc2UpXHJcbiAgICAgICAgICAgICk7XHJcblxyXG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xyXG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlZnJlc2hlZCcpKTtcclxuICAgICAgICAgICAgcmVzb2x2ZSh0b2tlblJlc3BvbnNlKTtcclxuICAgICAgICAgIH0sXHJcbiAgICAgICAgICBlcnIgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignRXJyb3IgcmVmcmVzaGluZyB0b2tlbicsIGVycik7XHJcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxyXG4gICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX3JlZnJlc2hfZXJyb3InLCBlcnIpXHJcbiAgICAgICAgICAgICk7XHJcbiAgICAgICAgICAgIHJlamVjdChlcnIpO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICk7XHJcbiAgICB9KTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCByZW1vdmVTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpOiB2b2lkIHtcclxuICAgIGlmICh0aGlzLnNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXIpIHtcclxuICAgICAgd2luZG93LnJlbW92ZUV2ZW50TGlzdGVuZXIoXHJcbiAgICAgICAgJ21lc3NhZ2UnLFxyXG4gICAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lclxyXG4gICAgICApO1xyXG4gICAgICB0aGlzLnNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXIgPSBudWxsO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHNldHVwU2lsZW50UmVmcmVzaEV2ZW50TGlzdGVuZXIoKTogdm9pZCB7XHJcbiAgICB0aGlzLnJlbW92ZVNpbGVudFJlZnJlc2hFdmVudExpc3RlbmVyKCk7XHJcblxyXG4gICAgdGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyID0gKGU6IE1lc3NhZ2VFdmVudCkgPT4ge1xyXG4gICAgICBjb25zdCBtZXNzYWdlID0gdGhpcy5wcm9jZXNzTWVzc2FnZUV2ZW50TWVzc2FnZShlKTtcclxuXHJcbiAgICAgIHRoaXMudHJ5TG9naW4oe1xyXG4gICAgICAgIGN1c3RvbUhhc2hGcmFnbWVudDogbWVzc2FnZSxcclxuICAgICAgICBwcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbjogdHJ1ZSxcclxuICAgICAgICBjdXN0b21SZWRpcmVjdFVyaTogdGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmkgfHwgdGhpcy5yZWRpcmVjdFVyaVxyXG4gICAgICB9KS5jYXRjaChlcnIgPT4gdGhpcy5kZWJ1ZygndHJ5TG9naW4gZHVyaW5nIHNpbGVudCByZWZyZXNoIGZhaWxlZCcsIGVycikpO1xyXG4gICAgfTtcclxuXHJcbiAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcihcclxuICAgICAgJ21lc3NhZ2UnLFxyXG4gICAgICB0aGlzLnNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXJcclxuICAgICk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBQZXJmb3JtcyBhIHNpbGVudCByZWZyZXNoIGZvciBpbXBsaWNpdCBmbG93LlxyXG4gICAqIFVzZSB0aGlzIG1ldGhvZCB0byBnZXQgbmV3IHRva2VucyB3aGVuL2JlZm9yZVxyXG4gICAqIHRoZSBleGlzdGluZyB0b2tlbnMgZXhwaXJlLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBzaWxlbnRSZWZyZXNoKFxyXG4gICAgcGFyYW1zOiBvYmplY3QgPSB7fSxcclxuICAgIG5vUHJvbXB0ID0gdHJ1ZVxyXG4gICk6IFByb21pc2U8T0F1dGhFdmVudD4ge1xyXG4gICAgY29uc3QgY2xhaW1zOiBvYmplY3QgPSB0aGlzLmdldElkZW50aXR5Q2xhaW1zKCkgfHwge307XHJcblxyXG4gICAgaWYgKHRoaXMudXNlSWRUb2tlbkhpbnRGb3JTaWxlbnRSZWZyZXNoICYmIHRoaXMuaGFzVmFsaWRJZFRva2VuKCkpIHtcclxuICAgICAgcGFyYW1zWydpZF90b2tlbl9oaW50J10gPSB0aGlzLmdldElkVG9rZW4oKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLmxvZ2luVXJsKSkge1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXHJcbiAgICAgICAgXCJsb2dpblVybCAgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSAncmVxdWlyZUh0dHBzJyBtdXN0IGJlIHNldCB0byAnZmFsc2UnIGFuZCBhbGxvdyBIVFRQICh3aXRob3V0IFRMUykuXCJcclxuICAgICAgKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAodHlwZW9mIHRoaXMuZG9jdW1lbnQgPT09ICd1bmRlZmluZWQnKSB7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcignc2lsZW50IHJlZnJlc2ggaXMgbm90IHN1cHBvcnRlZCBvbiB0aGlzIHBsYXRmb3JtJyk7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgZXhpc3RpbmdJZnJhbWUgPSB0aGlzLmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFxyXG4gICAgICB0aGlzLnNpbGVudFJlZnJlc2hJRnJhbWVOYW1lXHJcbiAgICApO1xyXG5cclxuICAgIGlmIChleGlzdGluZ0lmcmFtZSkge1xyXG4gICAgICB0aGlzLmRvY3VtZW50LmJvZHkucmVtb3ZlQ2hpbGQoZXhpc3RpbmdJZnJhbWUpO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMuc2lsZW50UmVmcmVzaFN1YmplY3QgPSBjbGFpbXNbJ3N1YiddO1xyXG5cclxuICAgIGNvbnN0IGlmcmFtZSA9IHRoaXMuZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnaWZyYW1lJyk7XHJcbiAgICBpZnJhbWUuaWQgPSB0aGlzLnNpbGVudFJlZnJlc2hJRnJhbWVOYW1lO1xyXG5cclxuICAgIHRoaXMuc2V0dXBTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpO1xyXG5cclxuICAgIGNvbnN0IHJlZGlyZWN0VXJpID0gdGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmkgfHwgdGhpcy5yZWRpcmVjdFVyaTtcclxuICAgIHRoaXMuY3JlYXRlTG9naW5VcmwobnVsbCwgbnVsbCwgcmVkaXJlY3RVcmksIG5vUHJvbXB0LCBwYXJhbXMpLnRoZW4odXJsID0+IHtcclxuICAgICAgaWZyYW1lLnNldEF0dHJpYnV0ZSgnc3JjJywgdXJsKTtcclxuXHJcbiAgICAgIGlmICghdGhpcy5zaWxlbnRSZWZyZXNoU2hvd0lGcmFtZSkge1xyXG4gICAgICAgIGlmcmFtZS5zdHlsZVsnZGlzcGxheSddID0gJ25vbmUnO1xyXG4gICAgICB9XHJcbiAgICAgIHRoaXMuZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChpZnJhbWUpO1xyXG4gICAgfSk7XHJcblxyXG4gICAgY29uc3QgZXJyb3JzID0gdGhpcy5ldmVudHMucGlwZShcclxuICAgICAgZmlsdGVyKGUgPT4gZSBpbnN0YW5jZW9mIE9BdXRoRXJyb3JFdmVudCksXHJcbiAgICAgIGZpcnN0KClcclxuICAgICk7XHJcbiAgICBjb25zdCBzdWNjZXNzID0gdGhpcy5ldmVudHMucGlwZShcclxuICAgICAgZmlsdGVyKGUgPT4gZS50eXBlID09PSAndG9rZW5fcmVjZWl2ZWQnKSxcclxuICAgICAgZmlyc3QoKVxyXG4gICAgKTtcclxuICAgIGNvbnN0IHRpbWVvdXQgPSBvZihcclxuICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnc2lsZW50X3JlZnJlc2hfdGltZW91dCcsIG51bGwpXHJcbiAgICApLnBpcGUoZGVsYXkodGhpcy5zaWxlbnRSZWZyZXNoVGltZW91dCkpO1xyXG5cclxuICAgIHJldHVybiByYWNlKFtlcnJvcnMsIHN1Y2Nlc3MsIHRpbWVvdXRdKVxyXG4gICAgICAucGlwZShcclxuICAgICAgICBtYXAoZSA9PiB7XHJcbiAgICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIE9BdXRoRXJyb3JFdmVudCkge1xyXG4gICAgICAgICAgICBpZiAoZS50eXBlID09PSAnc2lsZW50X3JlZnJlc2hfdGltZW91dCcpIHtcclxuICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcclxuICAgICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgICBlID0gbmV3IE9BdXRoRXJyb3JFdmVudCgnc2lsZW50X3JlZnJlc2hfZXJyb3InLCBlKTtcclxuICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB0aHJvdyBlO1xyXG4gICAgICAgICAgfSBlbHNlIGlmIChlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpIHtcclxuICAgICAgICAgICAgZSA9IG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgnc2lsZW50bHlfcmVmcmVzaGVkJyk7XHJcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgcmV0dXJuIGU7XHJcbiAgICAgICAgfSlcclxuICAgICAgKVxyXG4gICAgICAudG9Qcm9taXNlKCk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBUaGlzIG1ldGhvZCBleGlzdHMgZm9yIGJhY2t3YXJkcyBjb21wYXRpYmlsaXR5LlxyXG4gICAqIHtAbGluayBPQXV0aFNlcnZpY2UjaW5pdExvZ2luRmxvd0luUG9wdXB9IGhhbmRsZXMgYm90aCBjb2RlXHJcbiAgICogYW5kIGltcGxpY2l0IGZsb3dzLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBpbml0SW1wbGljaXRGbG93SW5Qb3B1cChvcHRpb25zPzoge1xyXG4gICAgaGVpZ2h0PzogbnVtYmVyO1xyXG4gICAgd2lkdGg/OiBudW1iZXI7XHJcbiAgfSkge1xyXG4gICAgcmV0dXJuIHRoaXMuaW5pdExvZ2luRmxvd0luUG9wdXAob3B0aW9ucyk7XHJcbiAgfVxyXG5cclxuICBwdWJsaWMgaW5pdExvZ2luRmxvd0luUG9wdXAob3B0aW9ucz86IHsgaGVpZ2h0PzogbnVtYmVyOyB3aWR0aD86IG51bWJlciB9KSB7XHJcbiAgICBvcHRpb25zID0gb3B0aW9ucyB8fCB7fTtcclxuICAgIHJldHVybiB0aGlzLmNyZWF0ZUxvZ2luVXJsKFxyXG4gICAgICBudWxsLFxyXG4gICAgICBudWxsLFxyXG4gICAgICB0aGlzLnNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaSxcclxuICAgICAgZmFsc2UsXHJcbiAgICAgIHtcclxuICAgICAgICBkaXNwbGF5OiAncG9wdXAnXHJcbiAgICAgIH1cclxuICAgICkudGhlbih1cmwgPT4ge1xyXG4gICAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xyXG4gICAgICAgIC8qKlxyXG4gICAgICAgICAqIEVycm9yIGhhbmRsaW5nIHNlY3Rpb25cclxuICAgICAgICAgKi9cclxuICAgICAgICBjb25zdCBjaGVja0ZvclBvcHVwQ2xvc2VkSW50ZXJ2YWwgPSA1MDA7XHJcbiAgICAgICAgbGV0IHdpbmRvd1JlZiA9IHdpbmRvdy5vcGVuKFxyXG4gICAgICAgICAgdXJsLFxyXG4gICAgICAgICAgJ19ibGFuaycsXHJcbiAgICAgICAgICB0aGlzLmNhbGN1bGF0ZVBvcHVwRmVhdHVyZXMob3B0aW9ucylcclxuICAgICAgICApO1xyXG4gICAgICAgIGxldCBjaGVja0ZvclBvcHVwQ2xvc2VkVGltZXI6IGFueTtcclxuICAgICAgICBjb25zdCBjaGVja0ZvclBvcHVwQ2xvc2VkID0gKCkgPT4ge1xyXG4gICAgICAgICAgaWYgKCF3aW5kb3dSZWYgfHwgd2luZG93UmVmLmNsb3NlZCkge1xyXG4gICAgICAgICAgICBjbGVhbnVwKCk7XHJcbiAgICAgICAgICAgIHJlamVjdChuZXcgT0F1dGhFcnJvckV2ZW50KCdwb3B1cF9jbG9zZWQnLCB7fSkpO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgIH07XHJcbiAgICAgICAgaWYgKCF3aW5kb3dSZWYpIHtcclxuICAgICAgICAgIHJlamVjdChuZXcgT0F1dGhFcnJvckV2ZW50KCdwb3B1cF9ibG9ja2VkJywge30pKTtcclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgY2hlY2tGb3JQb3B1cENsb3NlZFRpbWVyID0gd2luZG93LnNldEludGVydmFsKFxyXG4gICAgICAgICAgICBjaGVja0ZvclBvcHVwQ2xvc2VkLFxyXG4gICAgICAgICAgICBjaGVja0ZvclBvcHVwQ2xvc2VkSW50ZXJ2YWxcclxuICAgICAgICAgICk7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBjb25zdCBjbGVhbnVwID0gKCkgPT4ge1xyXG4gICAgICAgICAgd2luZG93LmNsZWFySW50ZXJ2YWwoY2hlY2tGb3JQb3B1cENsb3NlZFRpbWVyKTtcclxuICAgICAgICAgIHdpbmRvdy5yZW1vdmVFdmVudExpc3RlbmVyKCdtZXNzYWdlJywgbGlzdGVuZXIpO1xyXG4gICAgICAgICAgaWYgKHdpbmRvd1JlZiAhPT0gbnVsbCkge1xyXG4gICAgICAgICAgICB3aW5kb3dSZWYuY2xvc2UoKTtcclxuICAgICAgICAgIH1cclxuICAgICAgICAgIHdpbmRvd1JlZiA9IG51bGw7XHJcbiAgICAgICAgfTtcclxuXHJcbiAgICAgICAgY29uc3QgbGlzdGVuZXIgPSAoZTogTWVzc2FnZUV2ZW50KSA9PiB7XHJcbiAgICAgICAgICBjb25zdCBtZXNzYWdlID0gdGhpcy5wcm9jZXNzTWVzc2FnZUV2ZW50TWVzc2FnZShlKTtcclxuXHJcbiAgICAgICAgICBpZiAobWVzc2FnZSAmJiBtZXNzYWdlICE9PSBudWxsKSB7XHJcbiAgICAgICAgICAgIHRoaXMudHJ5TG9naW4oe1xyXG4gICAgICAgICAgICAgIGN1c3RvbUhhc2hGcmFnbWVudDogbWVzc2FnZSxcclxuICAgICAgICAgICAgICBwcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbjogdHJ1ZSxcclxuICAgICAgICAgICAgICBjdXN0b21SZWRpcmVjdFVyaTogdGhpcy5zaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmlcclxuICAgICAgICAgICAgfSkudGhlbihcclxuICAgICAgICAgICAgICAoKSA9PiB7XHJcbiAgICAgICAgICAgICAgICBjbGVhbnVwKCk7XHJcbiAgICAgICAgICAgICAgICByZXNvbHZlKCk7XHJcbiAgICAgICAgICAgICAgfSxcclxuICAgICAgICAgICAgICBlcnIgPT4ge1xyXG4gICAgICAgICAgICAgICAgY2xlYW51cCgpO1xyXG4gICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XHJcbiAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICApO1xyXG4gICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgY29uc29sZS5sb2coJ2ZhbHNlIGV2ZW50IGZpcmluZycpO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgIH07XHJcblxyXG4gICAgICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdtZXNzYWdlJywgbGlzdGVuZXIpO1xyXG4gICAgICB9KTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGNhbGN1bGF0ZVBvcHVwRmVhdHVyZXMob3B0aW9uczoge1xyXG4gICAgaGVpZ2h0PzogbnVtYmVyO1xyXG4gICAgd2lkdGg/OiBudW1iZXI7XHJcbiAgfSk6IHN0cmluZyB7XHJcbiAgICAvLyBTcGVjaWZ5IGFuIHN0YXRpYyBoZWlnaHQgYW5kIHdpZHRoIGFuZCBjYWxjdWxhdGUgY2VudGVyZWQgcG9zaXRpb25cclxuXHJcbiAgICBjb25zdCBoZWlnaHQgPSBvcHRpb25zLmhlaWdodCB8fCA0NzA7XHJcbiAgICBjb25zdCB3aWR0aCA9IG9wdGlvbnMud2lkdGggfHwgNTAwO1xyXG4gICAgY29uc3QgbGVmdCA9IHdpbmRvdy5zY3JlZW5MZWZ0ICsgKHdpbmRvdy5vdXRlcldpZHRoIC0gd2lkdGgpIC8gMjtcclxuICAgIGNvbnN0IHRvcCA9IHdpbmRvdy5zY3JlZW5Ub3AgKyAod2luZG93Lm91dGVySGVpZ2h0IC0gaGVpZ2h0KSAvIDI7XHJcbiAgICByZXR1cm4gYGxvY2F0aW9uPW5vLHRvb2xiYXI9bm8sd2lkdGg9JHt3aWR0aH0saGVpZ2h0PSR7aGVpZ2h0fSx0b3A9JHt0b3B9LGxlZnQ9JHtsZWZ0fWA7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgcHJvY2Vzc01lc3NhZ2VFdmVudE1lc3NhZ2UoZTogTWVzc2FnZUV2ZW50KTogc3RyaW5nIHtcclxuICAgIGxldCBleHBlY3RlZFByZWZpeCA9ICcjJztcclxuXHJcbiAgICBpZiAodGhpcy5zaWxlbnRSZWZyZXNoTWVzc2FnZVByZWZpeCkge1xyXG4gICAgICBleHBlY3RlZFByZWZpeCArPSB0aGlzLnNpbGVudFJlZnJlc2hNZXNzYWdlUHJlZml4O1xyXG4gICAgfVxyXG5cclxuICAgIGlmICghZSB8fCAhZS5kYXRhIHx8IHR5cGVvZiBlLmRhdGEgIT09ICdzdHJpbmcnKSB7XHJcbiAgICAgIHJldHVybjtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBwcmVmaXhlZE1lc3NhZ2U6IHN0cmluZyA9IGUuZGF0YTtcclxuXHJcbiAgICBpZiAoIXByZWZpeGVkTWVzc2FnZS5zdGFydHNXaXRoKGV4cGVjdGVkUHJlZml4KSkge1xyXG4gICAgICByZXR1cm47XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuICcjJyArIHByZWZpeGVkTWVzc2FnZS5zdWJzdHIoZXhwZWN0ZWRQcmVmaXgubGVuZ3RoKTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBjYW5QZXJmb3JtU2Vzc2lvbkNoZWNrKCk6IGJvb2xlYW4ge1xyXG4gICAgaWYgKCF0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkKSB7XHJcbiAgICAgIHJldHVybiBmYWxzZTtcclxuICAgIH1cclxuICAgIGlmICghdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVVcmwpIHtcclxuICAgICAgY29uc29sZS53YXJuKFxyXG4gICAgICAgICdzZXNzaW9uQ2hlY2tzRW5hYmxlZCBpcyBhY3RpdmF0ZWQgYnV0IHRoZXJlIGlzIG5vIHNlc3Npb25DaGVja0lGcmFtZVVybCdcclxuICAgICAgKTtcclxuICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgfVxyXG4gICAgY29uc3Qgc2Vzc2lvblN0YXRlID0gdGhpcy5nZXRTZXNzaW9uU3RhdGUoKTtcclxuICAgIGlmICghc2Vzc2lvblN0YXRlKSB7XHJcbiAgICAgIGNvbnNvbGUud2FybihcclxuICAgICAgICAnc2Vzc2lvbkNoZWNrc0VuYWJsZWQgaXMgYWN0aXZhdGVkIGJ1dCB0aGVyZSBpcyBubyBzZXNzaW9uX3N0YXRlJ1xyXG4gICAgICApO1xyXG4gICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICB9XHJcbiAgICBpZiAodHlwZW9mIHRoaXMuZG9jdW1lbnQgPT09ICd1bmRlZmluZWQnKSB7XHJcbiAgICAgIHJldHVybiBmYWxzZTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gdHJ1ZTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBzZXR1cFNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIoKTogdm9pZCB7XHJcbiAgICB0aGlzLnJlbW92ZVNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIoKTtcclxuXHJcbiAgICB0aGlzLnNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIgPSAoZTogTWVzc2FnZUV2ZW50KSA9PiB7XHJcbiAgICAgIGNvbnN0IG9yaWdpbiA9IGUub3JpZ2luLnRvTG93ZXJDYXNlKCk7XHJcbiAgICAgIGNvbnN0IGlzc3VlciA9IHRoaXMuaXNzdWVyLnRvTG93ZXJDYXNlKCk7XHJcblxyXG4gICAgICB0aGlzLmRlYnVnKCdzZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyJyk7XHJcblxyXG4gICAgICBpZiAoIWlzc3Vlci5zdGFydHNXaXRoKG9yaWdpbikpIHtcclxuICAgICAgICB0aGlzLmRlYnVnKFxyXG4gICAgICAgICAgJ3Nlc3Npb25DaGVja0V2ZW50TGlzdGVuZXInLFxyXG4gICAgICAgICAgJ3dyb25nIG9yaWdpbicsXHJcbiAgICAgICAgICBvcmlnaW4sXHJcbiAgICAgICAgICAnZXhwZWN0ZWQnLFxyXG4gICAgICAgICAgaXNzdWVyLFxyXG4gICAgICAgICAgJ2V2ZW50JyxcclxuICAgICAgICAgIGVcclxuICAgICAgICApO1xyXG5cclxuICAgICAgICByZXR1cm47XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIC8vIG9ubHkgcnVuIGluIEFuZ3VsYXIgem9uZSBpZiBpdCBpcyAnY2hhbmdlZCcgb3IgJ2Vycm9yJ1xyXG4gICAgICBzd2l0Y2ggKGUuZGF0YSkge1xyXG4gICAgICAgIGNhc2UgJ3VuY2hhbmdlZCc6XHJcbiAgICAgICAgICB0aGlzLmhhbmRsZVNlc3Npb25VbmNoYW5nZWQoKTtcclxuICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgIGNhc2UgJ2NoYW5nZWQnOlxyXG4gICAgICAgICAgdGhpcy5uZ1pvbmUucnVuKCgpID0+IHtcclxuICAgICAgICAgICAgdGhpcy5oYW5kbGVTZXNzaW9uQ2hhbmdlKCk7XHJcbiAgICAgICAgICB9KTtcclxuICAgICAgICAgIGJyZWFrO1xyXG4gICAgICAgIGNhc2UgJ2Vycm9yJzpcclxuICAgICAgICAgIHRoaXMubmdab25lLnJ1bigoKSA9PiB7XHJcbiAgICAgICAgICAgIHRoaXMuaGFuZGxlU2Vzc2lvbkVycm9yKCk7XHJcbiAgICAgICAgICB9KTtcclxuICAgICAgICAgIGJyZWFrO1xyXG4gICAgICB9XHJcblxyXG4gICAgICB0aGlzLmRlYnVnKCdnb3QgaW5mbyBmcm9tIHNlc3Npb24gY2hlY2sgaW5mcmFtZScsIGUpO1xyXG4gICAgfTtcclxuXHJcbiAgICAvLyBwcmV2ZW50IEFuZ3VsYXIgZnJvbSByZWZyZXNoaW5nIHRoZSB2aWV3IG9uIGV2ZXJ5IG1lc3NhZ2UgKHJ1bnMgaW4gaW50ZXJ2YWxzKVxyXG4gICAgdGhpcy5uZ1pvbmUucnVuT3V0c2lkZUFuZ3VsYXIoKCkgPT4ge1xyXG4gICAgICB3aW5kb3cuYWRkRXZlbnRMaXN0ZW5lcignbWVzc2FnZScsIHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcik7XHJcbiAgICB9KTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBoYW5kbGVTZXNzaW9uVW5jaGFuZ2VkKCk6IHZvaWQge1xyXG4gICAgdGhpcy5kZWJ1Zygnc2Vzc2lvbiBjaGVjaycsICdzZXNzaW9uIHVuY2hhbmdlZCcpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGhhbmRsZVNlc3Npb25DaGFuZ2UoKTogdm9pZCB7XHJcbiAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ3Nlc3Npb25fY2hhbmdlZCcpKTtcclxuICAgIHRoaXMuc3RvcFNlc3Npb25DaGVja1RpbWVyKCk7XHJcblxyXG4gICAgaWYgKCF0aGlzLnVzZVNpbGVudFJlZnJlc2ggJiYgdGhpcy5yZXNwb25zZVR5cGUgPT09ICdjb2RlJykge1xyXG4gICAgICB0aGlzLnJlZnJlc2hUb2tlbigpXHJcbiAgICAgICAgLnRoZW4oXyA9PiB7XHJcbiAgICAgICAgICB0aGlzLmRlYnVnKCd0b2tlbiByZWZyZXNoIGFmdGVyIHNlc3Npb24gY2hhbmdlIHdvcmtlZCcpO1xyXG4gICAgICAgIH0pXHJcbiAgICAgICAgLmNhdGNoKF8gPT4ge1xyXG4gICAgICAgICAgdGhpcy5kZWJ1ZygndG9rZW4gcmVmcmVzaCBkaWQgbm90IHdvcmsgYWZ0ZXIgc2Vzc2lvbiBjaGFuZ2VkJyk7XHJcbiAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ3Nlc3Npb25fdGVybWluYXRlZCcpKTtcclxuICAgICAgICAgIHRoaXMubG9nT3V0KHRydWUpO1xyXG4gICAgICAgIH0pO1xyXG4gICAgfSBlbHNlIGlmICh0aGlzLnNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaSkge1xyXG4gICAgICB0aGlzLnNpbGVudFJlZnJlc2goKS5jYXRjaChfID0+XHJcbiAgICAgICAgdGhpcy5kZWJ1Zygnc2lsZW50IHJlZnJlc2ggZmFpbGVkIGFmdGVyIHNlc3Npb24gY2hhbmdlZCcpXHJcbiAgICAgICk7XHJcbiAgICAgIHRoaXMud2FpdEZvclNpbGVudFJlZnJlc2hBZnRlclNlc3Npb25DaGFuZ2UoKTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEluZm9FdmVudCgnc2Vzc2lvbl90ZXJtaW5hdGVkJykpO1xyXG4gICAgICB0aGlzLmxvZ091dCh0cnVlKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCB3YWl0Rm9yU2lsZW50UmVmcmVzaEFmdGVyU2Vzc2lvbkNoYW5nZSgpOiB2b2lkIHtcclxuICAgIHRoaXMuZXZlbnRzXHJcbiAgICAgIC5waXBlKFxyXG4gICAgICAgIGZpbHRlcihcclxuICAgICAgICAgIChlOiBPQXV0aEV2ZW50KSA9PlxyXG4gICAgICAgICAgICBlLnR5cGUgPT09ICdzaWxlbnRseV9yZWZyZXNoZWQnIHx8XHJcbiAgICAgICAgICAgIGUudHlwZSA9PT0gJ3NpbGVudF9yZWZyZXNoX3RpbWVvdXQnIHx8XHJcbiAgICAgICAgICAgIGUudHlwZSA9PT0gJ3NpbGVudF9yZWZyZXNoX2Vycm9yJ1xyXG4gICAgICAgICksXHJcbiAgICAgICAgZmlyc3QoKVxyXG4gICAgICApXHJcbiAgICAgIC5zdWJzY3JpYmUoZSA9PiB7XHJcbiAgICAgICAgaWYgKGUudHlwZSAhPT0gJ3NpbGVudGx5X3JlZnJlc2hlZCcpIHtcclxuICAgICAgICAgIHRoaXMuZGVidWcoJ3NpbGVudCByZWZyZXNoIGRpZCBub3Qgd29yayBhZnRlciBzZXNzaW9uIGNoYW5nZWQnKTtcclxuICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEluZm9FdmVudCgnc2Vzc2lvbl90ZXJtaW5hdGVkJykpO1xyXG4gICAgICAgICAgdGhpcy5sb2dPdXQodHJ1ZSk7XHJcbiAgICAgICAgfVxyXG4gICAgICB9KTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBoYW5kbGVTZXNzaW9uRXJyb3IoKTogdm9pZCB7XHJcbiAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xyXG4gICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdzZXNzaW9uX2Vycm9yJykpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHJlbW92ZVNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIoKTogdm9pZCB7XHJcbiAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKSB7XHJcbiAgICAgIHdpbmRvdy5yZW1vdmVFdmVudExpc3RlbmVyKCdtZXNzYWdlJywgdGhpcy5zZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKTtcclxuICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyID0gbnVsbDtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBpbml0U2Vzc2lvbkNoZWNrKCk6IHZvaWQge1xyXG4gICAgaWYgKCF0aGlzLmNhblBlcmZvcm1TZXNzaW9uQ2hlY2soKSkge1xyXG4gICAgICByZXR1cm47XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgZXhpc3RpbmdJZnJhbWUgPSB0aGlzLmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFxyXG4gICAgICB0aGlzLnNlc3Npb25DaGVja0lGcmFtZU5hbWVcclxuICAgICk7XHJcbiAgICBpZiAoZXhpc3RpbmdJZnJhbWUpIHtcclxuICAgICAgdGhpcy5kb2N1bWVudC5ib2R5LnJlbW92ZUNoaWxkKGV4aXN0aW5nSWZyYW1lKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBpZnJhbWUgPSB0aGlzLmRvY3VtZW50LmNyZWF0ZUVsZW1lbnQoJ2lmcmFtZScpO1xyXG4gICAgaWZyYW1lLmlkID0gdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVOYW1lO1xyXG5cclxuICAgIHRoaXMuc2V0dXBTZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKCk7XHJcblxyXG4gICAgY29uc3QgdXJsID0gdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVVcmw7XHJcbiAgICBpZnJhbWUuc2V0QXR0cmlidXRlKCdzcmMnLCB1cmwpO1xyXG4gICAgaWZyYW1lLnN0eWxlLmRpc3BsYXkgPSAnbm9uZSc7XHJcbiAgICB0aGlzLmRvY3VtZW50LmJvZHkuYXBwZW5kQ2hpbGQoaWZyYW1lKTtcclxuXHJcbiAgICB0aGlzLnN0YXJ0U2Vzc2lvbkNoZWNrVGltZXIoKTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBzdGFydFNlc3Npb25DaGVja1RpbWVyKCk6IHZvaWQge1xyXG4gICAgdGhpcy5zdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTtcclxuICAgIHRoaXMubmdab25lLnJ1bk91dHNpZGVBbmd1bGFyKCgpID0+IHtcclxuICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tUaW1lciA9IHNldEludGVydmFsKFxyXG4gICAgICAgIHRoaXMuY2hlY2tTZXNzaW9uLmJpbmQodGhpcyksXHJcbiAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tJbnRlcnZhbGxcclxuICAgICAgKTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpOiB2b2lkIHtcclxuICAgIGlmICh0aGlzLnNlc3Npb25DaGVja1RpbWVyKSB7XHJcbiAgICAgIGNsZWFySW50ZXJ2YWwodGhpcy5zZXNzaW9uQ2hlY2tUaW1lcik7XHJcbiAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrVGltZXIgPSBudWxsO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgcHVibGljIGNoZWNrU2Vzc2lvbigpOiB2b2lkIHtcclxuICAgIGNvbnN0IGlmcmFtZTogYW55ID0gdGhpcy5kb2N1bWVudC5nZXRFbGVtZW50QnlJZChcclxuICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVOYW1lXHJcbiAgICApO1xyXG5cclxuICAgIGlmICghaWZyYW1lKSB7XHJcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oXHJcbiAgICAgICAgJ2NoZWNrU2Vzc2lvbiBkaWQgbm90IGZpbmQgaWZyYW1lJyxcclxuICAgICAgICB0aGlzLnNlc3Npb25DaGVja0lGcmFtZU5hbWVcclxuICAgICAgKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBzZXNzaW9uU3RhdGUgPSB0aGlzLmdldFNlc3Npb25TdGF0ZSgpO1xyXG5cclxuICAgIGlmICghc2Vzc2lvblN0YXRlKSB7XHJcbiAgICAgIHRoaXMuc3RvcFNlc3Npb25DaGVja1RpbWVyKCk7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgbWVzc2FnZSA9IHRoaXMuY2xpZW50SWQgKyAnICcgKyBzZXNzaW9uU3RhdGU7XHJcbiAgICBpZnJhbWUuY29udGVudFdpbmRvdy5wb3N0TWVzc2FnZShtZXNzYWdlLCB0aGlzLmlzc3Vlcik7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgYXN5bmMgY3JlYXRlTG9naW5VcmwoXHJcbiAgICBzdGF0ZSA9ICcnLFxyXG4gICAgbG9naW5IaW50ID0gJycsXHJcbiAgICBjdXN0b21SZWRpcmVjdFVyaSA9ICcnLFxyXG4gICAgbm9Qcm9tcHQgPSBmYWxzZSxcclxuICAgIHBhcmFtczogb2JqZWN0ID0ge31cclxuICApOiBQcm9taXNlPHN0cmluZz4ge1xyXG4gICAgY29uc3QgdGhhdCA9IHRoaXM7XHJcblxyXG4gICAgbGV0IHJlZGlyZWN0VXJpOiBzdHJpbmc7XHJcblxyXG4gICAgaWYgKGN1c3RvbVJlZGlyZWN0VXJpKSB7XHJcbiAgICAgIHJlZGlyZWN0VXJpID0gY3VzdG9tUmVkaXJlY3RVcmk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICByZWRpcmVjdFVyaSA9IHRoaXMucmVkaXJlY3RVcmk7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3Qgbm9uY2UgPSBhd2FpdCB0aGlzLmNyZWF0ZUFuZFNhdmVOb25jZSgpO1xyXG5cclxuICAgIGlmIChzdGF0ZSkge1xyXG4gICAgICBzdGF0ZSA9XHJcbiAgICAgICAgbm9uY2UgKyB0aGlzLmNvbmZpZy5ub25jZVN0YXRlU2VwYXJhdG9yICsgZW5jb2RlVVJJQ29tcG9uZW50KHN0YXRlKTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIHN0YXRlID0gbm9uY2U7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCF0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhdGhpcy5vaWRjKSB7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcignRWl0aGVyIHJlcXVlc3RBY2Nlc3NUb2tlbiBvciBvaWRjIG9yIGJvdGggbXVzdCBiZSB0cnVlJyk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHRoaXMuY29uZmlnLnJlc3BvbnNlVHlwZSkge1xyXG4gICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9IHRoaXMuY29uZmlnLnJlc3BvbnNlVHlwZTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIGlmICh0aGlzLm9pZGMgJiYgdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4pIHtcclxuICAgICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9ICdpZF90b2tlbiB0b2tlbic7XHJcbiAgICAgIH0gZWxzZSBpZiAodGhpcy5vaWRjICYmICF0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbikge1xyXG4gICAgICAgIHRoaXMucmVzcG9uc2VUeXBlID0gJ2lkX3Rva2VuJztcclxuICAgICAgfSBlbHNlIHtcclxuICAgICAgICB0aGlzLnJlc3BvbnNlVHlwZSA9ICd0b2tlbic7XHJcbiAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBzZXBlcmF0aW9uQ2hhciA9IHRoYXQubG9naW5VcmwuaW5kZXhPZignPycpID4gLTEgPyAnJicgOiAnPyc7XHJcblxyXG4gICAgbGV0IHNjb3BlID0gdGhhdC5zY29wZTtcclxuXHJcbiAgICBpZiAodGhpcy5vaWRjICYmICFzY29wZS5tYXRjaCgvKF58XFxzKW9wZW5pZCgkfFxccykvKSkge1xyXG4gICAgICBzY29wZSA9ICdvcGVuaWQgJyArIHNjb3BlO1xyXG4gICAgfVxyXG5cclxuICAgIGxldCB1cmwgPVxyXG4gICAgICB0aGF0LmxvZ2luVXJsICtcclxuICAgICAgc2VwZXJhdGlvbkNoYXIgK1xyXG4gICAgICAncmVzcG9uc2VfdHlwZT0nICtcclxuICAgICAgZW5jb2RlVVJJQ29tcG9uZW50KHRoYXQucmVzcG9uc2VUeXBlKSArXHJcbiAgICAgICcmY2xpZW50X2lkPScgK1xyXG4gICAgICBlbmNvZGVVUklDb21wb25lbnQodGhhdC5jbGllbnRJZCkgK1xyXG4gICAgICAnJnN0YXRlPScgK1xyXG4gICAgICBlbmNvZGVVUklDb21wb25lbnQoc3RhdGUpICtcclxuICAgICAgJyZyZWRpcmVjdF91cmk9JyArXHJcbiAgICAgIGVuY29kZVVSSUNvbXBvbmVudChyZWRpcmVjdFVyaSkgK1xyXG4gICAgICAnJnNjb3BlPScgK1xyXG4gICAgICBlbmNvZGVVUklDb21wb25lbnQoc2NvcGUpO1xyXG5cclxuICAgIGlmICh0aGlzLnJlc3BvbnNlVHlwZS5pbmNsdWRlcygnY29kZScpICYmICF0aGlzLmRpc2FibGVQS0NFKSB7XHJcbiAgICAgIGNvbnN0IFtcclxuICAgICAgICBjaGFsbGVuZ2UsXHJcbiAgICAgICAgdmVyaWZpZXJcclxuICAgICAgXSA9IGF3YWl0IHRoaXMuY3JlYXRlQ2hhbGxhbmdlVmVyaWZpZXJQYWlyRm9yUEtDRSgpO1xyXG5cclxuICAgICAgaWYgKFxyXG4gICAgICAgIHRoaXMuc2F2ZU5vbmNlc0luTG9jYWxTdG9yYWdlICYmXHJcbiAgICAgICAgdHlwZW9mIHdpbmRvd1snbG9jYWxTdG9yYWdlJ10gIT09ICd1bmRlZmluZWQnXHJcbiAgICAgICkge1xyXG4gICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCdQS0NFX3ZlcmlmaWVyJywgdmVyaWZpZXIpO1xyXG4gICAgICB9IGVsc2Uge1xyXG4gICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnUEtDRV92ZXJpZmllcicsIHZlcmlmaWVyKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgdXJsICs9ICcmY29kZV9jaGFsbGVuZ2U9JyArIGNoYWxsZW5nZTtcclxuICAgICAgdXJsICs9ICcmY29kZV9jaGFsbGVuZ2VfbWV0aG9kPVMyNTYnO1xyXG4gICAgfVxyXG5cclxuICAgIGlmIChsb2dpbkhpbnQpIHtcclxuICAgICAgdXJsICs9ICcmbG9naW5faGludD0nICsgZW5jb2RlVVJJQ29tcG9uZW50KGxvZ2luSGludCk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHRoYXQucmVzb3VyY2UpIHtcclxuICAgICAgdXJsICs9ICcmcmVzb3VyY2U9JyArIGVuY29kZVVSSUNvbXBvbmVudCh0aGF0LnJlc291cmNlKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAodGhhdC5vaWRjKSB7XHJcbiAgICAgIHVybCArPSAnJm5vbmNlPScgKyBlbmNvZGVVUklDb21wb25lbnQobm9uY2UpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmIChub1Byb21wdCkge1xyXG4gICAgICB1cmwgKz0gJyZwcm9tcHQ9bm9uZSc7XHJcbiAgICB9XHJcblxyXG4gICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmtleXMocGFyYW1zKSkge1xyXG4gICAgICB1cmwgKz1cclxuICAgICAgICAnJicgKyBlbmNvZGVVUklDb21wb25lbnQoa2V5KSArICc9JyArIGVuY29kZVVSSUNvbXBvbmVudChwYXJhbXNba2V5XSk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpIHtcclxuICAgICAgZm9yIChjb25zdCBrZXkgb2YgT2JqZWN0LmdldE93blByb3BlcnR5TmFtZXModGhpcy5jdXN0b21RdWVyeVBhcmFtcykpIHtcclxuICAgICAgICB1cmwgKz1cclxuICAgICAgICAgICcmJyArIGtleSArICc9JyArIGVuY29kZVVSSUNvbXBvbmVudCh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xyXG4gICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHVybDtcclxuICB9XHJcblxyXG4gIGluaXRJbXBsaWNpdEZsb3dJbnRlcm5hbChcclxuICAgIGFkZGl0aW9uYWxTdGF0ZSA9ICcnLFxyXG4gICAgcGFyYW1zOiBzdHJpbmcgfCBvYmplY3QgPSAnJ1xyXG4gICk6IHZvaWQge1xyXG4gICAgaWYgKHRoaXMuaW5JbXBsaWNpdEZsb3cpIHtcclxuICAgICAgcmV0dXJuO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSB0cnVlO1xyXG5cclxuICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMubG9naW5VcmwpKSB7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcihcclxuICAgICAgICBcImxvZ2luVXJsICBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5ICdyZXF1aXJlSHR0cHMnIG11c3QgYmUgc2V0IHRvICdmYWxzZScgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS5cIlxyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIGxldCBhZGRQYXJhbXM6IG9iamVjdCA9IHt9O1xyXG4gICAgbGV0IGxvZ2luSGludDogc3RyaW5nID0gbnVsbDtcclxuXHJcbiAgICBpZiAodHlwZW9mIHBhcmFtcyA9PT0gJ3N0cmluZycpIHtcclxuICAgICAgbG9naW5IaW50ID0gcGFyYW1zO1xyXG4gICAgfSBlbHNlIGlmICh0eXBlb2YgcGFyYW1zID09PSAnb2JqZWN0Jykge1xyXG4gICAgICBhZGRQYXJhbXMgPSBwYXJhbXM7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy5jcmVhdGVMb2dpblVybChhZGRpdGlvbmFsU3RhdGUsIGxvZ2luSGludCwgbnVsbCwgZmFsc2UsIGFkZFBhcmFtcylcclxuICAgICAgLnRoZW4odGhpcy5jb25maWcub3BlblVyaSlcclxuICAgICAgLmNhdGNoKGVycm9yID0+IHtcclxuICAgICAgICBjb25zb2xlLmVycm9yKCdFcnJvciBpbiBpbml0SW1wbGljaXRGbG93JywgZXJyb3IpO1xyXG4gICAgICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSBmYWxzZTtcclxuICAgICAgfSk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBTdGFydHMgdGhlIGltcGxpY2l0IGZsb3cgYW5kIHJlZGlyZWN0cyB0byB1c2VyIHRvXHJcbiAgICogdGhlIGF1dGggc2VydmVycycgbG9naW4gdXJsLlxyXG4gICAqXHJcbiAgICogQHBhcmFtIGFkZGl0aW9uYWxTdGF0ZSBPcHRpb25hbCBzdGF0ZSB0aGF0IGlzIHBhc3NlZCBhcm91bmQuXHJcbiAgICogIFlvdSdsbCBmaW5kIHRoaXMgc3RhdGUgaW4gdGhlIHByb3BlcnR5IGBzdGF0ZWAgYWZ0ZXIgYHRyeUxvZ2luYCBsb2dnZWQgaW4gdGhlIHVzZXIuXHJcbiAgICogQHBhcmFtIHBhcmFtcyBIYXNoIHdpdGggYWRkaXRpb25hbCBwYXJhbWV0ZXIuIElmIGl0IGlzIGEgc3RyaW5nLCBpdCBpcyB1c2VkIGZvciB0aGVcclxuICAgKiAgICAgICAgICAgICAgIHBhcmFtZXRlciBsb2dpbkhpbnQgKGZvciB0aGUgc2FrZSBvZiBjb21wYXRpYmlsaXR5IHdpdGggZm9ybWVyIHZlcnNpb25zKVxyXG4gICAqL1xyXG4gIHB1YmxpYyBpbml0SW1wbGljaXRGbG93KFxyXG4gICAgYWRkaXRpb25hbFN0YXRlID0gJycsXHJcbiAgICBwYXJhbXM6IHN0cmluZyB8IG9iamVjdCA9ICcnXHJcbiAgKTogdm9pZCB7XHJcbiAgICBpZiAodGhpcy5sb2dpblVybCAhPT0gJycpIHtcclxuICAgICAgdGhpcy5pbml0SW1wbGljaXRGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgdGhpcy5ldmVudHNcclxuICAgICAgICAucGlwZShmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICdkaXNjb3ZlcnlfZG9jdW1lbnRfbG9hZGVkJykpXHJcbiAgICAgICAgLnN1YnNjcmliZShfID0+IHRoaXMuaW5pdEltcGxpY2l0Rmxvd0ludGVybmFsKGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKSk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBSZXNldCBjdXJyZW50IGltcGxpY2l0IGZsb3dcclxuICAgKlxyXG4gICAqIEBkZXNjcmlwdGlvbiBUaGlzIG1ldGhvZCBhbGxvd3MgcmVzZXR0aW5nIHRoZSBjdXJyZW50IGltcGxpY3QgZmxvdyBpbiBvcmRlciB0byBiZSBpbml0aWFsaXplZCBhZ2Fpbi5cclxuICAgKi9cclxuICBwdWJsaWMgcmVzZXRJbXBsaWNpdEZsb3coKTogdm9pZCB7XHJcbiAgICB0aGlzLmluSW1wbGljaXRGbG93ID0gZmFsc2U7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgY2FsbE9uVG9rZW5SZWNlaXZlZElmRXhpc3RzKG9wdGlvbnM6IExvZ2luT3B0aW9ucyk6IHZvaWQge1xyXG4gICAgY29uc3QgdGhhdCA9IHRoaXM7XHJcbiAgICBpZiAob3B0aW9ucy5vblRva2VuUmVjZWl2ZWQpIHtcclxuICAgICAgY29uc3QgdG9rZW5QYXJhbXMgPSB7XHJcbiAgICAgICAgaWRDbGFpbXM6IHRoYXQuZ2V0SWRlbnRpdHlDbGFpbXMoKSxcclxuICAgICAgICBpZFRva2VuOiB0aGF0LmdldElkVG9rZW4oKSxcclxuICAgICAgICBhY2Nlc3NUb2tlbjogdGhhdC5nZXRBY2Nlc3NUb2tlbigpLFxyXG4gICAgICAgIHN0YXRlOiB0aGF0LnN0YXRlXHJcbiAgICAgIH07XHJcbiAgICAgIG9wdGlvbnMub25Ub2tlblJlY2VpdmVkKHRva2VuUGFyYW1zKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBzdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXHJcbiAgICBhY2Nlc3NUb2tlbjogc3RyaW5nLFxyXG4gICAgcmVmcmVzaFRva2VuOiBzdHJpbmcsXHJcbiAgICBleHBpcmVzSW46IG51bWJlcixcclxuICAgIGdyYW50ZWRTY29wZXM6IFN0cmluZyxcclxuICAgIGN1c3RvbVBhcmFtZXRlcnM/OiBNYXA8c3RyaW5nLCBzdHJpbmc+XHJcbiAgKTogdm9pZCB7XHJcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2FjY2Vzc190b2tlbicsIGFjY2Vzc1Rva2VuKTtcclxuICAgIGlmIChncmFudGVkU2NvcGVzICYmICFBcnJheS5pc0FycmF5KGdyYW50ZWRTY29wZXMpKSB7XHJcbiAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbShcclxuICAgICAgICAnZ3JhbnRlZF9zY29wZXMnLFxyXG4gICAgICAgIEpTT04uc3RyaW5naWZ5KGdyYW50ZWRTY29wZXMuc3BsaXQoJysnKSlcclxuICAgICAgKTtcclxuICAgIH0gZWxzZSBpZiAoZ3JhbnRlZFNjb3BlcyAmJiBBcnJheS5pc0FycmF5KGdyYW50ZWRTY29wZXMpKSB7XHJcbiAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnZ3JhbnRlZF9zY29wZXMnLCBKU09OLnN0cmluZ2lmeShncmFudGVkU2NvcGVzKSk7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdhY2Nlc3NfdG9rZW5fc3RvcmVkX2F0JywgJycgKyBEYXRlLm5vdygpKTtcclxuICAgIGlmIChleHBpcmVzSW4pIHtcclxuICAgICAgY29uc3QgZXhwaXJlc0luTWlsbGlTZWNvbmRzID0gZXhwaXJlc0luICogMTAwMDtcclxuICAgICAgY29uc3Qgbm93ID0gbmV3IERhdGUoKTtcclxuICAgICAgY29uc3QgZXhwaXJlc0F0ID0gbm93LmdldFRpbWUoKSArIGV4cGlyZXNJbk1pbGxpU2Vjb25kcztcclxuICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdleHBpcmVzX2F0JywgJycgKyBleHBpcmVzQXQpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmIChyZWZyZXNoVG9rZW4pIHtcclxuICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdyZWZyZXNoX3Rva2VuJywgcmVmcmVzaFRva2VuKTtcclxuICAgIH1cclxuICAgIGlmIChjdXN0b21QYXJhbWV0ZXJzKSB7XHJcbiAgICAgIGN1c3RvbVBhcmFtZXRlcnMuZm9yRWFjaCgodmFsdWU6IHN0cmluZywga2V5OiBzdHJpbmcpID0+IHtcclxuICAgICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oa2V5LCB2YWx1ZSk7XHJcbiAgICAgIH0pO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogRGVsZWdhdGVzIHRvIHRyeUxvZ2luSW1wbGljaXRGbG93IGZvciB0aGUgc2FrZSBvZiBjb21wZXRhYmlsaXR5XHJcbiAgICogQHBhcmFtIG9wdGlvbnMgT3B0aW9uYWwgb3B0aW9ucy5cclxuICAgKi9cclxuICBwdWJsaWMgdHJ5TG9naW4ob3B0aW9uczogTG9naW5PcHRpb25zID0gbnVsbCk6IFByb21pc2U8Ym9vbGVhbj4ge1xyXG4gICAgaWYgKHRoaXMuY29uZmlnLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XHJcbiAgICAgIHJldHVybiB0aGlzLnRyeUxvZ2luQ29kZUZsb3cob3B0aW9ucykudGhlbihfID0+IHRydWUpO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgcmV0dXJuIHRoaXMudHJ5TG9naW5JbXBsaWNpdEZsb3cob3B0aW9ucyk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIHBhcnNlUXVlcnlTdHJpbmcocXVlcnlTdHJpbmc6IHN0cmluZyk6IG9iamVjdCB7XHJcbiAgICBpZiAoIXF1ZXJ5U3RyaW5nIHx8IHF1ZXJ5U3RyaW5nLmxlbmd0aCA9PT0gMCkge1xyXG4gICAgICByZXR1cm4ge307XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHF1ZXJ5U3RyaW5nLmNoYXJBdCgwKSA9PT0gJz8nKSB7XHJcbiAgICAgIHF1ZXJ5U3RyaW5nID0gcXVlcnlTdHJpbmcuc3Vic3RyKDEpO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiB0aGlzLnVybEhlbHBlci5wYXJzZVF1ZXJ5U3RyaW5nKHF1ZXJ5U3RyaW5nKTtcclxuICB9XHJcblxyXG4gIHB1YmxpYyB0cnlMb2dpbkNvZGVGbG93KG9wdGlvbnM6IExvZ2luT3B0aW9ucyA9IG51bGwpOiBQcm9taXNlPHZvaWQ+IHtcclxuICAgIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xyXG5cclxuICAgIGNvbnN0IHF1ZXJ5U291cmNlID0gb3B0aW9ucy5jdXN0b21IYXNoRnJhZ21lbnRcclxuICAgICAgPyBvcHRpb25zLmN1c3RvbUhhc2hGcmFnbWVudC5zdWJzdHJpbmcoMSlcclxuICAgICAgOiB3aW5kb3cubG9jYXRpb24uc2VhcmNoO1xyXG5cclxuICAgIGNvbnN0IHBhcnRzID0gdGhpcy5nZXRDb2RlUGFydHNGcm9tVXJsKHF1ZXJ5U291cmNlKTtcclxuXHJcbiAgICBjb25zdCBjb2RlID0gcGFydHNbJ2NvZGUnXTtcclxuICAgIGNvbnN0IHN0YXRlID0gcGFydHNbJ3N0YXRlJ107XHJcblxyXG4gICAgY29uc3Qgc2Vzc2lvblN0YXRlID0gcGFydHNbJ3Nlc3Npb25fc3RhdGUnXTtcclxuXHJcbiAgICBpZiAoIW9wdGlvbnMucHJldmVudENsZWFySGFzaEFmdGVyTG9naW4pIHtcclxuICAgICAgY29uc3QgaHJlZiA9IGxvY2F0aW9uLmhyZWZcclxuICAgICAgICAucmVwbGFjZSgvWyZcXD9dY29kZT1bXiZcXCRdKi8sICcnKVxyXG4gICAgICAgIC5yZXBsYWNlKC9bJlxcP11zY29wZT1bXiZcXCRdKi8sICcnKVxyXG4gICAgICAgIC5yZXBsYWNlKC9bJlxcP11zdGF0ZT1bXiZcXCRdKi8sICcnKVxyXG4gICAgICAgIC5yZXBsYWNlKC9bJlxcP11zZXNzaW9uX3N0YXRlPVteJlxcJF0qLywgJycpO1xyXG5cclxuICAgICAgaGlzdG9yeS5yZXBsYWNlU3RhdGUobnVsbCwgd2luZG93Lm5hbWUsIGhyZWYpO1xyXG4gICAgfVxyXG5cclxuICAgIGxldCBbbm9uY2VJblN0YXRlLCB1c2VyU3RhdGVdID0gdGhpcy5wYXJzZVN0YXRlKHN0YXRlKTtcclxuICAgIHRoaXMuc3RhdGUgPSB1c2VyU3RhdGU7XHJcblxyXG4gICAgaWYgKHBhcnRzWydlcnJvciddKSB7XHJcbiAgICAgIHRoaXMuZGVidWcoJ2Vycm9yIHRyeWluZyB0byBsb2dpbicpO1xyXG4gICAgICB0aGlzLmhhbmRsZUxvZ2luRXJyb3Ioe30sIHBhcnRzKTtcclxuICAgICAgY29uc3QgZXJyID0gbmV3IE9BdXRoRXJyb3JFdmVudCgnY29kZV9lcnJvcicsIHt9LCBwYXJ0cyk7XHJcbiAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGVycik7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICghbm9uY2VJblN0YXRlKSB7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBzdWNjZXNzID0gdGhpcy52YWxpZGF0ZU5vbmNlKG5vbmNlSW5TdGF0ZSk7XHJcbiAgICBpZiAoIXN1Y2Nlc3MpIHtcclxuICAgICAgY29uc3QgZXZlbnQgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCdpbnZhbGlkX25vbmNlX2luX3N0YXRlJywgbnVsbCk7XHJcbiAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGV2ZW50KTtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGV2ZW50KTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLnN0b3JlU2Vzc2lvblN0YXRlKHNlc3Npb25TdGF0ZSk7XHJcblxyXG4gICAgaWYgKGNvZGUpIHtcclxuICAgICAgcmV0dXJuIHRoaXMuZ2V0VG9rZW5Gcm9tQ29kZShjb2RlLCBvcHRpb25zKS50aGVuKF8gPT4gbnVsbCk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKCk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBSZXRyaWV2ZSB0aGUgcmV0dXJuZWQgYXV0aCBjb2RlIGZyb20gdGhlIHJlZGlyZWN0IHVyaSB0aGF0IGhhcyBiZWVuIGNhbGxlZC5cclxuICAgKiBJZiByZXF1aXJlZCBhbHNvIGNoZWNrIGhhc2gsIGFzIHdlIGNvdWxkIHVzZSBoYXNoIGxvY2F0aW9uIHN0cmF0ZWd5LlxyXG4gICAqL1xyXG4gIHByaXZhdGUgZ2V0Q29kZVBhcnRzRnJvbVVybChxdWVyeVN0cmluZzogc3RyaW5nKTogb2JqZWN0IHtcclxuICAgIGlmICghcXVlcnlTdHJpbmcgfHwgcXVlcnlTdHJpbmcubGVuZ3RoID09PSAwKSB7XHJcbiAgICAgIHJldHVybiB0aGlzLnVybEhlbHBlci5nZXRIYXNoRnJhZ21lbnRQYXJhbXMoKTtcclxuICAgIH1cclxuXHJcbiAgICAvLyBub3JtYWxpemUgcXVlcnkgc3RyaW5nXHJcbiAgICBpZiAocXVlcnlTdHJpbmcuY2hhckF0KDApID09PSAnPycpIHtcclxuICAgICAgcXVlcnlTdHJpbmcgPSBxdWVyeVN0cmluZy5zdWJzdHIoMSk7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHRoaXMudXJsSGVscGVyLnBhcnNlUXVlcnlTdHJpbmcocXVlcnlTdHJpbmcpO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogR2V0IHRva2VuIHVzaW5nIGFuIGludGVybWVkaWF0ZSBjb2RlLiBXb3JrcyBmb3IgdGhlIEF1dGhvcml6YXRpb24gQ29kZSBmbG93LlxyXG4gICAqL1xyXG4gIHByaXZhdGUgZ2V0VG9rZW5Gcm9tQ29kZShcclxuICAgIGNvZGU6IHN0cmluZyxcclxuICAgIG9wdGlvbnM6IExvZ2luT3B0aW9uc1xyXG4gICk6IFByb21pc2U8b2JqZWN0PiB7XHJcbiAgICBsZXQgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoKVxyXG4gICAgICAuc2V0KCdncmFudF90eXBlJywgJ2F1dGhvcml6YXRpb25fY29kZScpXHJcbiAgICAgIC5zZXQoJ2NvZGUnLCBjb2RlKVxyXG4gICAgICAuc2V0KCdyZWRpcmVjdF91cmknLCBvcHRpb25zLmN1c3RvbVJlZGlyZWN0VXJpIHx8IHRoaXMucmVkaXJlY3RVcmkpO1xyXG5cclxuICAgIGlmICghdGhpcy5kaXNhYmxlUEtDRSkge1xyXG4gICAgICBsZXQgUEtDRVZlcmlmaWVyO1xyXG5cclxuICAgICAgaWYgKFxyXG4gICAgICAgIHRoaXMuc2F2ZU5vbmNlc0luTG9jYWxTdG9yYWdlICYmXHJcbiAgICAgICAgdHlwZW9mIHdpbmRvd1snbG9jYWxTdG9yYWdlJ10gIT09ICd1bmRlZmluZWQnXHJcbiAgICAgICkge1xyXG4gICAgICAgIFBLQ0VWZXJpZmllciA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdQS0NFX3ZlcmlmaWVyJyk7XHJcbiAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgUEtDRVZlcmlmaWVyID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdQS0NFX3ZlcmlmaWVyJyk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGlmICghUEtDRVZlcmlmaWVyKSB7XHJcbiAgICAgICAgY29uc29sZS53YXJuKCdObyBQS0NFIHZlcmlmaWVyIGZvdW5kIGluIG9hdXRoIHN0b3JhZ2UhJyk7XHJcbiAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY29kZV92ZXJpZmllcicsIFBLQ0VWZXJpZmllcik7XHJcbiAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gdGhpcy5mZXRjaEFuZFByb2Nlc3NUb2tlbihwYXJhbXMpO1xyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBmZXRjaEFuZFByb2Nlc3NUb2tlbihwYXJhbXM6IEh0dHBQYXJhbXMpOiBQcm9taXNlPFRva2VuUmVzcG9uc2U+IHtcclxuICAgIHRoaXMuYXNzZXJ0VXJsTm90TnVsbEFuZENvcnJlY3RQcm90b2NvbChcclxuICAgICAgdGhpcy50b2tlbkVuZHBvaW50LFxyXG4gICAgICAndG9rZW5FbmRwb2ludCdcclxuICAgICk7XHJcbiAgICBsZXQgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpLnNldChcclxuICAgICAgJ0NvbnRlbnQtVHlwZScsXHJcbiAgICAgICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXHJcbiAgICApO1xyXG5cclxuICAgIGlmICh0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcclxuICAgICAgY29uc3QgaGVhZGVyID0gYnRvYShgJHt0aGlzLmNsaWVudElkfToke3RoaXMuZHVtbXlDbGllbnRTZWNyZXR9YCk7XHJcbiAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldCgnQXV0aG9yaXphdGlvbicsICdCYXNpYyAnICsgaGVhZGVyKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xyXG4gICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfaWQnLCB0aGlzLmNsaWVudElkKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCAmJiB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KSB7XHJcbiAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9zZWNyZXQnLCB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xyXG4gICAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xyXG4gICAgICAgIGZvciAobGV0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xyXG4gICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldChrZXksIHRoaXMuY3VzdG9tUXVlcnlQYXJhbXNba2V5XSk7XHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcblxyXG4gICAgICB0aGlzLmh0dHBcclxuICAgICAgICAucG9zdDxUb2tlblJlc3BvbnNlPih0aGlzLnRva2VuRW5kcG9pbnQsIHBhcmFtcywgeyBoZWFkZXJzIH0pXHJcbiAgICAgICAgLnN1YnNjcmliZShcclxuICAgICAgICAgIHRva2VuUmVzcG9uc2UgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmRlYnVnKCdyZWZyZXNoIHRva2VuUmVzcG9uc2UnLCB0b2tlblJlc3BvbnNlKTtcclxuICAgICAgICAgICAgdGhpcy5zdG9yZUFjY2Vzc1Rva2VuUmVzcG9uc2UoXHJcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5hY2Nlc3NfdG9rZW4sXHJcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5yZWZyZXNoX3Rva2VuLFxyXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuZXhwaXJlc19pbiB8fFxyXG4gICAgICAgICAgICAgICAgdGhpcy5mYWxsYmFja0FjY2Vzc1Rva2VuRXhwaXJhdGlvblRpbWVJblNlYyxcclxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnNjb3BlLFxyXG4gICAgICAgICAgICAgIHRoaXMuZXh0cmFjdFJlY29nbml6ZWRDdXN0b21QYXJhbWV0ZXJzKHRva2VuUmVzcG9uc2UpXHJcbiAgICAgICAgICAgICk7XHJcblxyXG4gICAgICAgICAgICBpZiAodGhpcy5vaWRjICYmIHRva2VuUmVzcG9uc2UuaWRfdG9rZW4pIHtcclxuICAgICAgICAgICAgICB0aGlzLnByb2Nlc3NJZFRva2VuKFxyXG4gICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5pZF90b2tlbixcclxuICAgICAgICAgICAgICAgIHRva2VuUmVzcG9uc2UuYWNjZXNzX3Rva2VuXHJcbiAgICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICAgICAgLnRoZW4ocmVzdWx0ID0+IHtcclxuICAgICAgICAgICAgICAgICAgdGhpcy5zdG9yZUlkVG9rZW4ocmVzdWx0KTtcclxuXHJcbiAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxyXG4gICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKVxyXG4gICAgICAgICAgICAgICAgICApO1xyXG4gICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcclxuICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlZnJlc2hlZCcpXHJcbiAgICAgICAgICAgICAgICAgICk7XHJcblxyXG4gICAgICAgICAgICAgICAgICByZXNvbHZlKHRva2VuUmVzcG9uc2UpO1xyXG4gICAgICAgICAgICAgICAgfSlcclxuICAgICAgICAgICAgICAgIC5jYXRjaChyZWFzb24gPT4ge1xyXG4gICAgICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcclxuICAgICAgICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl92YWxpZGF0aW9uX2Vycm9yJywgcmVhc29uKVxyXG4gICAgICAgICAgICAgICAgICApO1xyXG4gICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKCdFcnJvciB2YWxpZGF0aW5nIHRva2VucycpO1xyXG4gICAgICAgICAgICAgICAgICBjb25zb2xlLmVycm9yKHJlYXNvbik7XHJcblxyXG4gICAgICAgICAgICAgICAgICByZWplY3QocmVhc29uKTtcclxuICAgICAgICAgICAgICAgIH0pO1xyXG4gICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XHJcbiAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWZyZXNoZWQnKSk7XHJcblxyXG4gICAgICAgICAgICAgIHJlc29sdmUodG9rZW5SZXNwb25zZSk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgIH0sXHJcbiAgICAgICAgICBlcnIgPT4ge1xyXG4gICAgICAgICAgICBjb25zb2xlLmVycm9yKCdFcnJvciBnZXR0aW5nIHRva2VuJywgZXJyKTtcclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXHJcbiAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fcmVmcmVzaF9lcnJvcicsIGVycilcclxuICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgcmVqZWN0KGVycik7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgKTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogQ2hlY2tzIHdoZXRoZXIgdGhlcmUgYXJlIHRva2VucyBpbiB0aGUgaGFzaCBmcmFnbWVudFxyXG4gICAqIGFzIGEgcmVzdWx0IG9mIHRoZSBpbXBsaWNpdCBmbG93LiBUaGVzZSB0b2tlbnMgYXJlXHJcbiAgICogcGFyc2VkLCB2YWxpZGF0ZWQgYW5kIHVzZWQgdG8gc2lnbiB0aGUgdXNlciBpbiB0byB0aGVcclxuICAgKiBjdXJyZW50IGNsaWVudC5cclxuICAgKlxyXG4gICAqIEBwYXJhbSBvcHRpb25zIE9wdGlvbmFsIG9wdGlvbnMuXHJcbiAgICovXHJcbiAgcHVibGljIHRyeUxvZ2luSW1wbGljaXRGbG93KG9wdGlvbnM6IExvZ2luT3B0aW9ucyA9IG51bGwpOiBQcm9taXNlPGJvb2xlYW4+IHtcclxuICAgIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xyXG5cclxuICAgIGxldCBwYXJ0czogb2JqZWN0O1xyXG5cclxuICAgIGlmIChvcHRpb25zLmN1c3RvbUhhc2hGcmFnbWVudCkge1xyXG4gICAgICBwYXJ0cyA9IHRoaXMudXJsSGVscGVyLmdldEhhc2hGcmFnbWVudFBhcmFtcyhvcHRpb25zLmN1c3RvbUhhc2hGcmFnbWVudCk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICBwYXJ0cyA9IHRoaXMudXJsSGVscGVyLmdldEhhc2hGcmFnbWVudFBhcmFtcygpO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMuZGVidWcoJ3BhcnNlZCB1cmwnLCBwYXJ0cyk7XHJcblxyXG4gICAgY29uc3Qgc3RhdGUgPSBwYXJ0c1snc3RhdGUnXTtcclxuXHJcbiAgICBsZXQgW25vbmNlSW5TdGF0ZSwgdXNlclN0YXRlXSA9IHRoaXMucGFyc2VTdGF0ZShzdGF0ZSk7XHJcbiAgICB0aGlzLnN0YXRlID0gdXNlclN0YXRlO1xyXG5cclxuICAgIGlmIChwYXJ0c1snZXJyb3InXSkge1xyXG4gICAgICB0aGlzLmRlYnVnKCdlcnJvciB0cnlpbmcgdG8gbG9naW4nKTtcclxuICAgICAgdGhpcy5oYW5kbGVMb2dpbkVycm9yKG9wdGlvbnMsIHBhcnRzKTtcclxuICAgICAgY29uc3QgZXJyID0gbmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fZXJyb3InLCB7fSwgcGFydHMpO1xyXG4gICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlcnIpO1xyXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBhY2Nlc3NUb2tlbiA9IHBhcnRzWydhY2Nlc3NfdG9rZW4nXTtcclxuICAgIGNvbnN0IGlkVG9rZW4gPSBwYXJ0c1snaWRfdG9rZW4nXTtcclxuICAgIGNvbnN0IHNlc3Npb25TdGF0ZSA9IHBhcnRzWydzZXNzaW9uX3N0YXRlJ107XHJcbiAgICBjb25zdCBncmFudGVkU2NvcGVzID0gcGFydHNbJ3Njb3BlJ107XHJcblxyXG4gICAgaWYgKCF0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhdGhpcy5vaWRjKSB7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChcclxuICAgICAgICAnRWl0aGVyIHJlcXVlc3RBY2Nlc3NUb2tlbiBvciBvaWRjIChvciBib3RoKSBtdXN0IGJlIHRydWUuJ1xyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhYWNjZXNzVG9rZW4pIHtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShmYWxzZSk7XHJcbiAgICB9XHJcbiAgICBpZiAodGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIW9wdGlvbnMuZGlzYWJsZU9BdXRoMlN0YXRlQ2hlY2sgJiYgIXN0YXRlKSB7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoZmFsc2UpO1xyXG4gICAgfVxyXG4gICAgaWYgKHRoaXMub2lkYyAmJiAhaWRUb2tlbikge1xyXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGZhbHNlKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCAmJiAhc2Vzc2lvblN0YXRlKSB7XHJcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oXHJcbiAgICAgICAgJ3Nlc3Npb24gY2hlY2tzIChTZXNzaW9uIFN0YXR1cyBDaGFuZ2UgTm90aWZpY2F0aW9uKSAnICtcclxuICAgICAgICAgICd3ZXJlIGFjdGl2YXRlZCBpbiB0aGUgY29uZmlndXJhdGlvbiBidXQgdGhlIGlkX3Rva2VuICcgK1xyXG4gICAgICAgICAgJ2RvZXMgbm90IGNvbnRhaW4gYSBzZXNzaW9uX3N0YXRlIGNsYWltJ1xyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhb3B0aW9ucy5kaXNhYmxlT0F1dGgyU3RhdGVDaGVjaykge1xyXG4gICAgICBjb25zdCBzdWNjZXNzID0gdGhpcy52YWxpZGF0ZU5vbmNlKG5vbmNlSW5TdGF0ZSk7XHJcblxyXG4gICAgICBpZiAoIXN1Y2Nlc3MpIHtcclxuICAgICAgICBjb25zdCBldmVudCA9IG5ldyBPQXV0aEVycm9yRXZlbnQoJ2ludmFsaWRfbm9uY2VfaW5fc3RhdGUnLCBudWxsKTtcclxuICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChldmVudCk7XHJcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGV2ZW50KTtcclxuICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbikge1xyXG4gICAgICB0aGlzLnN0b3JlQWNjZXNzVG9rZW5SZXNwb25zZShcclxuICAgICAgICBhY2Nlc3NUb2tlbixcclxuICAgICAgICBudWxsLFxyXG4gICAgICAgIHBhcnRzWydleHBpcmVzX2luJ10gfHwgdGhpcy5mYWxsYmFja0FjY2Vzc1Rva2VuRXhwaXJhdGlvblRpbWVJblNlYyxcclxuICAgICAgICBncmFudGVkU2NvcGVzXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCF0aGlzLm9pZGMpIHtcclxuICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcclxuICAgICAgaWYgKHRoaXMuY2xlYXJIYXNoQWZ0ZXJMb2dpbiAmJiAhb3B0aW9ucy5wcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbikge1xyXG4gICAgICAgIGxvY2F0aW9uLmhhc2ggPSAnJztcclxuICAgICAgfVxyXG5cclxuICAgICAgdGhpcy5jYWxsT25Ub2tlblJlY2VpdmVkSWZFeGlzdHMob3B0aW9ucyk7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUodHJ1ZSk7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHRoaXMucHJvY2Vzc0lkVG9rZW4oaWRUb2tlbiwgYWNjZXNzVG9rZW4pXHJcbiAgICAgIC50aGVuKHJlc3VsdCA9PiB7XHJcbiAgICAgICAgaWYgKG9wdGlvbnMudmFsaWRhdGlvbkhhbmRsZXIpIHtcclxuICAgICAgICAgIHJldHVybiBvcHRpb25zXHJcbiAgICAgICAgICAgIC52YWxpZGF0aW9uSGFuZGxlcih7XHJcbiAgICAgICAgICAgICAgYWNjZXNzVG9rZW46IGFjY2Vzc1Rva2VuLFxyXG4gICAgICAgICAgICAgIGlkQ2xhaW1zOiByZXN1bHQuaWRUb2tlbkNsYWltcyxcclxuICAgICAgICAgICAgICBpZFRva2VuOiByZXN1bHQuaWRUb2tlbixcclxuICAgICAgICAgICAgICBzdGF0ZTogc3RhdGVcclxuICAgICAgICAgICAgfSlcclxuICAgICAgICAgICAgLnRoZW4oXyA9PiByZXN1bHQpO1xyXG4gICAgICAgIH1cclxuICAgICAgICByZXR1cm4gcmVzdWx0O1xyXG4gICAgICB9KVxyXG4gICAgICAudGhlbihyZXN1bHQgPT4ge1xyXG4gICAgICAgIHRoaXMuc3RvcmVJZFRva2VuKHJlc3VsdCk7XHJcbiAgICAgICAgdGhpcy5zdG9yZVNlc3Npb25TdGF0ZShzZXNzaW9uU3RhdGUpO1xyXG4gICAgICAgIGlmICh0aGlzLmNsZWFySGFzaEFmdGVyTG9naW4gJiYgIW9wdGlvbnMucHJldmVudENsZWFySGFzaEFmdGVyTG9naW4pIHtcclxuICAgICAgICAgIGxvY2F0aW9uLmhhc2ggPSAnJztcclxuICAgICAgICB9XHJcbiAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcclxuICAgICAgICB0aGlzLmNhbGxPblRva2VuUmVjZWl2ZWRJZkV4aXN0cyhvcHRpb25zKTtcclxuICAgICAgICB0aGlzLmluSW1wbGljaXRGbG93ID0gZmFsc2U7XHJcbiAgICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICAgIH0pXHJcbiAgICAgIC5jYXRjaChyZWFzb24gPT4ge1xyXG4gICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxyXG4gICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fdmFsaWRhdGlvbl9lcnJvcicsIHJlYXNvbilcclxuICAgICAgICApO1xyXG4gICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdFcnJvciB2YWxpZGF0aW5nIHRva2VucycpO1xyXG4gICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKHJlYXNvbik7XHJcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KHJlYXNvbik7XHJcbiAgICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBwYXJzZVN0YXRlKHN0YXRlOiBzdHJpbmcpOiBbc3RyaW5nLCBzdHJpbmddIHtcclxuICAgIGxldCBub25jZSA9IHN0YXRlO1xyXG4gICAgbGV0IHVzZXJTdGF0ZSA9ICcnO1xyXG5cclxuICAgIGlmIChzdGF0ZSkge1xyXG4gICAgICBjb25zdCBpZHggPSBzdGF0ZS5pbmRleE9mKHRoaXMuY29uZmlnLm5vbmNlU3RhdGVTZXBhcmF0b3IpO1xyXG4gICAgICBpZiAoaWR4ID4gLTEpIHtcclxuICAgICAgICBub25jZSA9IHN0YXRlLnN1YnN0cigwLCBpZHgpO1xyXG4gICAgICAgIHVzZXJTdGF0ZSA9IHN0YXRlLnN1YnN0cihpZHggKyB0aGlzLmNvbmZpZy5ub25jZVN0YXRlU2VwYXJhdG9yLmxlbmd0aCk7XHJcbiAgICAgIH1cclxuICAgIH1cclxuICAgIHJldHVybiBbbm9uY2UsIHVzZXJTdGF0ZV07XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgdmFsaWRhdGVOb25jZShub25jZUluU3RhdGU6IHN0cmluZyk6IGJvb2xlYW4ge1xyXG4gICAgbGV0IHNhdmVkTm9uY2U7XHJcblxyXG4gICAgaWYgKFxyXG4gICAgICB0aGlzLnNhdmVOb25jZXNJbkxvY2FsU3RvcmFnZSAmJlxyXG4gICAgICB0eXBlb2Ygd2luZG93Wydsb2NhbFN0b3JhZ2UnXSAhPT0gJ3VuZGVmaW5lZCdcclxuICAgICkge1xyXG4gICAgICBzYXZlZE5vbmNlID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ25vbmNlJyk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICBzYXZlZE5vbmNlID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdub25jZScpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmIChzYXZlZE5vbmNlICE9PSBub25jZUluU3RhdGUpIHtcclxuICAgICAgY29uc3QgZXJyID0gJ1ZhbGlkYXRpbmcgYWNjZXNzX3Rva2VuIGZhaWxlZCwgd3Jvbmcgc3RhdGUvbm9uY2UuJztcclxuICAgICAgY29uc29sZS5lcnJvcihlcnIsIHNhdmVkTm9uY2UsIG5vbmNlSW5TdGF0ZSk7XHJcbiAgICAgIHJldHVybiBmYWxzZTtcclxuICAgIH1cclxuICAgIHJldHVybiB0cnVlO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHN0b3JlSWRUb2tlbihpZFRva2VuOiBQYXJzZWRJZFRva2VuKTogdm9pZCB7XHJcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuJywgaWRUb2tlbi5pZFRva2VuKTtcclxuICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnaWRfdG9rZW5fY2xhaW1zX29iaicsIGlkVG9rZW4uaWRUb2tlbkNsYWltc0pzb24pO1xyXG4gICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0JywgJycgKyBpZFRva2VuLmlkVG9rZW5FeHBpcmVzQXQpO1xyXG4gICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdpZF90b2tlbl9zdG9yZWRfYXQnLCAnJyArIERhdGUubm93KCkpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHN0b3JlU2Vzc2lvblN0YXRlKHNlc3Npb25TdGF0ZTogc3RyaW5nKTogdm9pZCB7XHJcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ3Nlc3Npb25fc3RhdGUnLCBzZXNzaW9uU3RhdGUpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGdldFNlc3Npb25TdGF0ZSgpOiBzdHJpbmcge1xyXG4gICAgcmV0dXJuIHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnc2Vzc2lvbl9zdGF0ZScpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGhhbmRsZUxvZ2luRXJyb3Iob3B0aW9uczogTG9naW5PcHRpb25zLCBwYXJ0czogb2JqZWN0KTogdm9pZCB7XHJcbiAgICBpZiAob3B0aW9ucy5vbkxvZ2luRXJyb3IpIHtcclxuICAgICAgb3B0aW9ucy5vbkxvZ2luRXJyb3IocGFydHMpO1xyXG4gICAgfVxyXG4gICAgaWYgKHRoaXMuY2xlYXJIYXNoQWZ0ZXJMb2dpbiAmJiAhb3B0aW9ucy5wcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbikge1xyXG4gICAgICBsb2NhdGlvbi5oYXNoID0gJyc7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBAaWdub3JlXHJcbiAgICovXHJcbiAgcHVibGljIHByb2Nlc3NJZFRva2VuKFxyXG4gICAgaWRUb2tlbjogc3RyaW5nLFxyXG4gICAgYWNjZXNzVG9rZW46IHN0cmluZyxcclxuICAgIHNraXBOb25jZUNoZWNrID0gZmFsc2VcclxuICApOiBQcm9taXNlPFBhcnNlZElkVG9rZW4+IHtcclxuICAgIGNvbnN0IHRva2VuUGFydHMgPSBpZFRva2VuLnNwbGl0KCcuJyk7XHJcbiAgICBjb25zdCBoZWFkZXJCYXNlNjQgPSB0aGlzLnBhZEJhc2U2NCh0b2tlblBhcnRzWzBdKTtcclxuICAgIGNvbnN0IGhlYWRlckpzb24gPSBiNjREZWNvZGVVbmljb2RlKGhlYWRlckJhc2U2NCk7XHJcbiAgICBjb25zdCBoZWFkZXIgPSBKU09OLnBhcnNlKGhlYWRlckpzb24pO1xyXG4gICAgY29uc3QgY2xhaW1zQmFzZTY0ID0gdGhpcy5wYWRCYXNlNjQodG9rZW5QYXJ0c1sxXSk7XHJcbiAgICBjb25zdCBjbGFpbXNKc29uID0gYjY0RGVjb2RlVW5pY29kZShjbGFpbXNCYXNlNjQpO1xyXG4gICAgY29uc3QgY2xhaW1zID0gSlNPTi5wYXJzZShjbGFpbXNKc29uKTtcclxuXHJcbiAgICBsZXQgc2F2ZWROb25jZTtcclxuICAgIGlmIChcclxuICAgICAgdGhpcy5zYXZlTm9uY2VzSW5Mb2NhbFN0b3JhZ2UgJiZcclxuICAgICAgdHlwZW9mIHdpbmRvd1snbG9jYWxTdG9yYWdlJ10gIT09ICd1bmRlZmluZWQnXHJcbiAgICApIHtcclxuICAgICAgc2F2ZWROb25jZSA9IGxvY2FsU3RvcmFnZS5nZXRJdGVtKCdub25jZScpO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgc2F2ZWROb25jZSA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnbm9uY2UnKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoQXJyYXkuaXNBcnJheShjbGFpbXMuYXVkKSkge1xyXG4gICAgICBpZiAoY2xhaW1zLmF1ZC5ldmVyeSh2ID0+IHYgIT09IHRoaXMuY2xpZW50SWQpKSB7XHJcbiAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGF1ZGllbmNlOiAnICsgY2xhaW1zLmF1ZC5qb2luKCcsJyk7XHJcbiAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xyXG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgICB9XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICBpZiAoY2xhaW1zLmF1ZCAhPT0gdGhpcy5jbGllbnRJZCkge1xyXG4gICAgICAgIGNvbnN0IGVyciA9ICdXcm9uZyBhdWRpZW5jZTogJyArIGNsYWltcy5hdWQ7XHJcbiAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xyXG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCFjbGFpbXMuc3ViKSB7XHJcbiAgICAgIGNvbnN0IGVyciA9ICdObyBzdWIgY2xhaW0gaW4gaWRfdG9rZW4nO1xyXG4gICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgfVxyXG5cclxuICAgIC8qIEZvciBub3csIHdlIG9ubHkgY2hlY2sgd2hldGhlciB0aGUgc3ViIGFnYWluc3RcclxuICAgICAqIHNpbGVudFJlZnJlc2hTdWJqZWN0IHdoZW4gc2Vzc2lvbkNoZWNrc0VuYWJsZWQgaXMgb25cclxuICAgICAqIFdlIHdpbGwgcmVjb25zaWRlciBpbiBhIGxhdGVyIHZlcnNpb24gdG8gZG8gdGhpc1xyXG4gICAgICogaW4gZXZlcnkgb3RoZXIgY2FzZSB0b28uXHJcbiAgICAgKi9cclxuICAgIGlmIChcclxuICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCAmJlxyXG4gICAgICB0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0ICYmXHJcbiAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFN1YmplY3QgIT09IGNsYWltc1snc3ViJ11cclxuICAgICkge1xyXG4gICAgICBjb25zdCBlcnIgPVxyXG4gICAgICAgICdBZnRlciByZWZyZXNoaW5nLCB3ZSBnb3QgYW4gaWRfdG9rZW4gZm9yIGFub3RoZXIgdXNlciAoc3ViKS4gJyArXHJcbiAgICAgICAgYEV4cGVjdGVkIHN1YjogJHt0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0fSwgcmVjZWl2ZWQgc3ViOiAke2NsYWltc1snc3ViJ119YDtcclxuXHJcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCFjbGFpbXMuaWF0KSB7XHJcbiAgICAgIGNvbnN0IGVyciA9ICdObyBpYXQgY2xhaW0gaW4gaWRfdG9rZW4nO1xyXG4gICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICghdGhpcy5za2lwSXNzdWVyQ2hlY2sgJiYgY2xhaW1zLmlzcyAhPT0gdGhpcy5pc3N1ZXIpIHtcclxuICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGlzc3VlcjogJyArIGNsYWltcy5pc3M7XHJcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCFza2lwTm9uY2VDaGVjayAmJiBjbGFpbXMubm9uY2UgIT09IHNhdmVkTm9uY2UpIHtcclxuICAgICAgY29uc3QgZXJyID0gJ1dyb25nIG5vbmNlOiAnICsgY2xhaW1zLm5vbmNlO1xyXG4gICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgfVxyXG4gICAgLy8gYXRfaGFzaCBpcyBub3QgYXBwbGljYWJsZSB0byBhdXRob3JpemF0aW9uIGNvZGUgZmxvd1xyXG4gICAgLy8gYWRkcmVzc2luZyBodHRwczovL2dpdGh1Yi5jb20vbWFuZnJlZHN0ZXllci9hbmd1bGFyLW9hdXRoMi1vaWRjL2lzc3Vlcy82NjFcclxuICAgIC8vIGkuZS4gQmFzZWQgb24gc3BlYyB0aGUgYXRfaGFzaCBjaGVjayBpcyBvbmx5IHRydWUgZm9yIGltcGxpY2l0IGNvZGUgZmxvdyBvbiBQaW5nIEZlZGVyYXRlXHJcbiAgICAvLyBodHRwczovL3d3dy5waW5naWRlbnRpdHkuY29tL2RldmVsb3Blci9lbi9yZXNvdXJjZXMvb3BlbmlkLWNvbm5lY3QtZGV2ZWxvcGVycy1ndWlkZS5odG1sXHJcbiAgICBpZiAoXHJcbiAgICAgIHRoaXMuaGFzT3duUHJvcGVydHkoJ3Jlc3BvbnNlVHlwZScpICYmXHJcbiAgICAgICh0aGlzLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnIHx8IHRoaXMucmVzcG9uc2VUeXBlID09PSAnaWRfdG9rZW4nKVxyXG4gICAgKSB7XHJcbiAgICAgIHRoaXMuZGlzYWJsZUF0SGFzaENoZWNrID0gdHJ1ZTtcclxuICAgIH1cclxuICAgIGlmIChcclxuICAgICAgIXRoaXMuZGlzYWJsZUF0SGFzaENoZWNrICYmXHJcbiAgICAgIHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmXHJcbiAgICAgICFjbGFpbXNbJ2F0X2hhc2gnXVxyXG4gICAgKSB7XHJcbiAgICAgIGNvbnN0IGVyciA9ICdBbiBhdF9oYXNoIGlzIG5lZWRlZCEnO1xyXG4gICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IG5vdyA9IERhdGUubm93KCk7XHJcbiAgICBjb25zdCBpc3N1ZWRBdE1TZWMgPSBjbGFpbXMuaWF0ICogMTAwMDtcclxuICAgIGNvbnN0IGV4cGlyZXNBdE1TZWMgPSBjbGFpbXMuZXhwICogMTAwMDtcclxuICAgIGNvbnN0IGNsb2NrU2tld0luTVNlYyA9ICh0aGlzLmNsb2NrU2tld0luU2VjIHx8IDYwMCkgKiAxMDAwO1xyXG5cclxuICAgIGlmIChcclxuICAgICAgaXNzdWVkQXRNU2VjIC0gY2xvY2tTa2V3SW5NU2VjID49IG5vdyB8fFxyXG4gICAgICBleHBpcmVzQXRNU2VjICsgY2xvY2tTa2V3SW5NU2VjIDw9IG5vd1xyXG4gICAgKSB7XHJcbiAgICAgIGNvbnN0IGVyciA9ICdUb2tlbiBoYXMgZXhwaXJlZCc7XHJcbiAgICAgIGNvbnNvbGUuZXJyb3IoZXJyKTtcclxuICAgICAgY29uc29sZS5lcnJvcih7XHJcbiAgICAgICAgbm93OiBub3csXHJcbiAgICAgICAgaXNzdWVkQXRNU2VjOiBpc3N1ZWRBdE1TZWMsXHJcbiAgICAgICAgZXhwaXJlc0F0TVNlYzogZXhwaXJlc0F0TVNlY1xyXG4gICAgICB9KTtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgdmFsaWRhdGlvblBhcmFtczogVmFsaWRhdGlvblBhcmFtcyA9IHtcclxuICAgICAgYWNjZXNzVG9rZW46IGFjY2Vzc1Rva2VuLFxyXG4gICAgICBpZFRva2VuOiBpZFRva2VuLFxyXG4gICAgICBqd2tzOiB0aGlzLmp3a3MsXHJcbiAgICAgIGlkVG9rZW5DbGFpbXM6IGNsYWltcyxcclxuICAgICAgaWRUb2tlbkhlYWRlcjogaGVhZGVyLFxyXG4gICAgICBsb2FkS2V5czogKCkgPT4gdGhpcy5sb2FkSndrcygpXHJcbiAgICB9O1xyXG5cclxuICAgIGlmICh0aGlzLmRpc2FibGVBdEhhc2hDaGVjaykge1xyXG4gICAgICByZXR1cm4gdGhpcy5jaGVja1NpZ25hdHVyZSh2YWxpZGF0aW9uUGFyYW1zKS50aGVuKF8gPT4ge1xyXG4gICAgICAgIGNvbnN0IHJlc3VsdDogUGFyc2VkSWRUb2tlbiA9IHtcclxuICAgICAgICAgIGlkVG9rZW46IGlkVG9rZW4sXHJcbiAgICAgICAgICBpZFRva2VuQ2xhaW1zOiBjbGFpbXMsXHJcbiAgICAgICAgICBpZFRva2VuQ2xhaW1zSnNvbjogY2xhaW1zSnNvbixcclxuICAgICAgICAgIGlkVG9rZW5IZWFkZXI6IGhlYWRlcixcclxuICAgICAgICAgIGlkVG9rZW5IZWFkZXJKc29uOiBoZWFkZXJKc29uLFxyXG4gICAgICAgICAgaWRUb2tlbkV4cGlyZXNBdDogZXhwaXJlc0F0TVNlY1xyXG4gICAgICAgIH07XHJcbiAgICAgICAgcmV0dXJuIHJlc3VsdDtcclxuICAgICAgfSk7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHRoaXMuY2hlY2tBdEhhc2godmFsaWRhdGlvblBhcmFtcykudGhlbihhdEhhc2hWYWxpZCA9PiB7XHJcbiAgICAgIGlmICghdGhpcy5kaXNhYmxlQXRIYXNoQ2hlY2sgJiYgdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiYgIWF0SGFzaFZhbGlkKSB7XHJcbiAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGF0X2hhc2gnO1xyXG4gICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcclxuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgcmV0dXJuIHRoaXMuY2hlY2tTaWduYXR1cmUodmFsaWRhdGlvblBhcmFtcykudGhlbihfID0+IHtcclxuICAgICAgICBjb25zdCBhdEhhc2hDaGVja0VuYWJsZWQgPSAhdGhpcy5kaXNhYmxlQXRIYXNoQ2hlY2s7XHJcbiAgICAgICAgY29uc3QgcmVzdWx0OiBQYXJzZWRJZFRva2VuID0ge1xyXG4gICAgICAgICAgaWRUb2tlbjogaWRUb2tlbixcclxuICAgICAgICAgIGlkVG9rZW5DbGFpbXM6IGNsYWltcyxcclxuICAgICAgICAgIGlkVG9rZW5DbGFpbXNKc29uOiBjbGFpbXNKc29uLFxyXG4gICAgICAgICAgaWRUb2tlbkhlYWRlcjogaGVhZGVyLFxyXG4gICAgICAgICAgaWRUb2tlbkhlYWRlckpzb246IGhlYWRlckpzb24sXHJcbiAgICAgICAgICBpZFRva2VuRXhwaXJlc0F0OiBleHBpcmVzQXRNU2VjXHJcbiAgICAgICAgfTtcclxuICAgICAgICBpZiAoYXRIYXNoQ2hlY2tFbmFibGVkKSB7XHJcbiAgICAgICAgICByZXR1cm4gdGhpcy5jaGVja0F0SGFzaCh2YWxpZGF0aW9uUGFyYW1zKS50aGVuKGF0SGFzaFZhbGlkMSA9PiB7XHJcbiAgICAgICAgICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhYXRIYXNoVmFsaWQxKSB7XHJcbiAgICAgICAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGF0X2hhc2gnO1xyXG4gICAgICAgICAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcclxuICAgICAgICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcclxuICAgICAgICAgICAgfSBlbHNlIHtcclxuICAgICAgICAgICAgICByZXR1cm4gcmVzdWx0O1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICB9KTtcclxuICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgcmV0dXJuIHJlc3VsdDtcclxuICAgICAgICB9XHJcbiAgICAgIH0pO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBSZXR1cm5zIHRoZSByZWNlaXZlZCBjbGFpbXMgYWJvdXQgdGhlIHVzZXIuXHJcbiAgICovXHJcbiAgcHVibGljIGdldElkZW50aXR5Q2xhaW1zKCk6IG9iamVjdCB7XHJcbiAgICBjb25zdCBjbGFpbXMgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2lkX3Rva2VuX2NsYWltc19vYmonKTtcclxuICAgIGlmICghY2xhaW1zKSB7XHJcbiAgICAgIHJldHVybiBudWxsO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIEpTT04ucGFyc2UoY2xhaW1zKTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFJldHVybnMgdGhlIGdyYW50ZWQgc2NvcGVzIGZyb20gdGhlIHNlcnZlci5cclxuICAgKi9cclxuICBwdWJsaWMgZ2V0R3JhbnRlZFNjb3BlcygpOiBvYmplY3Qge1xyXG4gICAgY29uc3Qgc2NvcGVzID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdncmFudGVkX3Njb3BlcycpO1xyXG4gICAgaWYgKCFzY29wZXMpIHtcclxuICAgICAgcmV0dXJuIG51bGw7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gSlNPTi5wYXJzZShzY29wZXMpO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogUmV0dXJucyB0aGUgY3VycmVudCBpZF90b2tlbi5cclxuICAgKi9cclxuICBwdWJsaWMgZ2V0SWRUb2tlbigpOiBzdHJpbmcge1xyXG4gICAgcmV0dXJuIHRoaXMuX3N0b3JhZ2UgPyB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2lkX3Rva2VuJykgOiBudWxsO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHBhZEJhc2U2NChiYXNlNjRkYXRhKTogc3RyaW5nIHtcclxuICAgIHdoaWxlIChiYXNlNjRkYXRhLmxlbmd0aCAlIDQgIT09IDApIHtcclxuICAgICAgYmFzZTY0ZGF0YSArPSAnPSc7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gYmFzZTY0ZGF0YTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFJldHVybnMgdGhlIGN1cnJlbnQgYWNjZXNzX3Rva2VuLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBnZXRBY2Nlc3NUb2tlbigpOiBzdHJpbmcge1xyXG4gICAgcmV0dXJuIHRoaXMuX3N0b3JhZ2UgPyB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2FjY2Vzc190b2tlbicpIDogbnVsbDtcclxuICB9XHJcblxyXG4gIHB1YmxpYyBnZXRSZWZyZXNoVG9rZW4oKTogc3RyaW5nIHtcclxuICAgIHJldHVybiB0aGlzLl9zdG9yYWdlID8gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdyZWZyZXNoX3Rva2VuJykgOiBudWxsO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogUmV0dXJucyB0aGUgZXhwaXJhdGlvbiBkYXRlIG9mIHRoZSBhY2Nlc3NfdG9rZW5cclxuICAgKiBhcyBtaWxsaXNlY29uZHMgc2luY2UgMTk3MC5cclxuICAgKi9cclxuICBwdWJsaWMgZ2V0QWNjZXNzVG9rZW5FeHBpcmF0aW9uKCk6IG51bWJlciB7XHJcbiAgICBpZiAoIXRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnZXhwaXJlc19hdCcpKSB7XHJcbiAgICAgIHJldHVybiBudWxsO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIHBhcnNlSW50KHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnZXhwaXJlc19hdCcpLCAxMCk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgZ2V0QWNjZXNzVG9rZW5TdG9yZWRBdCgpOiBudW1iZXIge1xyXG4gICAgcmV0dXJuIHBhcnNlSW50KHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnYWNjZXNzX3Rva2VuX3N0b3JlZF9hdCcpLCAxMCk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgZ2V0SWRUb2tlblN0b3JlZEF0KCk6IG51bWJlciB7XHJcbiAgICByZXR1cm4gcGFyc2VJbnQodGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9zdG9yZWRfYXQnKSwgMTApO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogUmV0dXJucyB0aGUgZXhwaXJhdGlvbiBkYXRlIG9mIHRoZSBpZF90b2tlblxyXG4gICAqIGFzIG1pbGxpc2Vjb25kcyBzaW5jZSAxOTcwLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBnZXRJZFRva2VuRXhwaXJhdGlvbigpOiBudW1iZXIge1xyXG4gICAgaWYgKCF0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnKSkge1xyXG4gICAgICByZXR1cm4gbnVsbDtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gcGFyc2VJbnQodGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0JyksIDEwKTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIENoZWNrZXMsIHdoZXRoZXIgdGhlcmUgaXMgYSB2YWxpZCBhY2Nlc3NfdG9rZW4uXHJcbiAgICovXHJcbiAgcHVibGljIGhhc1ZhbGlkQWNjZXNzVG9rZW4oKTogYm9vbGVhbiB7XHJcbiAgICBpZiAodGhpcy5nZXRBY2Nlc3NUb2tlbigpKSB7XHJcbiAgICAgIGNvbnN0IGV4cGlyZXNBdCA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnZXhwaXJlc19hdCcpO1xyXG4gICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpO1xyXG4gICAgICBpZiAoZXhwaXJlc0F0ICYmIHBhcnNlSW50KGV4cGlyZXNBdCwgMTApIDwgbm93LmdldFRpbWUoKSkge1xyXG4gICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgfVxyXG5cclxuICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIGZhbHNlO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogQ2hlY2tzIHdoZXRoZXIgdGhlcmUgaXMgYSB2YWxpZCBpZF90b2tlbi5cclxuICAgKi9cclxuICBwdWJsaWMgaGFzVmFsaWRJZFRva2VuKCk6IGJvb2xlYW4ge1xyXG4gICAgaWYgKHRoaXMuZ2V0SWRUb2tlbigpKSB7XHJcbiAgICAgIGNvbnN0IGV4cGlyZXNBdCA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fZXhwaXJlc19hdCcpO1xyXG4gICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpO1xyXG4gICAgICBpZiAoZXhwaXJlc0F0ICYmIHBhcnNlSW50KGV4cGlyZXNBdCwgMTApIDwgbm93LmdldFRpbWUoKSkge1xyXG4gICAgICAgIHJldHVybiBmYWxzZTtcclxuICAgICAgfVxyXG5cclxuICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIGZhbHNlO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogUmV0cmlldmUgYSBzYXZlZCBjdXN0b20gcHJvcGVydHkgb2YgdGhlIFRva2VuUmVwb25zZSBvYmplY3QuIE9ubHkgaWYgcHJlZGVmaW5lZCBpbiBhdXRoY29uZmlnLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBnZXRDdXN0b21Ub2tlblJlc3BvbnNlUHJvcGVydHkocmVxdWVzdGVkUHJvcGVydHk6IHN0cmluZyk6IGFueSB7XHJcbiAgICByZXR1cm4gdGhpcy5fc3RvcmFnZSAmJlxyXG4gICAgICB0aGlzLmNvbmZpZy5jdXN0b21Ub2tlblBhcmFtZXRlcnMgJiZcclxuICAgICAgdGhpcy5jb25maWcuY3VzdG9tVG9rZW5QYXJhbWV0ZXJzLmluZGV4T2YocmVxdWVzdGVkUHJvcGVydHkpID49IDAgJiZcclxuICAgICAgdGhpcy5fc3RvcmFnZS5nZXRJdGVtKHJlcXVlc3RlZFByb3BlcnR5KSAhPT0gbnVsbFxyXG4gICAgICA/IEpTT04ucGFyc2UodGhpcy5fc3RvcmFnZS5nZXRJdGVtKHJlcXVlc3RlZFByb3BlcnR5KSlcclxuICAgICAgOiBudWxsO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogUmV0dXJucyB0aGUgYXV0aC1oZWFkZXIgdGhhdCBjYW4gYmUgdXNlZFxyXG4gICAqIHRvIHRyYW5zbWl0IHRoZSBhY2Nlc3NfdG9rZW4gdG8gYSBzZXJ2aWNlXHJcbiAgICovXHJcbiAgcHVibGljIGF1dGhvcml6YXRpb25IZWFkZXIoKTogc3RyaW5nIHtcclxuICAgIHJldHVybiAnQmVhcmVyICcgKyB0aGlzLmdldEFjY2Vzc1Rva2VuKCk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBSZW1vdmVzIGFsbCB0b2tlbnMgYW5kIGxvZ3MgdGhlIHVzZXIgb3V0LlxyXG4gICAqIElmIGEgbG9nb3V0IHVybCBpcyBjb25maWd1cmVkLCB0aGUgdXNlciBpc1xyXG4gICAqIHJlZGlyZWN0ZWQgdG8gaXQgd2l0aCBvcHRpb25hbCBzdGF0ZSBwYXJhbWV0ZXIuXHJcbiAgICogQHBhcmFtIG5vUmVkaXJlY3RUb0xvZ291dFVybFxyXG4gICAqIEBwYXJhbSBzdGF0ZVxyXG4gICAqL1xyXG4gIHB1YmxpYyBsb2dPdXQoKTogdm9pZDtcclxuICBwdWJsaWMgbG9nT3V0KGN1c3RvbVBhcmFtZXRlcnM6IG9iamVjdCk6IHZvaWQ7XHJcbiAgcHVibGljIGxvZ091dChub1JlZGlyZWN0VG9Mb2dvdXRVcmw6IGJvb2xlYW4pOiB2b2lkO1xyXG4gIHB1YmxpYyBsb2dPdXQobm9SZWRpcmVjdFRvTG9nb3V0VXJsOiBib29sZWFuLCBzdGF0ZTogc3RyaW5nKTogdm9pZDtcclxuICBwdWJsaWMgbG9nT3V0KGN1c3RvbVBhcmFtZXRlcnM6IGJvb2xlYW4gfCBvYmplY3QgPSB7fSwgc3RhdGUgPSAnJyk6IHZvaWQge1xyXG4gICAgbGV0IG5vUmVkaXJlY3RUb0xvZ291dFVybCA9IGZhbHNlO1xyXG4gICAgaWYgKHR5cGVvZiBjdXN0b21QYXJhbWV0ZXJzID09PSAnYm9vbGVhbicpIHtcclxuICAgICAgbm9SZWRpcmVjdFRvTG9nb3V0VXJsID0gY3VzdG9tUGFyYW1ldGVycztcclxuICAgICAgY3VzdG9tUGFyYW1ldGVycyA9IHt9O1xyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IGlkX3Rva2VuID0gdGhpcy5nZXRJZFRva2VuKCk7XHJcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2FjY2Vzc190b2tlbicpO1xyXG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdpZF90b2tlbicpO1xyXG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdyZWZyZXNoX3Rva2VuJyk7XHJcblxyXG4gICAgaWYgKHRoaXMuc2F2ZU5vbmNlc0luTG9jYWxTdG9yYWdlKSB7XHJcbiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCdub25jZScpO1xyXG4gICAgICBsb2NhbFN0b3JhZ2UucmVtb3ZlSXRlbSgnUEtDRV92ZXJpZmllcicpO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdub25jZScpO1xyXG4gICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ1BLQ0VfdmVyaWZpZXInKTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2V4cGlyZXNfYXQnKTtcclxuICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnaWRfdG9rZW5fY2xhaW1zX29iaicpO1xyXG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0Jyk7XHJcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2lkX3Rva2VuX3N0b3JlZF9hdCcpO1xyXG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdhY2Nlc3NfdG9rZW5fc3RvcmVkX2F0Jyk7XHJcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2dyYW50ZWRfc2NvcGVzJyk7XHJcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ3Nlc3Npb25fc3RhdGUnKTtcclxuICAgIGlmICh0aGlzLmNvbmZpZy5jdXN0b21Ub2tlblBhcmFtZXRlcnMpIHtcclxuICAgICAgdGhpcy5jb25maWcuY3VzdG9tVG9rZW5QYXJhbWV0ZXJzLmZvckVhY2goY3VzdG9tUGFyYW0gPT5cclxuICAgICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oY3VzdG9tUGFyYW0pXHJcbiAgICAgICk7XHJcbiAgICB9XHJcbiAgICB0aGlzLnNpbGVudFJlZnJlc2hTdWJqZWN0ID0gbnVsbDtcclxuXHJcbiAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ2xvZ291dCcpKTtcclxuXHJcbiAgICBpZiAoIXRoaXMubG9nb3V0VXJsKSB7XHJcbiAgICAgIHJldHVybjtcclxuICAgIH1cclxuICAgIGlmIChub1JlZGlyZWN0VG9Mb2dvdXRVcmwpIHtcclxuICAgICAgcmV0dXJuO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICghaWRfdG9rZW4gJiYgIXRoaXMucG9zdExvZ291dFJlZGlyZWN0VXJpKSB7XHJcbiAgICAgIHJldHVybjtcclxuICAgIH1cclxuXHJcbiAgICBsZXQgbG9nb3V0VXJsOiBzdHJpbmc7XHJcblxyXG4gICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy5sb2dvdXRVcmwpKSB7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcihcclxuICAgICAgICBcImxvZ291dFVybCAgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSAncmVxdWlyZUh0dHBzJyBtdXN0IGJlIHNldCB0byAnZmFsc2UnIGFuZCBhbGxvdyBIVFRQICh3aXRob3V0IFRMUykuXCJcclxuICAgICAgKTtcclxuICAgIH1cclxuXHJcbiAgICAvLyBGb3IgYmFja3dhcmQgY29tcGF0aWJpbGl0eVxyXG4gICAgaWYgKHRoaXMubG9nb3V0VXJsLmluZGV4T2YoJ3t7JykgPiAtMSkge1xyXG4gICAgICBsb2dvdXRVcmwgPSB0aGlzLmxvZ291dFVybFxyXG4gICAgICAgIC5yZXBsYWNlKC9cXHtcXHtpZF90b2tlblxcfVxcfS8sIGlkX3Rva2VuKVxyXG4gICAgICAgIC5yZXBsYWNlKC9cXHtcXHtjbGllbnRfaWRcXH1cXH0vLCB0aGlzLmNsaWVudElkKTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcygpO1xyXG5cclxuICAgICAgaWYgKGlkX3Rva2VuKSB7XHJcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnaWRfdG9rZW5faGludCcsIGlkX3Rva2VuKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgY29uc3QgcG9zdExvZ291dFVybCA9IHRoaXMucG9zdExvZ291dFJlZGlyZWN0VXJpIHx8IHRoaXMucmVkaXJlY3RVcmk7XHJcbiAgICAgIGlmIChwb3N0TG9nb3V0VXJsKSB7XHJcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgncG9zdF9sb2dvdXRfcmVkaXJlY3RfdXJpJywgcG9zdExvZ291dFVybCk7XHJcblxyXG4gICAgICAgIGlmIChzdGF0ZSkge1xyXG4gICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnc3RhdGUnLCBzdGF0ZSk7XHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcblxyXG4gICAgICBmb3IgKGxldCBrZXkgaW4gY3VzdG9tUGFyYW1ldGVycykge1xyXG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoa2V5LCBjdXN0b21QYXJhbWV0ZXJzW2tleV0pO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBsb2dvdXRVcmwgPVxyXG4gICAgICAgIHRoaXMubG9nb3V0VXJsICtcclxuICAgICAgICAodGhpcy5sb2dvdXRVcmwuaW5kZXhPZignPycpID4gLTEgPyAnJicgOiAnPycpICtcclxuICAgICAgICBwYXJhbXMudG9TdHJpbmcoKTtcclxuICAgIH1cclxuICAgIHRoaXMuY29uZmlnLm9wZW5VcmkobG9nb3V0VXJsKTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIEBpZ25vcmVcclxuICAgKi9cclxuICBwdWJsaWMgY3JlYXRlQW5kU2F2ZU5vbmNlKCk6IFByb21pc2U8c3RyaW5nPiB7XHJcbiAgICBjb25zdCB0aGF0ID0gdGhpcztcclxuICAgIHJldHVybiB0aGlzLmNyZWF0ZU5vbmNlKCkudGhlbihmdW5jdGlvbihub25jZTogYW55KSB7XHJcbiAgICAgIC8vIFVzZSBsb2NhbFN0b3JhZ2UgZm9yIG5vbmNlIGlmIHBvc3NpYmxlXHJcbiAgICAgIC8vIGxvY2FsU3RvcmFnZSBpcyB0aGUgb25seSBzdG9yYWdlIHdobyBzdXJ2aXZlcyBhXHJcbiAgICAgIC8vIHJlZGlyZWN0IGluIEFMTCBicm93c2VycyAoYWxzbyBJRSlcclxuICAgICAgLy8gT3RoZXJ3aWVzZSB3ZSdkIGZvcmNlIHRlYW1zIHdobyBoYXZlIHRvIHN1cHBvcnRcclxuICAgICAgLy8gSUUgaW50byB1c2luZyBsb2NhbFN0b3JhZ2UgZm9yIGV2ZXJ5dGhpbmdcclxuICAgICAgaWYgKFxyXG4gICAgICAgIHRoYXQuc2F2ZU5vbmNlc0luTG9jYWxTdG9yYWdlICYmXHJcbiAgICAgICAgdHlwZW9mIHdpbmRvd1snbG9jYWxTdG9yYWdlJ10gIT09ICd1bmRlZmluZWQnXHJcbiAgICAgICkge1xyXG4gICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKCdub25jZScsIG5vbmNlKTtcclxuICAgICAgfSBlbHNlIHtcclxuICAgICAgICB0aGF0Ll9zdG9yYWdlLnNldEl0ZW0oJ25vbmNlJywgbm9uY2UpO1xyXG4gICAgICB9XHJcbiAgICAgIHJldHVybiBub25jZTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogQGlnbm9yZVxyXG4gICAqL1xyXG4gIHB1YmxpYyBuZ09uRGVzdHJveSgpOiB2b2lkIHtcclxuICAgIHRoaXMuY2xlYXJBY2Nlc3NUb2tlblRpbWVyKCk7XHJcbiAgICB0aGlzLmNsZWFySWRUb2tlblRpbWVyKCk7XHJcblxyXG4gICAgdGhpcy5yZW1vdmVTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpO1xyXG4gICAgY29uc3Qgc2lsZW50UmVmcmVzaEZyYW1lID0gdGhpcy5kb2N1bWVudC5nZXRFbGVtZW50QnlJZChcclxuICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoSUZyYW1lTmFtZVxyXG4gICAgKTtcclxuICAgIGlmIChzaWxlbnRSZWZyZXNoRnJhbWUpIHtcclxuICAgICAgc2lsZW50UmVmcmVzaEZyYW1lLnJlbW92ZSgpO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMuc3RvcFNlc3Npb25DaGVja1RpbWVyKCk7XHJcbiAgICB0aGlzLnJlbW92ZVNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIoKTtcclxuICAgIGNvbnN0IHNlc3Npb25DaGVja0ZyYW1lID0gdGhpcy5kb2N1bWVudC5nZXRFbGVtZW50QnlJZChcclxuICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVOYW1lXHJcbiAgICApO1xyXG4gICAgaWYgKHNlc3Npb25DaGVja0ZyYW1lKSB7XHJcbiAgICAgIHNlc3Npb25DaGVja0ZyYW1lLnJlbW92ZSgpO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGNyZWF0ZU5vbmNlKCk6IFByb21pc2U8c3RyaW5nPiB7XHJcbiAgICByZXR1cm4gbmV3IFByb21pc2UocmVzb2x2ZSA9PiB7XHJcbiAgICAgIGlmICh0aGlzLnJuZ1VybCkge1xyXG4gICAgICAgIHRocm93IG5ldyBFcnJvcihcclxuICAgICAgICAgICdjcmVhdGVOb25jZSB3aXRoIHJuZy13ZWItYXBpIGhhcyBub3QgYmVlbiBpbXBsZW1lbnRlZCBzbyBmYXInXHJcbiAgICAgICAgKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgLypcclxuICAgICAgICogVGhpcyBhbHBoYWJldCBpcyBmcm9tOlxyXG4gICAgICAgKiBodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNzYzNiNzZWN0aW9uLTQuMVxyXG4gICAgICAgKlxyXG4gICAgICAgKiBbQS1aXSAvIFthLXpdIC8gWzAtOV0gLyBcIi1cIiAvIFwiLlwiIC8gXCJfXCIgLyBcIn5cIlxyXG4gICAgICAgKi9cclxuICAgICAgY29uc3QgdW5yZXNlcnZlZCA9XHJcbiAgICAgICAgJ0FCQ0RFRkdISUpLTE1OT1BRUlNUVVZXWFlaYWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDU2Nzg5LS5ffic7XHJcbiAgICAgIGxldCBzaXplID0gNDU7XHJcbiAgICAgIGxldCBpZCA9ICcnO1xyXG5cclxuICAgICAgY29uc3QgY3J5cHRvID1cclxuICAgICAgICB0eXBlb2Ygc2VsZiA9PT0gJ3VuZGVmaW5lZCcgPyBudWxsIDogc2VsZi5jcnlwdG8gfHwgc2VsZlsnbXNDcnlwdG8nXTtcclxuICAgICAgaWYgKGNyeXB0bykge1xyXG4gICAgICAgIGxldCBieXRlcyA9IG5ldyBVaW50OEFycmF5KHNpemUpO1xyXG4gICAgICAgIGNyeXB0by5nZXRSYW5kb21WYWx1ZXMoYnl0ZXMpO1xyXG5cclxuICAgICAgICAvLyBOZWVkZWQgZm9yIElFXHJcbiAgICAgICAgaWYgKCFieXRlcy5tYXApIHtcclxuICAgICAgICAgIChieXRlcyBhcyBhbnkpLm1hcCA9IEFycmF5LnByb3RvdHlwZS5tYXA7XHJcbiAgICAgICAgfVxyXG5cclxuICAgICAgICBieXRlcyA9IGJ5dGVzLm1hcCh4ID0+IHVucmVzZXJ2ZWQuY2hhckNvZGVBdCh4ICUgdW5yZXNlcnZlZC5sZW5ndGgpKTtcclxuICAgICAgICBpZCA9IFN0cmluZy5mcm9tQ2hhckNvZGUuYXBwbHkobnVsbCwgYnl0ZXMpO1xyXG4gICAgICB9IGVsc2Uge1xyXG4gICAgICAgIHdoaWxlICgwIDwgc2l6ZS0tKSB7XHJcbiAgICAgICAgICBpZCArPSB1bnJlc2VydmVkWyhNYXRoLnJhbmRvbSgpICogdW5yZXNlcnZlZC5sZW5ndGgpIHwgMF07XHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcblxyXG4gICAgICByZXNvbHZlKGJhc2U2NFVybEVuY29kZShpZCkpO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgYXN5bmMgY2hlY2tBdEhhc2gocGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zKTogUHJvbWlzZTxib29sZWFuPiB7XHJcbiAgICBpZiAoIXRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlcikge1xyXG4gICAgICB0aGlzLmxvZ2dlci53YXJuKFxyXG4gICAgICAgICdObyB0b2tlblZhbGlkYXRpb25IYW5kbGVyIGNvbmZpZ3VyZWQuIENhbm5vdCBjaGVjayBhdF9oYXNoLidcclxuICAgICAgKTtcclxuICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gdGhpcy50b2tlblZhbGlkYXRpb25IYW5kbGVyLnZhbGlkYXRlQXRIYXNoKHBhcmFtcyk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgY2hlY2tTaWduYXR1cmUocGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zKTogUHJvbWlzZTxhbnk+IHtcclxuICAgIGlmICghdGhpcy50b2tlblZhbGlkYXRpb25IYW5kbGVyKSB7XHJcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oXHJcbiAgICAgICAgJ05vIHRva2VuVmFsaWRhdGlvbkhhbmRsZXIgY29uZmlndXJlZC4gQ2Fubm90IGNoZWNrIHNpZ25hdHVyZS4nXHJcbiAgICAgICk7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUobnVsbCk7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gdGhpcy50b2tlblZhbGlkYXRpb25IYW5kbGVyLnZhbGlkYXRlU2lnbmF0dXJlKHBhcmFtcyk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBTdGFydCB0aGUgaW1wbGljaXQgZmxvdyBvciB0aGUgY29kZSBmbG93LFxyXG4gICAqIGRlcGVuZGluZyBvbiB5b3VyIGNvbmZpZ3VyYXRpb24uXHJcbiAgICovXHJcbiAgcHVibGljIGluaXRMb2dpbkZsb3coYWRkaXRpb25hbFN0YXRlID0gJycsIHBhcmFtcyA9IHt9KTogdm9pZCB7XHJcbiAgICBpZiAodGhpcy5yZXNwb25zZVR5cGUgPT09ICdjb2RlJykge1xyXG4gICAgICByZXR1cm4gdGhpcy5pbml0Q29kZUZsb3coYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgcmV0dXJuIHRoaXMuaW5pdEltcGxpY2l0RmxvdyhhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcyk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBTdGFydHMgdGhlIGF1dGhvcml6YXRpb24gY29kZSBmbG93IGFuZCByZWRpcmVjdHMgdG8gdXNlciB0b1xyXG4gICAqIHRoZSBhdXRoIHNlcnZlcnMgbG9naW4gdXJsLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBpbml0Q29kZUZsb3coYWRkaXRpb25hbFN0YXRlID0gJycsIHBhcmFtcyA9IHt9KTogdm9pZCB7XHJcbiAgICBpZiAodGhpcy5sb2dpblVybCAhPT0gJycpIHtcclxuICAgICAgdGhpcy5pbml0Q29kZUZsb3dJbnRlcm5hbChhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcyk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICB0aGlzLmV2ZW50c1xyXG4gICAgICAgIC5waXBlKGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkZWQnKSlcclxuICAgICAgICAuc3Vic2NyaWJlKF8gPT4gdGhpcy5pbml0Q29kZUZsb3dJbnRlcm5hbChhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcykpO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBpbml0Q29kZUZsb3dJbnRlcm5hbChhZGRpdGlvbmFsU3RhdGUgPSAnJywgcGFyYW1zID0ge30pOiB2b2lkIHtcclxuICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMubG9naW5VcmwpKSB7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcihcclxuICAgICAgICBcImxvZ2luVXJsICBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5ICdyZXF1aXJlSHR0cHMnIG11c3QgYmUgc2V0IHRvICdmYWxzZScgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS5cIlxyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMuY3JlYXRlTG9naW5VcmwoYWRkaXRpb25hbFN0YXRlLCAnJywgbnVsbCwgZmFsc2UsIHBhcmFtcylcclxuICAgICAgLnRoZW4odGhpcy5jb25maWcub3BlblVyaSlcclxuICAgICAgLmNhdGNoKGVycm9yID0+IHtcclxuICAgICAgICBjb25zb2xlLmVycm9yKCdFcnJvciBpbiBpbml0QXV0aG9yaXphdGlvbkNvZGVGbG93Jyk7XHJcbiAgICAgICAgY29uc29sZS5lcnJvcihlcnJvcik7XHJcbiAgICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGFzeW5jIGNyZWF0ZUNoYWxsYW5nZVZlcmlmaWVyUGFpckZvclBLQ0UoKTogUHJvbWlzZTxcclxuICAgIFtzdHJpbmcsIHN0cmluZ11cclxuICA+IHtcclxuICAgIGlmICghdGhpcy5jcnlwdG8pIHtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKFxyXG4gICAgICAgICdQS0NFIHN1cHBvcnQgZm9yIGNvZGUgZmxvdyBuZWVkcyBhIENyeXB0b0hhbmRlci4gRGlkIHlvdSBpbXBvcnQgdGhlIE9BdXRoTW9kdWxlIHVzaW5nIGZvclJvb3QoKSA/J1xyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IHZlcmlmaWVyID0gYXdhaXQgdGhpcy5jcmVhdGVOb25jZSgpO1xyXG4gICAgY29uc3QgY2hhbGxlbmdlUmF3ID0gYXdhaXQgdGhpcy5jcnlwdG8uY2FsY0hhc2godmVyaWZpZXIsICdzaGEtMjU2Jyk7XHJcbiAgICBjb25zdCBjaGFsbGVuZ2UgPSBiYXNlNjRVcmxFbmNvZGUoY2hhbGxlbmdlUmF3KTtcclxuXHJcbiAgICByZXR1cm4gW2NoYWxsZW5nZSwgdmVyaWZpZXJdO1xyXG4gIH1cclxuXHJcbiAgcHJpdmF0ZSBleHRyYWN0UmVjb2duaXplZEN1c3RvbVBhcmFtZXRlcnMoXHJcbiAgICB0b2tlblJlc3BvbnNlOiBUb2tlblJlc3BvbnNlXHJcbiAgKTogTWFwPHN0cmluZywgc3RyaW5nPiB7XHJcbiAgICBsZXQgZm91bmRQYXJhbWV0ZXJzOiBNYXA8c3RyaW5nLCBzdHJpbmc+ID0gbmV3IE1hcDxzdHJpbmcsIHN0cmluZz4oKTtcclxuICAgIGlmICghdGhpcy5jb25maWcuY3VzdG9tVG9rZW5QYXJhbWV0ZXJzKSB7XHJcbiAgICAgIHJldHVybiBmb3VuZFBhcmFtZXRlcnM7XHJcbiAgICB9XHJcbiAgICB0aGlzLmNvbmZpZy5jdXN0b21Ub2tlblBhcmFtZXRlcnMuZm9yRWFjaCgocmVjb2duaXplZFBhcmFtZXRlcjogc3RyaW5nKSA9PiB7XHJcbiAgICAgIGlmICh0b2tlblJlc3BvbnNlW3JlY29nbml6ZWRQYXJhbWV0ZXJdKSB7XHJcbiAgICAgICAgZm91bmRQYXJhbWV0ZXJzLnNldChcclxuICAgICAgICAgIHJlY29nbml6ZWRQYXJhbWV0ZXIsXHJcbiAgICAgICAgICBKU09OLnN0cmluZ2lmeSh0b2tlblJlc3BvbnNlW3JlY29nbml6ZWRQYXJhbWV0ZXJdKVxyXG4gICAgICAgICk7XHJcbiAgICAgIH1cclxuICAgIH0pO1xyXG4gICAgcmV0dXJuIGZvdW5kUGFyYW1ldGVycztcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFJldm9rZXMgdGhlIGF1dGggdG9rZW4gdG8gc2VjdXJlIHRoZSB2dWxuYXJhYmlsaXR5XHJcbiAgICogb2YgdGhlIHRva2VuIGlzc3VlZCBhbGxvd2luZyB0aGUgYXV0aG9yaXphdGlvbiBzZXJ2ZXIgdG8gY2xlYW5cclxuICAgKiB1cCBhbnkgc2VjdXJpdHkgY3JlZGVudGlhbHMgYXNzb2NpYXRlZCB3aXRoIHRoZSBhdXRob3JpemF0aW9uXHJcbiAgICovXHJcbiAgcHVibGljIHJldm9rZVRva2VuQW5kTG9nb3V0KFxyXG4gICAgY3VzdG9tUGFyYW1ldGVyczogb2JqZWN0ID0ge30sXHJcbiAgICBpZ25vcmVDb3JzSXNzdWVzID0gZmFsc2VcclxuICApOiBQcm9taXNlPGFueT4ge1xyXG4gICAgbGV0IHJldm9rZUVuZHBvaW50ID0gdGhpcy5yZXZvY2F0aW9uRW5kcG9pbnQ7XHJcbiAgICBsZXQgYWNjZXNzVG9rZW4gPSB0aGlzLmdldEFjY2Vzc1Rva2VuKCk7XHJcbiAgICBsZXQgcmVmcmVzaFRva2VuID0gdGhpcy5nZXRSZWZyZXNoVG9rZW4oKTtcclxuXHJcbiAgICBpZiAoIWFjY2Vzc1Rva2VuKSB7XHJcbiAgICAgIHJldHVybjtcclxuICAgIH1cclxuXHJcbiAgICBsZXQgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoKTtcclxuXHJcbiAgICBsZXQgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpLnNldChcclxuICAgICAgJ0NvbnRlbnQtVHlwZScsXHJcbiAgICAgICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnXHJcbiAgICApO1xyXG5cclxuICAgIGlmICh0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcclxuICAgICAgY29uc3QgaGVhZGVyID0gYnRvYShgJHt0aGlzLmNsaWVudElkfToke3RoaXMuZHVtbXlDbGllbnRTZWNyZXR9YCk7XHJcbiAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldCgnQXV0aG9yaXphdGlvbicsICdCYXNpYyAnICsgaGVhZGVyKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xyXG4gICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfaWQnLCB0aGlzLmNsaWVudElkKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCAmJiB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KSB7XHJcbiAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9zZWNyZXQnLCB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xyXG4gICAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xyXG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoa2V5LCB0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zW2tleV0pO1xyXG4gICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcclxuICAgICAgbGV0IHJldm9rZUFjY2Vzc1Rva2VuOiBPYnNlcnZhYmxlPHZvaWQ+O1xyXG4gICAgICBsZXQgcmV2b2tlUmVmcmVzaFRva2VuOiBPYnNlcnZhYmxlPHZvaWQ+O1xyXG5cclxuICAgICAgaWYgKGFjY2Vzc1Rva2VuKSB7XHJcbiAgICAgICAgbGV0IHJldm9rYXRpb25QYXJhbXMgPSBwYXJhbXNcclxuICAgICAgICAgIC5zZXQoJ3Rva2VuJywgYWNjZXNzVG9rZW4pXHJcbiAgICAgICAgICAuc2V0KCd0b2tlbl90eXBlX2hpbnQnLCAnYWNjZXNzX3Rva2VuJyk7XHJcbiAgICAgICAgcmV2b2tlQWNjZXNzVG9rZW4gPSB0aGlzLmh0dHAucG9zdDx2b2lkPihcclxuICAgICAgICAgIHJldm9rZUVuZHBvaW50LFxyXG4gICAgICAgICAgcmV2b2thdGlvblBhcmFtcyxcclxuICAgICAgICAgIHsgaGVhZGVycyB9XHJcbiAgICAgICAgKTtcclxuICAgICAgfSBlbHNlIHtcclxuICAgICAgICByZXZva2VBY2Nlc3NUb2tlbiA9IG9mKG51bGwpO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBpZiAocmVmcmVzaFRva2VuKSB7XHJcbiAgICAgICAgbGV0IHJldm9rYXRpb25QYXJhbXMgPSBwYXJhbXNcclxuICAgICAgICAgIC5zZXQoJ3Rva2VuJywgcmVmcmVzaFRva2VuKVxyXG4gICAgICAgICAgLnNldCgndG9rZW5fdHlwZV9oaW50JywgJ3JlZnJlc2hfdG9rZW4nKTtcclxuICAgICAgICByZXZva2VSZWZyZXNoVG9rZW4gPSB0aGlzLmh0dHAucG9zdDx2b2lkPihcclxuICAgICAgICAgIHJldm9rZUVuZHBvaW50LFxyXG4gICAgICAgICAgcmV2b2thdGlvblBhcmFtcyxcclxuICAgICAgICAgIHsgaGVhZGVycyB9XHJcbiAgICAgICAgKTtcclxuICAgICAgfSBlbHNlIHtcclxuICAgICAgICByZXZva2VSZWZyZXNoVG9rZW4gPSBvZihudWxsKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgaWYgKGlnbm9yZUNvcnNJc3N1ZXMpIHtcclxuICAgICAgICByZXZva2VBY2Nlc3NUb2tlbiA9IHJldm9rZUFjY2Vzc1Rva2VuLnBpcGUoXHJcbiAgICAgICAgICBjYXRjaEVycm9yKChlcnI6IEh0dHBFcnJvclJlc3BvbnNlKSA9PiB7XHJcbiAgICAgICAgICAgIGlmIChlcnIuc3RhdHVzID09PSAwKSB7XHJcbiAgICAgICAgICAgICAgcmV0dXJuIG9mPHZvaWQ+KG51bGwpO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIHJldHVybiB0aHJvd0Vycm9yKGVycik7XHJcbiAgICAgICAgICB9KVxyXG4gICAgICAgICk7XHJcblxyXG4gICAgICAgIHJldm9rZVJlZnJlc2hUb2tlbiA9IHJldm9rZVJlZnJlc2hUb2tlbi5waXBlKFxyXG4gICAgICAgICAgY2F0Y2hFcnJvcigoZXJyOiBIdHRwRXJyb3JSZXNwb25zZSkgPT4ge1xyXG4gICAgICAgICAgICBpZiAoZXJyLnN0YXR1cyA9PT0gMCkge1xyXG4gICAgICAgICAgICAgIHJldHVybiBvZjx2b2lkPihudWxsKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICByZXR1cm4gdGhyb3dFcnJvcihlcnIpO1xyXG4gICAgICAgICAgfSlcclxuICAgICAgICApO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBjb21iaW5lTGF0ZXN0KFtyZXZva2VBY2Nlc3NUb2tlbiwgcmV2b2tlUmVmcmVzaFRva2VuXSkuc3Vic2NyaWJlKFxyXG4gICAgICAgIHJlcyA9PiB7XHJcbiAgICAgICAgICB0aGlzLmxvZ091dChjdXN0b21QYXJhbWV0ZXJzKTtcclxuICAgICAgICAgIHJlc29sdmUocmVzKTtcclxuICAgICAgICAgIHRoaXMubG9nZ2VyLmluZm8oJ1Rva2VuIHN1Y2Nlc3NmdWxseSByZXZva2VkJyk7XHJcbiAgICAgICAgfSxcclxuICAgICAgICBlcnIgPT4ge1xyXG4gICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ0Vycm9yIHJldm9raW5nIHRva2VuJywgZXJyKTtcclxuICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxyXG4gICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9yZXZva2VfZXJyb3InLCBlcnIpXHJcbiAgICAgICAgICApO1xyXG4gICAgICAgICAgcmVqZWN0KGVycik7XHJcbiAgICAgICAgfVxyXG4gICAgICApO1xyXG4gICAgfSk7XHJcbiAgfVxyXG59XHJcbiJdfQ==