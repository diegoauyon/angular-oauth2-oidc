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
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoib2F1dGgtc2VydmljZS5qcyIsInNvdXJjZVJvb3QiOiJDOi9Vc2Vycy9kaWVnby5hdXlvbi9Qcm9qZWN0cy90ZWx1cy9hbmd1bGFyLW9hdXRoMi1vaWRjL3Byb2plY3RzL2xpYi9zcmMvIiwic291cmNlcyI6WyJvYXV0aC1zZXJ2aWNlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiI7QUFBQSxPQUFPLEVBQUUsTUFBTSxFQUFFLFVBQVUsRUFBRSxNQUFNLEVBQWEsUUFBUSxFQUFFLE1BQU0sZUFBZSxDQUFDO0FBQ2hGLE9BQU8sRUFDTCxVQUFVLEVBRVYsV0FBVyxFQUNYLFVBQVUsRUFDWCxNQUFNLHNCQUFzQixDQUFDO0FBQzlCLE9BQU8sRUFDTCxhQUFhLEVBQ2IsSUFBSSxFQUVKLEVBQUUsRUFDRixJQUFJLEVBQ0osT0FBTyxFQUVQLFVBQVUsRUFDWCxNQUFNLE1BQU0sQ0FBQztBQUNkLE9BQU8sRUFDTCxVQUFVLEVBQ1YsWUFBWSxFQUNaLEtBQUssRUFDTCxNQUFNLEVBQ04sS0FBSyxFQUNMLEdBQUcsRUFDSCxTQUFTLEVBQ1QsR0FBRyxFQUNKLE1BQU0sZ0JBQWdCLENBQUM7QUFDeEIsT0FBTyxFQUFFLFFBQVEsRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBRTNDLE9BQU8sRUFDTCxpQkFBaUIsRUFFbEIsTUFBTSx1Q0FBdUMsQ0FBQztBQUMvQyxPQUFPLEVBQUUsZ0JBQWdCLEVBQUUsTUFBTSxzQkFBc0IsQ0FBQztBQUN4RCxPQUFPLEVBQ0wsZUFBZSxFQUVmLGNBQWMsRUFDZCxpQkFBaUIsRUFDbEIsTUFBTSxVQUFVLENBQUM7QUFDbEIsT0FBTyxFQUVMLFdBQVcsRUFDWCxZQUFZLEVBS2IsTUFBTSxTQUFTLENBQUM7QUFDakIsT0FBTyxFQUFFLGdCQUFnQixFQUFFLGVBQWUsRUFBRSxNQUFNLGlCQUFpQixDQUFDO0FBQ3BFLE9BQU8sRUFBRSxVQUFVLEVBQUUsTUFBTSxlQUFlLENBQUM7QUFDM0MsT0FBTyxFQUFFLHVCQUF1QixFQUFFLE1BQU0sV0FB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TUFBTSxDQUFDLGdCQUFnQixDQUFDLENBQUM7Z0JBQzlCLE9BQU8sQ0FBQyxHQUFHLENBQUMsQ0FBQztnQkFDYixJQUFJLENBQUMsTUFBTSxDQUFDLElBQUksQ0FBQyw0QkFBNEIsQ0FBQyxDQUFDO1lBQ2pELENBQUMsRUFDRCxHQUFHLENBQUMsRUFBRTtnQkFDSixJQUFJLENBQUMsTUFBTSxDQUFDLEtBQUssQ0FBQyxzQkFBc0IsRUFBRSxHQUFHLENBQUMsQ0FBQztnQkFDL0MsSUFBSSxDQUFDLGFBQWEsQ0FBQyxJQUFJLENBQ3JCLElBQUksZUFBZSxDQUFDLG9CQUFvQixFQUFFLEdBQUcsQ0FBQyxDQUMvQyxDQUFDO2dCQUNGLE1BQU0sQ0FBQyxHQUFHLENBQUMsQ0FBQztZQUNkLENBQUMsQ0FDRixDQUFDO1FBQ0osQ0FBQyxDQUFDLENBQUM7SUFDTCxDQUFDOzs7WUEva0ZGLFVBQVU7OztZQTNEa0IsTUFBTTtZQUVqQyxVQUFVO1lBeUNWLFlBQVksdUJBeUVULFFBQVE7WUF0RlgsaUJBQWlCLHVCQXVGZCxRQUFRO1lBbkVKLFVBQVUsdUJBb0VkLFFBQVE7WUFyRkosZ0JBQWdCO1lBU3ZCLFdBQVc7WUFVSixXQUFXLHVCQXFFZixRQUFROzRDQUNSLE1BQU0sU0FBQyxRQUFRIiwic291cmNlc0NvbnRlbnQiOlsiaW1wb3J0IHsgSW5qZWN0LCBJbmplY3RhYmxlLCBOZ1pvbmUsIE9uRGVzdHJveSwgT3B0aW9uYWwgfSBmcm9tICdAYW5ndWxhci9jb3JlJztcclxuaW1wb3J0IHtcclxuICBIdHRwQ2xpZW50LFxyXG4gIEh0dHBFcnJvclJlc3BvbnNlLFxyXG4gIEh0dHBIZWFkZXJzLFxyXG4gIEh0dHBQYXJhbXNcclxufSBmcm9tICdAYW5ndWxhci9jb21tb24vaHR0cCc7XHJcbmltcG9ydCB7XHJcbiAgY29tYmluZUxhdGVzdCxcclxuICBmcm9tLFxyXG4gIE9ic2VydmFibGUsXHJcbiAgb2YsXHJcbiAgcmFjZSxcclxuICBTdWJqZWN0LFxyXG4gIFN1YnNjcmlwdGlvbixcclxuICB0aHJvd0Vycm9yXHJcbn0gZnJvbSAncnhqcyc7XHJcbmltcG9ydCB7XHJcbiAgY2F0Y2hFcnJvcixcclxuICBkZWJvdW5jZVRpbWUsXHJcbiAgZGVsYXksXHJcbiAgZmlsdGVyLFxyXG4gIGZpcnN0LFxyXG4gIG1hcCxcclxuICBzd2l0Y2hNYXAsXHJcbiAgdGFwXHJcbn0gZnJvbSAncnhqcy9vcGVyYXRvcnMnO1xyXG5pbXBvcnQgeyBET0NVTUVOVCB9IGZyb20gJ0Bhbmd1bGFyL2NvbW1vbic7XHJcblxyXG5pbXBvcnQge1xyXG4gIFZhbGlkYXRpb25IYW5kbGVyLFxyXG4gIFZhbGlkYXRpb25QYXJhbXNcclxufSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vdmFsaWRhdGlvbi1oYW5kbGVyJztcclxuaW1wb3J0IHsgVXJsSGVscGVyU2VydmljZSB9IGZyb20gJy4vdXJsLWhlbHBlci5zZXJ2aWNlJztcclxuaW1wb3J0IHtcclxuICBPQXV0aEVycm9yRXZlbnQsXHJcbiAgT0F1dGhFdmVudCxcclxuICBPQXV0aEluZm9FdmVudCxcclxuICBPQXV0aFN1Y2Nlc3NFdmVudFxyXG59IGZyb20gJy4vZXZlbnRzJztcclxuaW1wb3J0IHtcclxuICBMb2dpbk9wdGlvbnMsXHJcbiAgT0F1dGhMb2dnZXIsXHJcbiAgT0F1dGhTdG9yYWdlLFxyXG4gIE9pZGNEaXNjb3ZlcnlEb2MsXHJcbiAgUGFyc2VkSWRUb2tlbixcclxuICBUb2tlblJlc3BvbnNlLFxyXG4gIFVzZXJJbmZvXHJcbn0gZnJvbSAnLi90eXBlcyc7XHJcbmltcG9ydCB7IGI2NERlY29kZVVuaWNvZGUsIGJhc2U2NFVybEVuY29kZSB9IGZyb20gJy4vYmFzZTY0LWhlbHBlcic7XHJcbmltcG9ydCB7IEF1dGhDb25maWcgfSBmcm9tICcuL2F1dGguY29uZmlnJztcclxuaW1wb3J0IHsgV2ViSHR0cFVybEVuY29kaW5nQ29kZWMgfSBmcm9tICcuL2VuY29kZXInO1xyXG5pbXBvcnQgeyBIYXNoSGFuZGxlciB9IGZyb20gJy4vdG9rZW4tdmFsaWRhdGlvbi9oYXNoLWhhbmRsZXInO1xyXG5cclxuLyoqXHJcbiAqIFNlcnZpY2UgZm9yIGxvZ2dpbmcgaW4gYW5kIGxvZ2dpbmcgb3V0IHdpdGhcclxuICogT0lEQyBhbmQgT0F1dGgyLiBTdXBwb3J0cyBpbXBsaWNpdCBmbG93IGFuZFxyXG4gKiBwYXNzd29yZCBmbG93LlxyXG4gKi9cclxuQEluamVjdGFibGUoKVxyXG5leHBvcnQgY2xhc3MgT0F1dGhTZXJ2aWNlIGV4dGVuZHMgQXV0aENvbmZpZyBpbXBsZW1lbnRzIE9uRGVzdHJveSB7XHJcbiAgLy8gRXh0ZW5kaW5nIEF1dGhDb25maWcgaXN0IGp1c3QgZm9yIExFR0FDWSByZWFzb25zXHJcbiAgLy8gdG8gbm90IGJyZWFrIGV4aXN0aW5nIGNvZGUuXHJcblxyXG4gIC8qKlxyXG4gICAqIFRoZSBWYWxpZGF0aW9uSGFuZGxlciB1c2VkIHRvIHZhbGlkYXRlIHJlY2VpdmVkXHJcbiAgICogaWRfdG9rZW5zLlxyXG4gICAqL1xyXG4gIHB1YmxpYyB0b2tlblZhbGlkYXRpb25IYW5kbGVyOiBWYWxpZGF0aW9uSGFuZGxlcjtcclxuXHJcbiAgLyoqXHJcbiAgICogQGludGVybmFsXHJcbiAgICogRGVwcmVjYXRlZDogIHVzZSBwcm9wZXJ0eSBldmVudHMgaW5zdGVhZFxyXG4gICAqL1xyXG4gIHB1YmxpYyBkaXNjb3ZlcnlEb2N1bWVudExvYWRlZCA9IGZhbHNlO1xyXG5cclxuICAvKipcclxuICAgKiBAaW50ZXJuYWxcclxuICAgKiBEZXByZWNhdGVkOiAgdXNlIHByb3BlcnR5IGV2ZW50cyBpbnN0ZWFkXHJcbiAgICovXHJcbiAgcHVibGljIGRpc2NvdmVyeURvY3VtZW50TG9hZGVkJDogT2JzZXJ2YWJsZTxPaWRjRGlzY292ZXJ5RG9jPjtcclxuXHJcbiAgLyoqXHJcbiAgICogSW5mb3JtcyBhYm91dCBldmVudHMsIGxpa2UgdG9rZW5fcmVjZWl2ZWQgb3IgdG9rZW5fZXhwaXJlcy5cclxuICAgKiBTZWUgdGhlIHN0cmluZyBlbnVtIEV2ZW50VHlwZSBmb3IgYSBmdWxsIGxpc3Qgb2YgZXZlbnQgdHlwZXMuXHJcbiAgICovXHJcbiAgcHVibGljIGV2ZW50czogT2JzZXJ2YWJsZTxPQXV0aEV2ZW50PjtcclxuXHJcbiAgLyoqXHJcbiAgICogVGhlIHJlY2VpdmVkIChwYXNzZWQgYXJvdW5kKSBzdGF0ZSwgd2hlbiBsb2dnaW5nXHJcbiAgICogaW4gd2l0aCBpbXBsaWNpdCBmbG93LlxyXG4gICAqL1xyXG4gIHB1YmxpYyBzdGF0ZT8gPSAnJztcclxuXHJcbiAgcHJvdGVjdGVkIGV2ZW50c1N1YmplY3Q6IFN1YmplY3Q8T0F1dGhFdmVudD4gPSBuZXcgU3ViamVjdDxPQXV0aEV2ZW50PigpO1xyXG4gIHByb3RlY3RlZCBkaXNjb3ZlcnlEb2N1bWVudExvYWRlZFN1YmplY3Q6IFN1YmplY3Q8XHJcbiAgICBPaWRjRGlzY292ZXJ5RG9jXHJcbiAgPiA9IG5ldyBTdWJqZWN0PE9pZGNEaXNjb3ZlcnlEb2M+KCk7XHJcbiAgcHJvdGVjdGVkIHNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXI6IEV2ZW50TGlzdGVuZXI7XHJcbiAgcHJvdGVjdGVkIGdyYW50VHlwZXNTdXBwb3J0ZWQ6IEFycmF5PHN0cmluZz4gPSBbXTtcclxuICBwcm90ZWN0ZWQgX3N0b3JhZ2U6IE9BdXRoU3RvcmFnZTtcclxuICBwcm90ZWN0ZWQgYWNjZXNzVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uOiBTdWJzY3JpcHRpb247XHJcbiAgcHJvdGVjdGVkIGlkVG9rZW5UaW1lb3V0U3Vic2NyaXB0aW9uOiBTdWJzY3JpcHRpb247XHJcbiAgcHJvdGVjdGVkIHRva2VuUmVjZWl2ZWRTdWJzY3JpcHRpb246IFN1YnNjcmlwdGlvbjtcclxuICBwcm90ZWN0ZWQgc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcjogRXZlbnRMaXN0ZW5lcjtcclxuICBwcm90ZWN0ZWQgandrc1VyaTogc3RyaW5nO1xyXG4gIHByb3RlY3RlZCBzZXNzaW9uQ2hlY2tUaW1lcjogYW55O1xyXG4gIHByb3RlY3RlZCBzaWxlbnRSZWZyZXNoU3ViamVjdDogc3RyaW5nO1xyXG4gIHByb3RlY3RlZCBpbkltcGxpY2l0RmxvdyA9IGZhbHNlO1xyXG5cclxuICBwcm90ZWN0ZWQgc2F2ZU5vbmNlc0luTG9jYWxTdG9yYWdlID0gZmFsc2U7XHJcbiAgcHJpdmF0ZSBkb2N1bWVudDogRG9jdW1lbnQ7XHJcblxyXG4gIGNvbnN0cnVjdG9yKFxyXG4gICAgcHJvdGVjdGVkIG5nWm9uZTogTmdab25lLFxyXG4gICAgcHJvdGVjdGVkIGh0dHA6IEh0dHBDbGllbnQsXHJcbiAgICBAT3B0aW9uYWwoKSBzdG9yYWdlOiBPQXV0aFN0b3JhZ2UsXHJcbiAgICBAT3B0aW9uYWwoKSB0b2tlblZhbGlkYXRpb25IYW5kbGVyOiBWYWxpZGF0aW9uSGFuZGxlcixcclxuICAgIEBPcHRpb25hbCgpIHByb3RlY3RlZCBjb25maWc6IEF1dGhDb25maWcsXHJcbiAgICBwcm90ZWN0ZWQgdXJsSGVscGVyOiBVcmxIZWxwZXJTZXJ2aWNlLFxyXG4gICAgcHJvdGVjdGVkIGxvZ2dlcjogT0F1dGhMb2dnZXIsXHJcbiAgICBAT3B0aW9uYWwoKSBwcm90ZWN0ZWQgY3J5cHRvOiBIYXNoSGFuZGxlcixcclxuICAgIEBJbmplY3QoRE9DVU1FTlQpIGRvY3VtZW50OiBhbnlcclxuICApIHtcclxuICAgIHN1cGVyKCk7XHJcblxyXG4gICAgdGhpcy5kZWJ1ZygnYW5ndWxhci1vYXV0aDItb2lkYyB2OC1iZXRhJyk7XHJcblxyXG4gICAgLy8gU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9tYW5mcmVkc3RleWVyL2FuZ3VsYXItb2F1dGgyLW9pZGMvaXNzdWVzLzc3MyBmb3Igd2h5IHRoaXMgaXMgbmVlZGVkXHJcbiAgICB0aGlzLmRvY3VtZW50ID0gZG9jdW1lbnQ7XHJcblxyXG4gICAgdGhpcy5kaXNjb3ZlcnlEb2N1bWVudExvYWRlZCQgPSB0aGlzLmRpc2NvdmVyeURvY3VtZW50TG9hZGVkU3ViamVjdC5hc09ic2VydmFibGUoKTtcclxuICAgIHRoaXMuZXZlbnRzID0gdGhpcy5ldmVudHNTdWJqZWN0LmFzT2JzZXJ2YWJsZSgpO1xyXG5cclxuICAgIGlmICh0b2tlblZhbGlkYXRpb25IYW5kbGVyKSB7XHJcbiAgICAgIHRoaXMudG9rZW5WYWxpZGF0aW9uSGFuZGxlciA9IHRva2VuVmFsaWRhdGlvbkhhbmRsZXI7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKGNvbmZpZykge1xyXG4gICAgICB0aGlzLmNvbmZpZ3VyZShjb25maWcpO1xyXG4gICAgfVxyXG5cclxuICAgIHRyeSB7XHJcbiAgICAgIGlmIChzdG9yYWdlKSB7XHJcbiAgICAgICAgdGhpcy5zZXRTdG9yYWdlKHN0b3JhZ2UpO1xyXG4gICAgICB9IGVsc2UgaWYgKHR5cGVvZiBzZXNzaW9uU3RvcmFnZSAhPT0gJ3VuZGVmaW5lZCcpIHtcclxuICAgICAgICB0aGlzLnNldFN0b3JhZ2Uoc2Vzc2lvblN0b3JhZ2UpO1xyXG4gICAgICB9XHJcbiAgICB9IGNhdGNoIChlKSB7XHJcbiAgICAgIGNvbnNvbGUuZXJyb3IoXHJcbiAgICAgICAgJ05vIE9BdXRoU3RvcmFnZSBwcm92aWRlZCBhbmQgY2Fubm90IGFjY2VzcyBkZWZhdWx0IChzZXNzaW9uU3RvcmFnZSkuJyArXHJcbiAgICAgICAgICAnQ29uc2lkZXIgcHJvdmlkaW5nIGEgY3VzdG9tIE9BdXRoU3RvcmFnZSBpbXBsZW1lbnRhdGlvbiBpbiB5b3VyIG1vZHVsZS4nLFxyXG4gICAgICAgIGVcclxuICAgICAgKTtcclxuICAgIH1cclxuXHJcbiAgICAvLyBpbiBJRSwgc2Vzc2lvblN0b3JhZ2UgZG9lcyBub3QgYWx3YXlzIHN1cnZpdmUgYSByZWRpcmVjdFxyXG4gICAgaWYgKFxyXG4gICAgICB0eXBlb2Ygd2luZG93ICE9PSAndW5kZWZpbmVkJyAmJlxyXG4gICAgICB0eXBlb2Ygd2luZG93Wydsb2NhbFN0b3JhZ2UnXSAhPT0gJ3VuZGVmaW5lZCdcclxuICAgICkge1xyXG4gICAgICBjb25zdCB1YSA9IHdpbmRvdz8ubmF2aWdhdG9yPy51c2VyQWdlbnQ7XHJcbiAgICAgIGNvbnN0IG1zaWUgPSB1YT8uaW5jbHVkZXMoJ01TSUUgJykgfHwgdWE/LmluY2x1ZGVzKCdUcmlkZW50Jyk7XHJcblxyXG4gICAgICBpZiAobXNpZSkge1xyXG4gICAgICAgIHRoaXMuc2F2ZU5vbmNlc0luTG9jYWxTdG9yYWdlID0gdHJ1ZTtcclxuICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIHRoaXMuc2V0dXBSZWZyZXNoVGltZXIoKTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFVzZSB0aGlzIG1ldGhvZCB0byBjb25maWd1cmUgdGhlIHNlcnZpY2VcclxuICAgKiBAcGFyYW0gY29uZmlnIHRoZSBjb25maWd1cmF0aW9uXHJcbiAgICovXHJcbiAgcHVibGljIGNvbmZpZ3VyZShjb25maWc6IEF1dGhDb25maWcpOiB2b2lkIHtcclxuICAgIC8vIEZvciB0aGUgc2FrZSBvZiBkb3dud2FyZCBjb21wYXRpYmlsaXR5IHdpdGhcclxuICAgIC8vIG9yaWdpbmFsIGNvbmZpZ3VyYXRpb24gQVBJXHJcbiAgICBPYmplY3QuYXNzaWduKHRoaXMsIG5ldyBBdXRoQ29uZmlnKCksIGNvbmZpZyk7XHJcblxyXG4gICAgdGhpcy5jb25maWcgPSBPYmplY3QuYXNzaWduKHt9IGFzIEF1dGhDb25maWcsIG5ldyBBdXRoQ29uZmlnKCksIGNvbmZpZyk7XHJcblxyXG4gICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQpIHtcclxuICAgICAgdGhpcy5zZXR1cFNlc3Npb25DaGVjaygpO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMuY29uZmlnQ2hhbmdlZCgpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGNvbmZpZ0NoYW5nZWQoKTogdm9pZCB7XHJcbiAgICB0aGlzLnNldHVwUmVmcmVzaFRpbWVyKCk7XHJcbiAgfVxyXG5cclxuICBwdWJsaWMgcmVzdGFydFNlc3Npb25DaGVja3NJZlN0aWxsTG9nZ2VkSW4oKTogdm9pZCB7XHJcbiAgICBpZiAodGhpcy5oYXNWYWxpZElkVG9rZW4oKSkge1xyXG4gICAgICB0aGlzLmluaXRTZXNzaW9uQ2hlY2soKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCByZXN0YXJ0UmVmcmVzaFRpbWVySWZTdGlsbExvZ2dlZEluKCk6IHZvaWQge1xyXG4gICAgdGhpcy5zZXR1cEV4cGlyYXRpb25UaW1lcnMoKTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBzZXR1cFNlc3Npb25DaGVjaygpOiB2b2lkIHtcclxuICAgIHRoaXMuZXZlbnRzLnBpcGUoZmlsdGVyKGUgPT4gZS50eXBlID09PSAndG9rZW5fcmVjZWl2ZWQnKSkuc3Vic2NyaWJlKGUgPT4ge1xyXG4gICAgICB0aGlzLmluaXRTZXNzaW9uQ2hlY2soKTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogV2lsbCBzZXR1cCB1cCBzaWxlbnQgcmVmcmVzaGluZyBmb3Igd2hlbiB0aGUgdG9rZW4gaXNcclxuICAgKiBhYm91dCB0byBleHBpcmUuIFdoZW4gdGhlIHVzZXIgaXMgbG9nZ2VkIG91dCB2aWEgdGhpcy5sb2dPdXQgbWV0aG9kLCB0aGVcclxuICAgKiBzaWxlbnQgcmVmcmVzaGluZyB3aWxsIHBhdXNlIGFuZCBub3QgcmVmcmVzaCB0aGUgdG9rZW5zIHVudGlsIHRoZSB1c2VyIGlzXHJcbiAgICogbG9nZ2VkIGJhY2sgaW4gdmlhIHJlY2VpdmluZyBhIG5ldyB0b2tlbi5cclxuICAgKiBAcGFyYW0gcGFyYW1zIEFkZGl0aW9uYWwgcGFyYW1ldGVyIHRvIHBhc3NcclxuICAgKiBAcGFyYW0gbGlzdGVuVG8gU2V0dXAgYXV0b21hdGljIHJlZnJlc2ggb2YgYSBzcGVjaWZpYyB0b2tlbiB0eXBlXHJcbiAgICovXHJcbiAgcHVibGljIHNldHVwQXV0b21hdGljU2lsZW50UmVmcmVzaChcclxuICAgIHBhcmFtczogb2JqZWN0ID0ge30sXHJcbiAgICBsaXN0ZW5Ubz86ICdhY2Nlc3NfdG9rZW4nIHwgJ2lkX3Rva2VuJyB8ICdhbnknLFxyXG4gICAgbm9Qcm9tcHQgPSB0cnVlXHJcbiAgKTogdm9pZCB7XHJcbiAgICBsZXQgc2hvdWxkUnVuU2lsZW50UmVmcmVzaCA9IHRydWU7XHJcbiAgICB0aGlzLmV2ZW50c1xyXG4gICAgICAucGlwZShcclxuICAgICAgICB0YXAoZSA9PiB7XHJcbiAgICAgICAgICBpZiAoZS50eXBlID09PSAndG9rZW5fcmVjZWl2ZWQnKSB7XHJcbiAgICAgICAgICAgIHNob3VsZFJ1blNpbGVudFJlZnJlc2ggPSB0cnVlO1xyXG4gICAgICAgICAgfSBlbHNlIGlmIChlLnR5cGUgPT09ICdsb2dvdXQnKSB7XHJcbiAgICAgICAgICAgIHNob3VsZFJ1blNpbGVudFJlZnJlc2ggPSBmYWxzZTtcclxuICAgICAgICAgIH1cclxuICAgICAgICB9KSxcclxuICAgICAgICBmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICd0b2tlbl9leHBpcmVzJyksXHJcbiAgICAgICAgZGVib3VuY2VUaW1lKDEwMDApXHJcbiAgICAgIClcclxuICAgICAgLnN1YnNjcmliZShlID0+IHtcclxuICAgICAgICBjb25zdCBldmVudCA9IGUgYXMgT0F1dGhJbmZvRXZlbnQ7XHJcbiAgICAgICAgaWYgKFxyXG4gICAgICAgICAgKGxpc3RlblRvID09IG51bGwgfHwgbGlzdGVuVG8gPT09ICdhbnknIHx8IGV2ZW50LmluZm8gPT09IGxpc3RlblRvKSAmJlxyXG4gICAgICAgICAgc2hvdWxkUnVuU2lsZW50UmVmcmVzaFxyXG4gICAgICAgICkge1xyXG4gICAgICAgICAgLy8gdGhpcy5zaWxlbnRSZWZyZXNoKHBhcmFtcywgbm9Qcm9tcHQpLmNhdGNoKF8gPT4ge1xyXG4gICAgICAgICAgdGhpcy5yZWZyZXNoSW50ZXJuYWwocGFyYW1zLCBub1Byb21wdCkuY2F0Y2goXyA9PiB7XHJcbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ0F1dG9tYXRpYyBzaWxlbnQgcmVmcmVzaCBkaWQgbm90IHdvcmsnKTtcclxuICAgICAgICAgIH0pO1xyXG4gICAgICAgIH1cclxuICAgICAgfSk7XHJcblxyXG4gICAgdGhpcy5yZXN0YXJ0UmVmcmVzaFRpbWVySWZTdGlsbExvZ2dlZEluKCk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgcmVmcmVzaEludGVybmFsKFxyXG4gICAgcGFyYW1zLFxyXG4gICAgbm9Qcm9tcHRcclxuICApOiBQcm9taXNlPFRva2VuUmVzcG9uc2UgfCBPQXV0aEV2ZW50PiB7XHJcbiAgICBpZiAoIXRoaXMudXNlU2lsZW50UmVmcmVzaCAmJiB0aGlzLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XHJcbiAgICAgIHJldHVybiB0aGlzLnJlZnJlc2hUb2tlbigpO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgcmV0dXJuIHRoaXMuc2lsZW50UmVmcmVzaChwYXJhbXMsIG5vUHJvbXB0KTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIENvbnZlbmllbmNlIG1ldGhvZCB0aGF0IGZpcnN0IGNhbGxzIGBsb2FkRGlzY292ZXJ5RG9jdW1lbnQoLi4uKWAgYW5kXHJcbiAgICogZGlyZWN0bHkgY2hhaW5zIHVzaW5nIHRoZSBgdGhlbiguLi4pYCBwYXJ0IG9mIHRoZSBwcm9taXNlIHRvIGNhbGxcclxuICAgKiB0aGUgYHRyeUxvZ2luKC4uLilgIG1ldGhvZC5cclxuICAgKlxyXG4gICAqIEBwYXJhbSBvcHRpb25zIExvZ2luT3B0aW9ucyB0byBwYXNzIHRocm91Z2ggdG8gYHRyeUxvZ2luKC4uLilgXHJcbiAgICovXHJcbiAgcHVibGljIGxvYWREaXNjb3ZlcnlEb2N1bWVudEFuZFRyeUxvZ2luKFxyXG4gICAgb3B0aW9uczogTG9naW5PcHRpb25zID0gbnVsbFxyXG4gICk6IFByb21pc2U8Ym9vbGVhbj4ge1xyXG4gICAgcmV0dXJuIHRoaXMubG9hZERpc2NvdmVyeURvY3VtZW50KCkudGhlbihkb2MgPT4ge1xyXG4gICAgICByZXR1cm4gdGhpcy50cnlMb2dpbihvcHRpb25zKTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogQ29udmVuaWVuY2UgbWV0aG9kIHRoYXQgZmlyc3QgY2FsbHMgYGxvYWREaXNjb3ZlcnlEb2N1bWVudEFuZFRyeUxvZ2luKC4uLilgXHJcbiAgICogYW5kIGlmIHRoZW4gY2hhaW5zIHRvIGBpbml0TG9naW5GbG93KClgLCBidXQgb25seSBpZiB0aGVyZSBpcyBubyB2YWxpZFxyXG4gICAqIElkVG9rZW4gb3Igbm8gdmFsaWQgQWNjZXNzVG9rZW4uXHJcbiAgICpcclxuICAgKiBAcGFyYW0gb3B0aW9ucyBMb2dpbk9wdGlvbnMgdG8gcGFzcyB0aHJvdWdoIHRvIGB0cnlMb2dpbiguLi4pYFxyXG4gICAqL1xyXG4gIHB1YmxpYyBsb2FkRGlzY292ZXJ5RG9jdW1lbnRBbmRMb2dpbihcclxuICAgIG9wdGlvbnM6IExvZ2luT3B0aW9ucyAmIHsgc3RhdGU/OiBzdHJpbmcgfSA9IG51bGxcclxuICApOiBQcm9taXNlPGJvb2xlYW4+IHtcclxuICAgIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xyXG4gICAgcmV0dXJuIHRoaXMubG9hZERpc2NvdmVyeURvY3VtZW50QW5kVHJ5TG9naW4ob3B0aW9ucykudGhlbihfID0+IHtcclxuICAgICAgaWYgKCF0aGlzLmhhc1ZhbGlkSWRUb2tlbigpIHx8ICF0aGlzLmhhc1ZhbGlkQWNjZXNzVG9rZW4oKSkge1xyXG4gICAgICAgIGNvbnN0IHN0YXRlID0gdHlwZW9mIG9wdGlvbnMuc3RhdGUgPT09ICdzdHJpbmcnID8gb3B0aW9ucy5zdGF0ZSA6ICcnO1xyXG4gICAgICAgIHRoaXMuaW5pdExvZ2luRmxvdyhzdGF0ZSk7XHJcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICB9IGVsc2Uge1xyXG4gICAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgICB9XHJcbiAgICB9KTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBkZWJ1ZyguLi5hcmdzKTogdm9pZCB7XHJcbiAgICBpZiAodGhpcy5zaG93RGVidWdJbmZvcm1hdGlvbikge1xyXG4gICAgICB0aGlzLmxvZ2dlci5kZWJ1Zy5hcHBseSh0aGlzLmxvZ2dlciwgYXJncyk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgdmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQodXJsOiBzdHJpbmcpOiBzdHJpbmdbXSB7XHJcbiAgICBjb25zdCBlcnJvcnM6IHN0cmluZ1tdID0gW107XHJcbiAgICBjb25zdCBodHRwc0NoZWNrID0gdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHVybCk7XHJcbiAgICBjb25zdCBpc3N1ZXJDaGVjayA9IHRoaXMudmFsaWRhdGVVcmxBZ2FpbnN0SXNzdWVyKHVybCk7XHJcblxyXG4gICAgaWYgKCFodHRwc0NoZWNrKSB7XHJcbiAgICAgIGVycm9ycy5wdXNoKFxyXG4gICAgICAgICdodHRwcyBmb3IgYWxsIHVybHMgcmVxdWlyZWQuIEFsc28gZm9yIHVybHMgcmVjZWl2ZWQgYnkgZGlzY292ZXJ5LidcclxuICAgICAgKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIWlzc3VlckNoZWNrKSB7XHJcbiAgICAgIGVycm9ycy5wdXNoKFxyXG4gICAgICAgICdFdmVyeSB1cmwgaW4gZGlzY292ZXJ5IGRvY3VtZW50IGhhcyB0byBzdGFydCB3aXRoIHRoZSBpc3N1ZXIgdXJsLicgK1xyXG4gICAgICAgICAgJ0Fsc28gc2VlIHByb3BlcnR5IHN0cmljdERpc2NvdmVyeURvY3VtZW50VmFsaWRhdGlvbi4nXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIGVycm9ycztcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCB2YWxpZGF0ZVVybEZvckh0dHBzKHVybDogc3RyaW5nKTogYm9vbGVhbiB7XHJcbiAgICBpZiAoIXVybCkge1xyXG4gICAgICByZXR1cm4gdHJ1ZTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBsY1VybCA9IHVybC50b0xvd2VyQ2FzZSgpO1xyXG5cclxuICAgIGlmICh0aGlzLnJlcXVpcmVIdHRwcyA9PT0gZmFsc2UpIHtcclxuICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKFxyXG4gICAgICAobGNVcmwubWF0Y2goL15odHRwOlxcL1xcL2xvY2FsaG9zdCgkfFs6XFwvXSkvKSB8fFxyXG4gICAgICAgIGxjVXJsLm1hdGNoKC9eaHR0cDpcXC9cXC9sb2NhbGhvc3QoJHxbOlxcL10pLykpICYmXHJcbiAgICAgIHRoaXMucmVxdWlyZUh0dHBzID09PSAncmVtb3RlT25seSdcclxuICAgICkge1xyXG4gICAgICByZXR1cm4gdHJ1ZTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gbGNVcmwuc3RhcnRzV2l0aCgnaHR0cHM6Ly8nKTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBhc3NlcnRVcmxOb3ROdWxsQW5kQ29ycmVjdFByb3RvY29sKFxyXG4gICAgdXJsOiBzdHJpbmcgfCB1bmRlZmluZWQsXHJcbiAgICBkZXNjcmlwdGlvbjogc3RyaW5nXHJcbiAgKSB7XHJcbiAgICBpZiAoIXVybCkge1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoYCcke2Rlc2NyaXB0aW9ufScgc2hvdWxkIG5vdCBiZSBudWxsYCk7XHJcbiAgICB9XHJcbiAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh1cmwpKSB7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcihcclxuICAgICAgICBgJyR7ZGVzY3JpcHRpb259JyBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5ICdyZXF1aXJlSHR0cHMnIG11c3QgYmUgc2V0IHRvICdmYWxzZScgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS5gXHJcbiAgICAgICk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgdmFsaWRhdGVVcmxBZ2FpbnN0SXNzdWVyKHVybDogc3RyaW5nKSB7XHJcbiAgICBpZiAoIXRoaXMuc3RyaWN0RGlzY292ZXJ5RG9jdW1lbnRWYWxpZGF0aW9uKSB7XHJcbiAgICAgIHJldHVybiB0cnVlO1xyXG4gICAgfVxyXG4gICAgaWYgKCF1cmwpIHtcclxuICAgICAgcmV0dXJuIHRydWU7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gdXJsLnRvTG93ZXJDYXNlKCkuc3RhcnRzV2l0aCh0aGlzLmlzc3Vlci50b0xvd2VyQ2FzZSgpKTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBzZXR1cFJlZnJlc2hUaW1lcigpOiB2b2lkIHtcclxuICAgIGlmICh0eXBlb2Ygd2luZG93ID09PSAndW5kZWZpbmVkJykge1xyXG4gICAgICB0aGlzLmRlYnVnKCd0aW1lciBub3Qgc3VwcG9ydGVkIG9uIHRoaXMgcGxhdHRmb3JtJyk7XHJcbiAgICAgIHJldHVybjtcclxuICAgIH1cclxuXHJcbiAgICBpZiAodGhpcy5oYXNWYWxpZElkVG9rZW4oKSB8fCB0aGlzLmhhc1ZhbGlkQWNjZXNzVG9rZW4oKSkge1xyXG4gICAgICB0aGlzLmNsZWFyQWNjZXNzVG9rZW5UaW1lcigpO1xyXG4gICAgICB0aGlzLmNsZWFySWRUb2tlblRpbWVyKCk7XHJcbiAgICAgIHRoaXMuc2V0dXBFeHBpcmF0aW9uVGltZXJzKCk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHRoaXMudG9rZW5SZWNlaXZlZFN1YnNjcmlwdGlvbilcclxuICAgICAgdGhpcy50b2tlblJlY2VpdmVkU3Vic2NyaXB0aW9uLnVuc3Vic2NyaWJlKCk7XHJcblxyXG4gICAgdGhpcy50b2tlblJlY2VpdmVkU3Vic2NyaXB0aW9uID0gdGhpcy5ldmVudHNcclxuICAgICAgLnBpcGUoZmlsdGVyKGUgPT4gZS50eXBlID09PSAndG9rZW5fcmVjZWl2ZWQnKSlcclxuICAgICAgLnN1YnNjcmliZShfID0+IHtcclxuICAgICAgICB0aGlzLmNsZWFyQWNjZXNzVG9rZW5UaW1lcigpO1xyXG4gICAgICAgIHRoaXMuY2xlYXJJZFRva2VuVGltZXIoKTtcclxuICAgICAgICB0aGlzLnNldHVwRXhwaXJhdGlvblRpbWVycygpO1xyXG4gICAgICB9KTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBzZXR1cEV4cGlyYXRpb25UaW1lcnMoKTogdm9pZCB7XHJcbiAgICBpZiAodGhpcy5oYXNWYWxpZEFjY2Vzc1Rva2VuKCkpIHtcclxuICAgICAgdGhpcy5zZXR1cEFjY2Vzc1Rva2VuVGltZXIoKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAodGhpcy5oYXNWYWxpZElkVG9rZW4oKSkge1xyXG4gICAgICB0aGlzLnNldHVwSWRUb2tlblRpbWVyKCk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgc2V0dXBBY2Nlc3NUb2tlblRpbWVyKCk6IHZvaWQge1xyXG4gICAgY29uc3QgZXhwaXJhdGlvbiA9IHRoaXMuZ2V0QWNjZXNzVG9rZW5FeHBpcmF0aW9uKCk7XHJcbiAgICBjb25zdCBzdG9yZWRBdCA9IHRoaXMuZ2V0QWNjZXNzVG9rZW5TdG9yZWRBdCgpO1xyXG4gICAgY29uc3QgdGltZW91dCA9IHRoaXMuY2FsY1RpbWVvdXQoc3RvcmVkQXQsIGV4cGlyYXRpb24pO1xyXG5cclxuICAgIHRoaXMubmdab25lLnJ1bk91dHNpZGVBbmd1bGFyKCgpID0+IHtcclxuICAgICAgdGhpcy5hY2Nlc3NUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24gPSBvZihcclxuICAgICAgICBuZXcgT0F1dGhJbmZvRXZlbnQoJ3Rva2VuX2V4cGlyZXMnLCAnYWNjZXNzX3Rva2VuJylcclxuICAgICAgKVxyXG4gICAgICAgIC5waXBlKGRlbGF5KHRpbWVvdXQpKVxyXG4gICAgICAgIC5zdWJzY3JpYmUoZSA9PiB7XHJcbiAgICAgICAgICB0aGlzLm5nWm9uZS5ydW4oKCkgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChlKTtcclxuICAgICAgICAgIH0pO1xyXG4gICAgICAgIH0pO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgc2V0dXBJZFRva2VuVGltZXIoKTogdm9pZCB7XHJcbiAgICBjb25zdCBleHBpcmF0aW9uID0gdGhpcy5nZXRJZFRva2VuRXhwaXJhdGlvbigpO1xyXG4gICAgY29uc3Qgc3RvcmVkQXQgPSB0aGlzLmdldElkVG9rZW5TdG9yZWRBdCgpO1xyXG4gICAgY29uc3QgdGltZW91dCA9IHRoaXMuY2FsY1RpbWVvdXQoc3RvcmVkQXQsIGV4cGlyYXRpb24pO1xyXG5cclxuICAgIHRoaXMubmdab25lLnJ1bk91dHNpZGVBbmd1bGFyKCgpID0+IHtcclxuICAgICAgdGhpcy5pZFRva2VuVGltZW91dFN1YnNjcmlwdGlvbiA9IG9mKFxyXG4gICAgICAgIG5ldyBPQXV0aEluZm9FdmVudCgndG9rZW5fZXhwaXJlcycsICdpZF90b2tlbicpXHJcbiAgICAgIClcclxuICAgICAgICAucGlwZShkZWxheSh0aW1lb3V0KSlcclxuICAgICAgICAuc3Vic2NyaWJlKGUgPT4ge1xyXG4gICAgICAgICAgdGhpcy5uZ1pvbmUucnVuKCgpID0+IHtcclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZSk7XHJcbiAgICAgICAgICB9KTtcclxuICAgICAgICB9KTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogU3RvcHMgdGltZXJzIGZvciBhdXRvbWF0aWMgcmVmcmVzaC5cclxuICAgKiBUbyByZXN0YXJ0IGl0LCBjYWxsIHNldHVwQXV0b21hdGljU2lsZW50UmVmcmVzaCBhZ2Fpbi5cclxuICAgKi9cclxuICBwdWJsaWMgc3RvcEF1dG9tYXRpY1JlZnJlc2goKSB7XHJcbiAgICB0aGlzLmNsZWFyQWNjZXNzVG9rZW5UaW1lcigpO1xyXG4gICAgdGhpcy5jbGVhcklkVG9rZW5UaW1lcigpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGNsZWFyQWNjZXNzVG9rZW5UaW1lcigpOiB2b2lkIHtcclxuICAgIGlmICh0aGlzLmFjY2Vzc1Rva2VuVGltZW91dFN1YnNjcmlwdGlvbikge1xyXG4gICAgICB0aGlzLmFjY2Vzc1Rva2VuVGltZW91dFN1YnNjcmlwdGlvbi51bnN1YnNjcmliZSgpO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGNsZWFySWRUb2tlblRpbWVyKCk6IHZvaWQge1xyXG4gICAgaWYgKHRoaXMuaWRUb2tlblRpbWVvdXRTdWJzY3JpcHRpb24pIHtcclxuICAgICAgdGhpcy5pZFRva2VuVGltZW91dFN1YnNjcmlwdGlvbi51bnN1YnNjcmliZSgpO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGNhbGNUaW1lb3V0KHN0b3JlZEF0OiBudW1iZXIsIGV4cGlyYXRpb246IG51bWJlcik6IG51bWJlciB7XHJcbiAgICBjb25zdCBub3cgPSBEYXRlLm5vdygpO1xyXG4gICAgY29uc3QgZGVsdGEgPVxyXG4gICAgICAoZXhwaXJhdGlvbiAtIHN0b3JlZEF0KSAqIHRoaXMudGltZW91dEZhY3RvciAtIChub3cgLSBzdG9yZWRBdCk7XHJcbiAgICByZXR1cm4gTWF0aC5tYXgoMCwgZGVsdGEpO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogREVQUkVDQVRFRC4gVXNlIGEgcHJvdmlkZXIgZm9yIE9BdXRoU3RvcmFnZSBpbnN0ZWFkOlxyXG4gICAqXHJcbiAgICogeyBwcm92aWRlOiBPQXV0aFN0b3JhZ2UsIHVzZUZhY3Rvcnk6IG9BdXRoU3RvcmFnZUZhY3RvcnkgfVxyXG4gICAqIGV4cG9ydCBmdW5jdGlvbiBvQXV0aFN0b3JhZ2VGYWN0b3J5KCk6IE9BdXRoU3RvcmFnZSB7IHJldHVybiBsb2NhbFN0b3JhZ2U7IH1cclxuICAgKiBTZXRzIGEgY3VzdG9tIHN0b3JhZ2UgdXNlZCB0byBzdG9yZSB0aGUgcmVjZWl2ZWRcclxuICAgKiB0b2tlbnMgb24gY2xpZW50IHNpZGUuIEJ5IGRlZmF1bHQsIHRoZSBicm93c2VyJ3NcclxuICAgKiBzZXNzaW9uU3RvcmFnZSBpcyB1c2VkLlxyXG4gICAqIEBpZ25vcmVcclxuICAgKlxyXG4gICAqIEBwYXJhbSBzdG9yYWdlXHJcbiAgICovXHJcbiAgcHVibGljIHNldFN0b3JhZ2Uoc3RvcmFnZTogT0F1dGhTdG9yYWdlKTogdm9pZCB7XHJcbiAgICB0aGlzLl9zdG9yYWdlID0gc3RvcmFnZTtcclxuICAgIHRoaXMuY29uZmlnQ2hhbmdlZCgpO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogTG9hZHMgdGhlIGRpc2NvdmVyeSBkb2N1bWVudCB0byBjb25maWd1cmUgbW9zdFxyXG4gICAqIHByb3BlcnRpZXMgb2YgdGhpcyBzZXJ2aWNlLiBUaGUgdXJsIG9mIHRoZSBkaXNjb3ZlcnlcclxuICAgKiBkb2N1bWVudCBpcyBpbmZlcmVkIGZyb20gdGhlIGlzc3VlcidzIHVybCBhY2NvcmRpbmdcclxuICAgKiB0byB0aGUgT3BlbklkIENvbm5lY3Qgc3BlYy4gVG8gdXNlIGFub3RoZXIgdXJsIHlvdVxyXG4gICAqIGNhbiBwYXNzIGl0IHRvIHRvIG9wdGlvbmFsIHBhcmFtZXRlciBmdWxsVXJsLlxyXG4gICAqXHJcbiAgICogQHBhcmFtIGZ1bGxVcmxcclxuICAgKi9cclxuICBwdWJsaWMgbG9hZERpc2NvdmVyeURvY3VtZW50KFxyXG4gICAgZnVsbFVybDogc3RyaW5nID0gbnVsbFxyXG4gICk6IFByb21pc2U8T0F1dGhTdWNjZXNzRXZlbnQ+IHtcclxuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XHJcbiAgICAgIGlmICghZnVsbFVybCkge1xyXG4gICAgICAgIGZ1bGxVcmwgPSB0aGlzLmlzc3VlciB8fCAnJztcclxuICAgICAgICBpZiAoIWZ1bGxVcmwuZW5kc1dpdGgoJy8nKSkge1xyXG4gICAgICAgICAgZnVsbFVybCArPSAnLyc7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIGZ1bGxVcmwgKz0gJy53ZWxsLWtub3duL29wZW5pZC1jb25maWd1cmF0aW9uJztcclxuICAgICAgfVxyXG5cclxuICAgICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHMoZnVsbFVybCkpIHtcclxuICAgICAgICByZWplY3QoXHJcbiAgICAgICAgICBcImlzc3VlciAgbXVzdCB1c2UgSFRUUFMgKHdpdGggVExTKSwgb3IgY29uZmlnIHZhbHVlIGZvciBwcm9wZXJ0eSAncmVxdWlyZUh0dHBzJyBtdXN0IGJlIHNldCB0byAnZmFsc2UnIGFuZCBhbGxvdyBIVFRQICh3aXRob3V0IFRMUykuXCJcclxuICAgICAgICApO1xyXG4gICAgICAgIHJldHVybjtcclxuICAgICAgfVxyXG5cclxuICAgICAgdGhpcy5odHRwLmdldDxPaWRjRGlzY292ZXJ5RG9jPihmdWxsVXJsKS5zdWJzY3JpYmUoXHJcbiAgICAgICAgZG9jID0+IHtcclxuICAgICAgICAgIGlmICghdGhpcy52YWxpZGF0ZURpc2NvdmVyeURvY3VtZW50KGRvYykpIHtcclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXHJcbiAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgnZGlzY292ZXJ5X2RvY3VtZW50X3ZhbGlkYXRpb25fZXJyb3InLCBudWxsKVxyXG4gICAgICAgICAgICApO1xyXG4gICAgICAgICAgICByZWplY3QoJ2Rpc2NvdmVyeV9kb2N1bWVudF92YWxpZGF0aW9uX2Vycm9yJyk7XHJcbiAgICAgICAgICAgIHJldHVybjtcclxuICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICB0aGlzLmxvZ2luVXJsID0gZG9jLmF1dGhvcml6YXRpb25fZW5kcG9pbnQ7XHJcbiAgICAgICAgICB0aGlzLmxvZ291dFVybCA9IGRvYy5lbmRfc2Vzc2lvbl9lbmRwb2ludCB8fCB0aGlzLmxvZ291dFVybDtcclxuICAgICAgICAgIHRoaXMuZ3JhbnRUeXBlc1N1cHBvcnRlZCA9IGRvYy5ncmFudF90eXBlc19zdXBwb3J0ZWQ7XHJcbiAgICAgICAgICB0aGlzLmlzc3VlciA9IGRvYy5pc3N1ZXI7XHJcbiAgICAgICAgICB0aGlzLnRva2VuRW5kcG9pbnQgPSB0aGlzLnRva2VuRW5kcG9pbnRcclxuICAgICAgICAgICAgPyB0aGlzLnRva2VuRW5kcG9pbnRcclxuICAgICAgICAgICAgOiBkb2MudG9rZW5fZW5kcG9pbnQ7XHJcbiAgICAgICAgICB0aGlzLnVzZXJpbmZvRW5kcG9pbnQgPVxyXG4gICAgICAgICAgICBkb2MudXNlcmluZm9fZW5kcG9pbnQgfHwgdGhpcy51c2VyaW5mb0VuZHBvaW50O1xyXG4gICAgICAgICAgdGhpcy5qd2tzVXJpID0gZG9jLmp3a3NfdXJpO1xyXG4gICAgICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVVcmwgPVxyXG4gICAgICAgICAgICBkb2MuY2hlY2tfc2Vzc2lvbl9pZnJhbWUgfHwgdGhpcy5zZXNzaW9uQ2hlY2tJRnJhbWVVcmw7XHJcblxyXG4gICAgICAgICAgdGhpcy5kaXNjb3ZlcnlEb2N1bWVudExvYWRlZCA9IHRydWU7XHJcbiAgICAgICAgICB0aGlzLmRpc2NvdmVyeURvY3VtZW50TG9hZGVkU3ViamVjdC5uZXh0KGRvYyk7XHJcbiAgICAgICAgICB0aGlzLnJldm9jYXRpb25FbmRwb2ludCA9IGRvYy5yZXZvY2F0aW9uX2VuZHBvaW50O1xyXG5cclxuICAgICAgICAgIGlmICh0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkKSB7XHJcbiAgICAgICAgICAgIHRoaXMucmVzdGFydFNlc3Npb25DaGVja3NJZlN0aWxsTG9nZ2VkSW4oKTtcclxuICAgICAgICAgIH1cclxuXHJcbiAgICAgICAgICB0aGlzLmxvYWRKd2tzKClcclxuICAgICAgICAgICAgLnRoZW4oandrcyA9PiB7XHJcbiAgICAgICAgICAgICAgY29uc3QgcmVzdWx0OiBvYmplY3QgPSB7XHJcbiAgICAgICAgICAgICAgICBkaXNjb3ZlcnlEb2N1bWVudDogZG9jLFxyXG4gICAgICAgICAgICAgICAgandrczogandrc1xyXG4gICAgICAgICAgICAgIH07XHJcblxyXG4gICAgICAgICAgICAgIGNvbnN0IGV2ZW50ID0gbmV3IE9BdXRoU3VjY2Vzc0V2ZW50KFxyXG4gICAgICAgICAgICAgICAgJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkZWQnLFxyXG4gICAgICAgICAgICAgICAgcmVzdWx0XHJcbiAgICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChldmVudCk7XHJcbiAgICAgICAgICAgICAgcmVzb2x2ZShldmVudCk7XHJcbiAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICB9KVxyXG4gICAgICAgICAgICAuY2F0Y2goZXJyID0+IHtcclxuICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcclxuICAgICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkX2Vycm9yJywgZXJyKVxyXG4gICAgICAgICAgICAgICk7XHJcbiAgICAgICAgICAgICAgcmVqZWN0KGVycik7XHJcbiAgICAgICAgICAgICAgcmV0dXJuO1xyXG4gICAgICAgICAgICB9KTtcclxuICAgICAgICB9LFxyXG4gICAgICAgIGVyciA9PiB7XHJcbiAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignZXJyb3IgbG9hZGluZyBkaXNjb3ZlcnkgZG9jdW1lbnQnLCBlcnIpO1xyXG4gICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXHJcbiAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkX2Vycm9yJywgZXJyKVxyXG4gICAgICAgICAgKTtcclxuICAgICAgICAgIHJlamVjdChlcnIpO1xyXG4gICAgICAgIH1cclxuICAgICAgKTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGxvYWRKd2tzKCk6IFByb21pc2U8b2JqZWN0PiB7XHJcbiAgICByZXR1cm4gbmV3IFByb21pc2U8b2JqZWN0PigocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XHJcbiAgICAgIGlmICh0aGlzLmp3a3NVcmkpIHtcclxuICAgICAgICB0aGlzLmh0dHAuZ2V0KHRoaXMuandrc1VyaSkuc3Vic2NyaWJlKFxyXG4gICAgICAgICAgandrcyA9PiB7XHJcbiAgICAgICAgICAgIHRoaXMuandrcyA9IGp3a3M7XHJcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxyXG4gICAgICAgICAgICAgIG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRlZCcpXHJcbiAgICAgICAgICAgICk7XHJcbiAgICAgICAgICAgIHJlc29sdmUoandrcyk7XHJcbiAgICAgICAgICB9LFxyXG4gICAgICAgICAgZXJyID0+IHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ2Vycm9yIGxvYWRpbmcgandrcycsIGVycik7XHJcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxyXG4gICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ2p3a3NfbG9hZF9lcnJvcicsIGVycilcclxuICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgcmVqZWN0KGVycik7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgKTtcclxuICAgICAgfSBlbHNlIHtcclxuICAgICAgICByZXNvbHZlKG51bGwpO1xyXG4gICAgICB9XHJcbiAgICB9KTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCB2YWxpZGF0ZURpc2NvdmVyeURvY3VtZW50KGRvYzogT2lkY0Rpc2NvdmVyeURvYyk6IGJvb2xlYW4ge1xyXG4gICAgbGV0IGVycm9yczogc3RyaW5nW107XHJcblxyXG4gICAgaWYgKCF0aGlzLnNraXBJc3N1ZXJDaGVjayAmJiBkb2MuaXNzdWVyICE9PSB0aGlzLmlzc3Vlcikge1xyXG4gICAgICB0aGlzLmxvZ2dlci5lcnJvcihcclxuICAgICAgICAnaW52YWxpZCBpc3N1ZXIgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcclxuICAgICAgICAnZXhwZWN0ZWQ6ICcgKyB0aGlzLmlzc3VlcixcclxuICAgICAgICAnY3VycmVudDogJyArIGRvYy5pc3N1ZXJcclxuICAgICAgKTtcclxuICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgfVxyXG5cclxuICAgIGVycm9ycyA9IHRoaXMudmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQoZG9jLmF1dGhvcml6YXRpb25fZW5kcG9pbnQpO1xyXG4gICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XHJcbiAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxyXG4gICAgICAgICdlcnJvciB2YWxpZGF0aW5nIGF1dGhvcml6YXRpb25fZW5kcG9pbnQgaW4gZGlzY292ZXJ5IGRvY3VtZW50JyxcclxuICAgICAgICBlcnJvcnNcclxuICAgICAgKTtcclxuICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgfVxyXG5cclxuICAgIGVycm9ycyA9IHRoaXMudmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQoZG9jLmVuZF9zZXNzaW9uX2VuZHBvaW50KTtcclxuICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xyXG4gICAgICB0aGlzLmxvZ2dlci5lcnJvcihcclxuICAgICAgICAnZXJyb3IgdmFsaWRhdGluZyBlbmRfc2Vzc2lvbl9lbmRwb2ludCBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxyXG4gICAgICAgIGVycm9yc1xyXG4gICAgICApO1xyXG4gICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICB9XHJcblxyXG4gICAgZXJyb3JzID0gdGhpcy52YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudChkb2MudG9rZW5fZW5kcG9pbnQpO1xyXG4gICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XHJcbiAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxyXG4gICAgICAgICdlcnJvciB2YWxpZGF0aW5nIHRva2VuX2VuZHBvaW50IGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXHJcbiAgICAgICAgZXJyb3JzXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgZXJyb3JzID0gdGhpcy52YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudChkb2MucmV2b2NhdGlvbl9lbmRwb2ludCk7XHJcbiAgICBpZiAoZXJyb3JzLmxlbmd0aCA+IDApIHtcclxuICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoXHJcbiAgICAgICAgJ2Vycm9yIHZhbGlkYXRpbmcgcmV2b2NhdGlvbl9lbmRwb2ludCBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxyXG4gICAgICAgIGVycm9yc1xyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIGVycm9ycyA9IHRoaXMudmFsaWRhdGVVcmxGcm9tRGlzY292ZXJ5RG9jdW1lbnQoZG9jLnVzZXJpbmZvX2VuZHBvaW50KTtcclxuICAgIGlmIChlcnJvcnMubGVuZ3RoID4gMCkge1xyXG4gICAgICB0aGlzLmxvZ2dlci5lcnJvcihcclxuICAgICAgICAnZXJyb3IgdmFsaWRhdGluZyB1c2VyaW5mb19lbmRwb2ludCBpbiBkaXNjb3ZlcnkgZG9jdW1lbnQnLFxyXG4gICAgICAgIGVycm9yc1xyXG4gICAgICApO1xyXG4gICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICB9XHJcblxyXG4gICAgZXJyb3JzID0gdGhpcy52YWxpZGF0ZVVybEZyb21EaXNjb3ZlcnlEb2N1bWVudChkb2Muandrc191cmkpO1xyXG4gICAgaWYgKGVycm9ycy5sZW5ndGggPiAwKSB7XHJcbiAgICAgIHRoaXMubG9nZ2VyLmVycm9yKFxyXG4gICAgICAgICdlcnJvciB2YWxpZGF0aW5nIGp3a3NfdXJpIGluIGRpc2NvdmVyeSBkb2N1bWVudCcsXHJcbiAgICAgICAgZXJyb3JzXHJcbiAgICAgICk7XHJcbiAgICAgIHJldHVybiBmYWxzZTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAodGhpcy5zZXNzaW9uQ2hlY2tzRW5hYmxlZCAmJiAhZG9jLmNoZWNrX3Nlc3Npb25faWZyYW1lKSB7XHJcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oXHJcbiAgICAgICAgJ3Nlc3Npb25DaGVja3NFbmFibGVkIGlzIGFjdGl2YXRlZCBidXQgZGlzY292ZXJ5IGRvY3VtZW50JyArXHJcbiAgICAgICAgICAnIGRvZXMgbm90IGNvbnRhaW4gYSBjaGVja19zZXNzaW9uX2lmcmFtZSBmaWVsZCdcclxuICAgICAgKTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gdHJ1ZTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFVzZXMgcGFzc3dvcmQgZmxvdyB0byBleGNoYW5nZSB1c2VyTmFtZSBhbmQgcGFzc3dvcmQgZm9yIGFuXHJcbiAgICogYWNjZXNzX3Rva2VuLiBBZnRlciByZWNlaXZpbmcgdGhlIGFjY2Vzc190b2tlbiwgdGhpcyBtZXRob2RcclxuICAgKiB1c2VzIGl0IHRvIHF1ZXJ5IHRoZSB1c2VyaW5mbyBlbmRwb2ludCBpbiBvcmRlciB0byBnZXQgaW5mb3JtYXRpb25cclxuICAgKiBhYm91dCB0aGUgdXNlciBpbiBxdWVzdGlvbi5cclxuICAgKlxyXG4gICAqIFdoZW4gdXNpbmcgdGhpcywgbWFrZSBzdXJlIHRoYXQgdGhlIHByb3BlcnR5IG9pZGMgaXMgc2V0IHRvIGZhbHNlLlxyXG4gICAqIE90aGVyd2lzZSBzdHJpY3RlciB2YWxpZGF0aW9ucyB0YWtlIHBsYWNlIHRoYXQgbWFrZSB0aGlzIG9wZXJhdGlvblxyXG4gICAqIGZhaWwuXHJcbiAgICpcclxuICAgKiBAcGFyYW0gdXNlck5hbWVcclxuICAgKiBAcGFyYW0gcGFzc3dvcmRcclxuICAgKiBAcGFyYW0gaGVhZGVycyBPcHRpb25hbCBhZGRpdGlvbmFsIGh0dHAtaGVhZGVycy5cclxuICAgKi9cclxuICBwdWJsaWMgZmV0Y2hUb2tlblVzaW5nUGFzc3dvcmRGbG93QW5kTG9hZFVzZXJQcm9maWxlKFxyXG4gICAgdXNlck5hbWU6IHN0cmluZyxcclxuICAgIHBhc3N3b3JkOiBzdHJpbmcsXHJcbiAgICBoZWFkZXJzOiBIdHRwSGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpXHJcbiAgKTogUHJvbWlzZTxVc2VySW5mbz4ge1xyXG4gICAgcmV0dXJuIHRoaXMuZmV0Y2hUb2tlblVzaW5nUGFzc3dvcmRGbG93KFxyXG4gICAgICB1c2VyTmFtZSxcclxuICAgICAgcGFzc3dvcmQsXHJcbiAgICAgIGhlYWRlcnNcclxuICAgICkudGhlbigoKSA9PiB0aGlzLmxvYWRVc2VyUHJvZmlsZSgpKTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIExvYWRzIHRoZSB1c2VyIHByb2ZpbGUgYnkgYWNjZXNzaW5nIHRoZSB1c2VyIGluZm8gZW5kcG9pbnQgZGVmaW5lZCBieSBPcGVuSWQgQ29ubmVjdC5cclxuICAgKlxyXG4gICAqIFdoZW4gdXNpbmcgdGhpcyB3aXRoIE9BdXRoMiBwYXNzd29yZCBmbG93LCBtYWtlIHN1cmUgdGhhdCB0aGUgcHJvcGVydHkgb2lkYyBpcyBzZXQgdG8gZmFsc2UuXHJcbiAgICogT3RoZXJ3aXNlIHN0cmljdGVyIHZhbGlkYXRpb25zIHRha2UgcGxhY2UgdGhhdCBtYWtlIHRoaXMgb3BlcmF0aW9uIGZhaWwuXHJcbiAgICovXHJcbiAgcHVibGljIGxvYWRVc2VyUHJvZmlsZSgpOiBQcm9taXNlPFVzZXJJbmZvPiB7XHJcbiAgICBpZiAoIXRoaXMuaGFzVmFsaWRBY2Nlc3NUb2tlbigpKSB7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcignQ2FuIG5vdCBsb2FkIFVzZXIgUHJvZmlsZSB3aXRob3V0IGFjY2Vzc190b2tlbicpO1xyXG4gICAgfVxyXG4gICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy51c2VyaW5mb0VuZHBvaW50KSkge1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXHJcbiAgICAgICAgXCJ1c2VyaW5mb0VuZHBvaW50IG11c3QgdXNlIEhUVFBTICh3aXRoIFRMUyksIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgJ3JlcXVpcmVIdHRwcycgbXVzdCBiZSBzZXQgdG8gJ2ZhbHNlJyBhbmQgYWxsb3cgSFRUUCAod2l0aG91dCBUTFMpLlwiXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIG5ldyBQcm9taXNlKChyZXNvbHZlLCByZWplY3QpID0+IHtcclxuICAgICAgY29uc3QgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpLnNldChcclxuICAgICAgICAnQXV0aG9yaXphdGlvbicsXHJcbiAgICAgICAgJ0JlYXJlciAnICsgdGhpcy5nZXRBY2Nlc3NUb2tlbigpXHJcbiAgICAgICk7XHJcblxyXG4gICAgICB0aGlzLmh0dHBcclxuICAgICAgICAuZ2V0PFVzZXJJbmZvPih0aGlzLnVzZXJpbmZvRW5kcG9pbnQsIHsgaGVhZGVycyB9KVxyXG4gICAgICAgIC5zdWJzY3JpYmUoXHJcbiAgICAgICAgICBpbmZvID0+IHtcclxuICAgICAgICAgICAgdGhpcy5kZWJ1ZygndXNlcmluZm8gcmVjZWl2ZWQnLCBpbmZvKTtcclxuXHJcbiAgICAgICAgICAgIGNvbnN0IGV4aXN0aW5nQ2xhaW1zID0gdGhpcy5nZXRJZGVudGl0eUNsYWltcygpIHx8IHt9O1xyXG5cclxuICAgICAgICAgICAgaWYgKCF0aGlzLnNraXBTdWJqZWN0Q2hlY2spIHtcclxuICAgICAgICAgICAgICBpZiAoXHJcbiAgICAgICAgICAgICAgICB0aGlzLm9pZGMgJiZcclxuICAgICAgICAgICAgICAgICghZXhpc3RpbmdDbGFpbXNbJ3N1YiddIHx8IGluZm8uc3ViICE9PSBleGlzdGluZ0NsYWltc1snc3ViJ10pXHJcbiAgICAgICAgICAgICAgKSB7XHJcbiAgICAgICAgICAgICAgICBjb25zdCBlcnIgPVxyXG4gICAgICAgICAgICAgICAgICAnaWYgcHJvcGVydHkgb2lkYyBpcyB0cnVlLCB0aGUgcmVjZWl2ZWQgdXNlci1pZCAoc3ViKSBoYXMgdG8gYmUgdGhlIHVzZXItaWQgJyArXHJcbiAgICAgICAgICAgICAgICAgICdvZiB0aGUgdXNlciB0aGF0IGhhcyBsb2dnZWQgaW4gd2l0aCBvaWRjLlxcbicgK1xyXG4gICAgICAgICAgICAgICAgICAnaWYgeW91IGFyZSBub3QgdXNpbmcgb2lkYyBidXQganVzdCBvYXV0aDIgcGFzc3dvcmQgZmxvdyBzZXQgb2lkYyB0byBmYWxzZSc7XHJcblxyXG4gICAgICAgICAgICAgICAgcmVqZWN0KGVycik7XHJcbiAgICAgICAgICAgICAgICByZXR1cm47XHJcbiAgICAgICAgICAgICAgfVxyXG4gICAgICAgICAgICB9XHJcblxyXG4gICAgICAgICAgICBpbmZvID0gT2JqZWN0LmFzc2lnbih7fSwgZXhpc3RpbmdDbGFpbXMsIGluZm8pO1xyXG5cclxuICAgICAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdpZF90b2tlbl9jbGFpbXNfb2JqJywgSlNPTi5zdHJpbmdpZnkoaW5mbykpO1xyXG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcclxuICAgICAgICAgICAgICBuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3VzZXJfcHJvZmlsZV9sb2FkZWQnKVxyXG4gICAgICAgICAgICApO1xyXG4gICAgICAgICAgICByZXNvbHZlKGluZm8pO1xyXG4gICAgICAgICAgfSxcclxuICAgICAgICAgIGVyciA9PiB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdlcnJvciBsb2FkaW5nIHVzZXIgaW5mbycsIGVycik7XHJcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxyXG4gICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ3VzZXJfcHJvZmlsZV9sb2FkX2Vycm9yJywgZXJyKVxyXG4gICAgICAgICAgICApO1xyXG4gICAgICAgICAgICByZWplY3QoZXJyKTtcclxuICAgICAgICAgIH1cclxuICAgICAgICApO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBVc2VzIHBhc3N3b3JkIGZsb3cgdG8gZXhjaGFuZ2UgdXNlck5hbWUgYW5kIHBhc3N3b3JkIGZvciBhbiBhY2Nlc3NfdG9rZW4uXHJcbiAgICogQHBhcmFtIHVzZXJOYW1lXHJcbiAgICogQHBhcmFtIHBhc3N3b3JkXHJcbiAgICogQHBhcmFtIGhlYWRlcnMgT3B0aW9uYWwgYWRkaXRpb25hbCBodHRwLWhlYWRlcnMuXHJcbiAgICovXHJcbiAgcHVibGljIGZldGNoVG9rZW5Vc2luZ1Bhc3N3b3JkRmxvdyhcclxuICAgIHVzZXJOYW1lOiBzdHJpbmcsXHJcbiAgICBwYXNzd29yZDogc3RyaW5nLFxyXG4gICAgaGVhZGVyczogSHR0cEhlYWRlcnMgPSBuZXcgSHR0cEhlYWRlcnMoKVxyXG4gICk6IFByb21pc2U8VG9rZW5SZXNwb25zZT4ge1xyXG4gICAgdGhpcy5hc3NlcnRVcmxOb3ROdWxsQW5kQ29ycmVjdFByb3RvY29sKFxyXG4gICAgICB0aGlzLnRva2VuRW5kcG9pbnQsXHJcbiAgICAgICd0b2tlbkVuZHBvaW50J1xyXG4gICAgKTtcclxuXHJcbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xyXG4gICAgICAvKipcclxuICAgICAgICogQSBgSHR0cFBhcmFtZXRlckNvZGVjYCB0aGF0IHVzZXMgYGVuY29kZVVSSUNvbXBvbmVudGAgYW5kIGBkZWNvZGVVUklDb21wb25lbnRgIHRvXHJcbiAgICAgICAqIHNlcmlhbGl6ZSBhbmQgcGFyc2UgVVJMIHBhcmFtZXRlciBrZXlzIGFuZCB2YWx1ZXMuXHJcbiAgICAgICAqXHJcbiAgICAgICAqIEBzdGFibGVcclxuICAgICAgICovXHJcbiAgICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcyh7IGVuY29kZXI6IG5ldyBXZWJIdHRwVXJsRW5jb2RpbmdDb2RlYygpIH0pXHJcbiAgICAgICAgLnNldCgnZ3JhbnRfdHlwZScsICdwYXNzd29yZCcpXHJcbiAgICAgICAgLnNldCgnc2NvcGUnLCB0aGlzLnNjb3BlKVxyXG4gICAgICAgIC5zZXQoJ3VzZXJuYW1lJywgdXNlck5hbWUpXHJcbiAgICAgICAgLnNldCgncGFzc3dvcmQnLCBwYXNzd29yZCk7XHJcblxyXG4gICAgICBpZiAodGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XHJcbiAgICAgICAgY29uc3QgaGVhZGVyID0gYnRvYShgJHt0aGlzLmNsaWVudElkfToke3RoaXMuZHVtbXlDbGllbnRTZWNyZXR9YCk7XHJcbiAgICAgICAgaGVhZGVycyA9IGhlYWRlcnMuc2V0KCdBdXRob3JpemF0aW9uJywgJ0Jhc2ljICcgKyBoZWFkZXIpO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xyXG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9pZCcsIHRoaXMuY2xpZW50SWQpO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBpZiAoIXRoaXMudXNlSHR0cEJhc2ljQXV0aCAmJiB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KSB7XHJcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X3NlY3JldCcsIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xyXG4gICAgICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpKSB7XHJcbiAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KGtleSwgdGhpcy5jdXN0b21RdWVyeVBhcmFtc1trZXldKTtcclxuICAgICAgICB9XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldChcclxuICAgICAgICAnQ29udGVudC1UeXBlJyxcclxuICAgICAgICAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJ1xyXG4gICAgICApO1xyXG5cclxuICAgICAgdGhpcy5odHRwXHJcbiAgICAgICAgLnBvc3Q8VG9rZW5SZXNwb25zZT4odGhpcy50b2tlbkVuZHBvaW50LCBwYXJhbXMsIHsgaGVhZGVycyB9KVxyXG4gICAgICAgIC5zdWJzY3JpYmUoXHJcbiAgICAgICAgICB0b2tlblJlc3BvbnNlID0+IHtcclxuICAgICAgICAgICAgdGhpcy5kZWJ1ZygndG9rZW5SZXNwb25zZScsIHRva2VuUmVzcG9uc2UpO1xyXG4gICAgICAgICAgICB0aGlzLnN0b3JlQWNjZXNzVG9rZW5SZXNwb25zZShcclxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlbixcclxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnJlZnJlc2hfdG9rZW4sXHJcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5leHBpcmVzX2luIHx8XHJcbiAgICAgICAgICAgICAgICB0aGlzLmZhbGxiYWNrQWNjZXNzVG9rZW5FeHBpcmF0aW9uVGltZUluU2VjLFxyXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2Uuc2NvcGUsXHJcbiAgICAgICAgICAgICAgdGhpcy5leHRyYWN0UmVjb2duaXplZEN1c3RvbVBhcmFtZXRlcnModG9rZW5SZXNwb25zZSlcclxuICAgICAgICAgICAgKTtcclxuXHJcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XHJcbiAgICAgICAgICAgIHJlc29sdmUodG9rZW5SZXNwb25zZSk7XHJcbiAgICAgICAgICB9LFxyXG4gICAgICAgICAgZXJyID0+IHtcclxuICAgICAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ0Vycm9yIHBlcmZvcm1pbmcgcGFzc3dvcmQgZmxvdycsIGVycik7XHJcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX2Vycm9yJywgZXJyKSk7XHJcbiAgICAgICAgICAgIHJlamVjdChlcnIpO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICk7XHJcbiAgICB9KTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFJlZnJlc2hlcyB0aGUgdG9rZW4gdXNpbmcgYSByZWZyZXNoX3Rva2VuLlxyXG4gICAqIFRoaXMgZG9lcyBub3Qgd29yayBmb3IgaW1wbGljaXQgZmxvdywgYi9jXHJcbiAgICogdGhlcmUgaXMgbm8gcmVmcmVzaF90b2tlbiBpbiB0aGlzIGZsb3cuXHJcbiAgICogQSBzb2x1dGlvbiBmb3IgdGhpcyBpcyBwcm92aWRlZCBieSB0aGVcclxuICAgKiBtZXRob2Qgc2lsZW50UmVmcmVzaC5cclxuICAgKi9cclxuICBwdWJsaWMgcmVmcmVzaFRva2VuKCk6IFByb21pc2U8VG9rZW5SZXNwb25zZT4ge1xyXG4gICAgdGhpcy5hc3NlcnRVcmxOb3ROdWxsQW5kQ29ycmVjdFByb3RvY29sKFxyXG4gICAgICB0aGlzLnRva2VuRW5kcG9pbnQsXHJcbiAgICAgICd0b2tlbkVuZHBvaW50J1xyXG4gICAgKTtcclxuXHJcbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xyXG4gICAgICBsZXQgcGFyYW1zID0gbmV3IEh0dHBQYXJhbXMoKVxyXG4gICAgICAgIC5zZXQoJ2dyYW50X3R5cGUnLCAncmVmcmVzaF90b2tlbicpXHJcbiAgICAgICAgLnNldCgnc2NvcGUnLCB0aGlzLnNjb3BlKVxyXG4gICAgICAgIC5zZXQoJ3JlZnJlc2hfdG9rZW4nLCB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ3JlZnJlc2hfdG9rZW4nKSk7XHJcblxyXG4gICAgICBsZXQgaGVhZGVycyA9IG5ldyBIdHRwSGVhZGVycygpLnNldChcclxuICAgICAgICAnQ29udGVudC1UeXBlJyxcclxuICAgICAgICAnYXBwbGljYXRpb24veC13d3ctZm9ybS11cmxlbmNvZGVkJ1xyXG4gICAgICApO1xyXG5cclxuICAgICAgaWYgKHRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xyXG4gICAgICAgIGNvbnN0IGhlYWRlciA9IGJ0b2EoYCR7dGhpcy5jbGllbnRJZH06JHt0aGlzLmR1bW15Q2xpZW50U2VjcmV0fWApO1xyXG4gICAgICAgIGhlYWRlcnMgPSBoZWFkZXJzLnNldCgnQXV0aG9yaXphdGlvbicsICdCYXNpYyAnICsgaGVhZGVyKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgaWYgKCF0aGlzLnVzZUh0dHBCYXNpY0F1dGgpIHtcclxuICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjbGllbnRfaWQnLCB0aGlzLmNsaWVudElkKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgaWYgKCF0aGlzLnVzZUh0dHBCYXNpY0F1dGggJiYgdGhpcy5kdW1teUNsaWVudFNlY3JldCkge1xyXG4gICAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9zZWNyZXQnLCB0aGlzLmR1bW15Q2xpZW50U2VjcmV0KTtcclxuICAgICAgfVxyXG5cclxuICAgICAgaWYgKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpIHtcclxuICAgICAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xyXG4gICAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldChrZXksIHRoaXMuY3VzdG9tUXVlcnlQYXJhbXNba2V5XSk7XHJcbiAgICAgICAgfVxyXG4gICAgICB9XHJcblxyXG4gICAgICB0aGlzLmh0dHBcclxuICAgICAgICAucG9zdDxUb2tlblJlc3BvbnNlPih0aGlzLnRva2VuRW5kcG9pbnQsIHBhcmFtcywgeyBoZWFkZXJzIH0pXHJcbiAgICAgICAgLnBpcGUoXHJcbiAgICAgICAgICBzd2l0Y2hNYXAodG9rZW5SZXNwb25zZSA9PiB7XHJcbiAgICAgICAgICAgIGlmICh0b2tlblJlc3BvbnNlLmlkX3Rva2VuKSB7XHJcbiAgICAgICAgICAgICAgcmV0dXJuIGZyb20oXHJcbiAgICAgICAgICAgICAgICB0aGlzLnByb2Nlc3NJZFRva2VuKFxyXG4gICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmlkX3Rva2VuLFxyXG4gICAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlbixcclxuICAgICAgICAgICAgICAgICAgdHJ1ZVxyXG4gICAgICAgICAgICAgICAgKVxyXG4gICAgICAgICAgICAgICkucGlwZShcclxuICAgICAgICAgICAgICAgIHRhcChyZXN1bHQgPT4gdGhpcy5zdG9yZUlkVG9rZW4ocmVzdWx0KSksXHJcbiAgICAgICAgICAgICAgICBtYXAoXyA9PiB0b2tlblJlc3BvbnNlKVxyXG4gICAgICAgICAgICAgICk7XHJcbiAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgcmV0dXJuIG9mKHRva2VuUmVzcG9uc2UpO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICB9KVxyXG4gICAgICAgIClcclxuICAgICAgICAuc3Vic2NyaWJlKFxyXG4gICAgICAgICAgdG9rZW5SZXNwb25zZSA9PiB7XHJcbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ3JlZnJlc2ggdG9rZW5SZXNwb25zZScsIHRva2VuUmVzcG9uc2UpO1xyXG4gICAgICAgICAgICB0aGlzLnN0b3JlQWNjZXNzVG9rZW5SZXNwb25zZShcclxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlbixcclxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnJlZnJlc2hfdG9rZW4sXHJcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5leHBpcmVzX2luIHx8XHJcbiAgICAgICAgICAgICAgICB0aGlzLmZhbGxiYWNrQWNjZXNzVG9rZW5FeHBpcmF0aW9uVGltZUluU2VjLFxyXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2Uuc2NvcGUsXHJcbiAgICAgICAgICAgICAgdGhpcy5leHRyYWN0UmVjb2duaXplZEN1c3RvbVBhcmFtZXRlcnModG9rZW5SZXNwb25zZSlcclxuICAgICAgICAgICAgKTtcclxuXHJcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVjZWl2ZWQnKSk7XHJcbiAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVmcmVzaGVkJykpO1xyXG4gICAgICAgICAgICByZXNvbHZlKHRva2VuUmVzcG9uc2UpO1xyXG4gICAgICAgICAgfSxcclxuICAgICAgICAgIGVyciA9PiB7XHJcbiAgICAgICAgICAgIHRoaXMubG9nZ2VyLmVycm9yKCdFcnJvciByZWZyZXNoaW5nIHRva2VuJywgZXJyKTtcclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXHJcbiAgICAgICAgICAgICAgbmV3IE9BdXRoRXJyb3JFdmVudCgndG9rZW5fcmVmcmVzaF9lcnJvcicsIGVycilcclxuICAgICAgICAgICAgKTtcclxuICAgICAgICAgICAgcmVqZWN0KGVycik7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgKTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHJlbW92ZVNpbGVudFJlZnJlc2hFdmVudExpc3RlbmVyKCk6IHZvaWQge1xyXG4gICAgaWYgKHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lcikge1xyXG4gICAgICB3aW5kb3cucmVtb3ZlRXZlbnRMaXN0ZW5lcihcclxuICAgICAgICAnbWVzc2FnZScsXHJcbiAgICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoUG9zdE1lc3NhZ2VFdmVudExpc3RlbmVyXHJcbiAgICAgICk7XHJcbiAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lciA9IG51bGw7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgc2V0dXBTaWxlbnRSZWZyZXNoRXZlbnRMaXN0ZW5lcigpOiB2b2lkIHtcclxuICAgIHRoaXMucmVtb3ZlU2lsZW50UmVmcmVzaEV2ZW50TGlzdGVuZXIoKTtcclxuXHJcbiAgICB0aGlzLnNpbGVudFJlZnJlc2hQb3N0TWVzc2FnZUV2ZW50TGlzdGVuZXIgPSAoZTogTWVzc2FnZUV2ZW50KSA9PiB7XHJcbiAgICAgIGNvbnN0IG1lc3NhZ2UgPSB0aGlzLnByb2Nlc3NNZXNzYWdlRXZlbnRNZXNzYWdlKGUpO1xyXG5cclxuICAgICAgdGhpcy50cnlMb2dpbih7XHJcbiAgICAgICAgY3VzdG9tSGFzaEZyYWdtZW50OiBtZXNzYWdlLFxyXG4gICAgICAgIHByZXZlbnRDbGVhckhhc2hBZnRlckxvZ2luOiB0cnVlLFxyXG4gICAgICAgIGN1c3RvbVJlZGlyZWN0VXJpOiB0aGlzLnNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaSB8fCB0aGlzLnJlZGlyZWN0VXJpXHJcbiAgICAgIH0pLmNhdGNoKGVyciA9PiB0aGlzLmRlYnVnKCd0cnlMb2dpbiBkdXJpbmcgc2lsZW50IHJlZnJlc2ggZmFpbGVkJywgZXJyKSk7XHJcbiAgICB9O1xyXG5cclxuICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKFxyXG4gICAgICAnbWVzc2FnZScsXHJcbiAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFBvc3RNZXNzYWdlRXZlbnRMaXN0ZW5lclxyXG4gICAgKTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFBlcmZvcm1zIGEgc2lsZW50IHJlZnJlc2ggZm9yIGltcGxpY2l0IGZsb3cuXHJcbiAgICogVXNlIHRoaXMgbWV0aG9kIHRvIGdldCBuZXcgdG9rZW5zIHdoZW4vYmVmb3JlXHJcbiAgICogdGhlIGV4aXN0aW5nIHRva2VucyBleHBpcmUuXHJcbiAgICovXHJcbiAgcHVibGljIHNpbGVudFJlZnJlc2goXHJcbiAgICBwYXJhbXM6IG9iamVjdCA9IHt9LFxyXG4gICAgbm9Qcm9tcHQgPSB0cnVlXHJcbiAgKTogUHJvbWlzZTxPQXV0aEV2ZW50PiB7XHJcbiAgICBjb25zdCBjbGFpbXM6IG9iamVjdCA9IHRoaXMuZ2V0SWRlbnRpdHlDbGFpbXMoKSB8fCB7fTtcclxuXHJcbiAgICBpZiAodGhpcy51c2VJZFRva2VuSGludEZvclNpbGVudFJlZnJlc2ggJiYgdGhpcy5oYXNWYWxpZElkVG9rZW4oKSkge1xyXG4gICAgICBwYXJhbXNbJ2lkX3Rva2VuX2hpbnQnXSA9IHRoaXMuZ2V0SWRUb2tlbigpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICghdGhpcy52YWxpZGF0ZVVybEZvckh0dHBzKHRoaXMubG9naW5VcmwpKSB7XHJcbiAgICAgIHRocm93IG5ldyBFcnJvcihcclxuICAgICAgICBcImxvZ2luVXJsICBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5ICdyZXF1aXJlSHR0cHMnIG11c3QgYmUgc2V0IHRvICdmYWxzZScgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS5cIlxyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICh0eXBlb2YgdGhpcy5kb2N1bWVudCA9PT0gJ3VuZGVmaW5lZCcpIHtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKCdzaWxlbnQgcmVmcmVzaCBpcyBub3Qgc3VwcG9ydGVkIG9uIHRoaXMgcGxhdGZvcm0nKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBleGlzdGluZ0lmcmFtZSA9IHRoaXMuZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXHJcbiAgICAgIHRoaXMuc2lsZW50UmVmcmVzaElGcmFtZU5hbWVcclxuICAgICk7XHJcblxyXG4gICAgaWYgKGV4aXN0aW5nSWZyYW1lKSB7XHJcbiAgICAgIHRoaXMuZG9jdW1lbnQuYm9keS5yZW1vdmVDaGlsZChleGlzdGluZ0lmcmFtZSk7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdCA9IGNsYWltc1snc3ViJ107XHJcblxyXG4gICAgY29uc3QgaWZyYW1lID0gdGhpcy5kb2N1bWVudC5jcmVhdGVFbGVtZW50KCdpZnJhbWUnKTtcclxuICAgIGlmcmFtZS5pZCA9IHRoaXMuc2lsZW50UmVmcmVzaElGcmFtZU5hbWU7XHJcblxyXG4gICAgdGhpcy5zZXR1cFNpbGVudFJlZnJlc2hFdmVudExpc3RlbmVyKCk7XHJcblxyXG4gICAgY29uc3QgcmVkaXJlY3RVcmkgPSB0aGlzLnNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaSB8fCB0aGlzLnJlZGlyZWN0VXJpO1xyXG4gICAgdGhpcy5jcmVhdGVMb2dpblVybChudWxsLCBudWxsLCByZWRpcmVjdFVyaSwgbm9Qcm9tcHQsIHBhcmFtcykudGhlbih1cmwgPT4ge1xyXG4gICAgICBpZnJhbWUuc2V0QXR0cmlidXRlKCdzcmMnLCB1cmwpO1xyXG5cclxuICAgICAgaWYgKCF0aGlzLnNpbGVudFJlZnJlc2hTaG93SUZyYW1lKSB7XHJcbiAgICAgICAgaWZyYW1lLnN0eWxlWydkaXNwbGF5J10gPSAnbm9uZSc7XHJcbiAgICAgIH1cclxuICAgICAgdGhpcy5kb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGlmcmFtZSk7XHJcbiAgICB9KTtcclxuXHJcbiAgICBjb25zdCBlcnJvcnMgPSB0aGlzLmV2ZW50cy5waXBlKFxyXG4gICAgICBmaWx0ZXIoZSA9PiBlIGluc3RhbmNlb2YgT0F1dGhFcnJvckV2ZW50KSxcclxuICAgICAgZmlyc3QoKVxyXG4gICAgKTtcclxuICAgIGNvbnN0IHN1Y2Nlc3MgPSB0aGlzLmV2ZW50cy5waXBlKFxyXG4gICAgICBmaWx0ZXIoZSA9PiBlLnR5cGUgPT09ICd0b2tlbl9yZWNlaXZlZCcpLFxyXG4gICAgICBmaXJzdCgpXHJcbiAgICApO1xyXG4gICAgY29uc3QgdGltZW91dCA9IG9mKFxyXG4gICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCdzaWxlbnRfcmVmcmVzaF90aW1lb3V0JywgbnVsbClcclxuICAgICkucGlwZShkZWxheSh0aGlzLnNpbGVudFJlZnJlc2hUaW1lb3V0KSk7XHJcblxyXG4gICAgcmV0dXJuIHJhY2UoW2Vycm9ycywgc3VjY2VzcywgdGltZW91dF0pXHJcbiAgICAgIC5waXBlKFxyXG4gICAgICAgIG1hcChlID0+IHtcclxuICAgICAgICAgIGlmIChlIGluc3RhbmNlb2YgT0F1dGhFcnJvckV2ZW50KSB7XHJcbiAgICAgICAgICAgIGlmIChlLnR5cGUgPT09ICdzaWxlbnRfcmVmcmVzaF90aW1lb3V0Jykge1xyXG4gICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xyXG4gICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgIGUgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCdzaWxlbnRfcmVmcmVzaF9lcnJvcicsIGUpO1xyXG4gICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGUpO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIHRocm93IGU7XHJcbiAgICAgICAgICB9IGVsc2UgaWYgKGUudHlwZSA9PT0gJ3Rva2VuX3JlY2VpdmVkJykge1xyXG4gICAgICAgICAgICBlID0gbmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCdzaWxlbnRseV9yZWZyZXNoZWQnKTtcclxuICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZSk7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgICByZXR1cm4gZTtcclxuICAgICAgICB9KVxyXG4gICAgICApXHJcbiAgICAgIC50b1Byb21pc2UoKTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFRoaXMgbWV0aG9kIGV4aXN0cyBmb3IgYmFja3dhcmRzIGNvbXBhdGliaWxpdHkuXHJcbiAgICoge0BsaW5rIE9BdXRoU2VydmljZSNpbml0TG9naW5GbG93SW5Qb3B1cH0gaGFuZGxlcyBib3RoIGNvZGVcclxuICAgKiBhbmQgaW1wbGljaXQgZmxvd3MuXHJcbiAgICovXHJcbiAgcHVibGljIGluaXRJbXBsaWNpdEZsb3dJblBvcHVwKG9wdGlvbnM/OiB7XHJcbiAgICBoZWlnaHQ/OiBudW1iZXI7XHJcbiAgICB3aWR0aD86IG51bWJlcjtcclxuICB9KSB7XHJcbiAgICByZXR1cm4gdGhpcy5pbml0TG9naW5GbG93SW5Qb3B1cChvcHRpb25zKTtcclxuICB9XHJcblxyXG4gIHB1YmxpYyBpbml0TG9naW5GbG93SW5Qb3B1cChvcHRpb25zPzogeyBoZWlnaHQ/OiBudW1iZXI7IHdpZHRoPzogbnVtYmVyIH0pIHtcclxuICAgIG9wdGlvbnMgPSBvcHRpb25zIHx8IHt9O1xyXG4gICAgcmV0dXJuIHRoaXMuY3JlYXRlTG9naW5VcmwoXHJcbiAgICAgIG51bGwsXHJcbiAgICAgIG51bGwsXHJcbiAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFJlZGlyZWN0VXJpLFxyXG4gICAgICBmYWxzZSxcclxuICAgICAge1xyXG4gICAgICAgIGRpc3BsYXk6ICdwb3B1cCdcclxuICAgICAgfVxyXG4gICAgKS50aGVuKHVybCA9PiB7XHJcbiAgICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XHJcbiAgICAgICAgLyoqXHJcbiAgICAgICAgICogRXJyb3IgaGFuZGxpbmcgc2VjdGlvblxyXG4gICAgICAgICAqL1xyXG4gICAgICAgIGNvbnN0IGNoZWNrRm9yUG9wdXBDbG9zZWRJbnRlcnZhbCA9IDUwMDtcclxuICAgICAgICBsZXQgd2luZG93UmVmID0gd2luZG93Lm9wZW4oXHJcbiAgICAgICAgICB1cmwsXHJcbiAgICAgICAgICAnX2JsYW5rJyxcclxuICAgICAgICAgIHRoaXMuY2FsY3VsYXRlUG9wdXBGZWF0dXJlcyhvcHRpb25zKVxyXG4gICAgICAgICk7XHJcbiAgICAgICAgbGV0IGNoZWNrRm9yUG9wdXBDbG9zZWRUaW1lcjogYW55O1xyXG4gICAgICAgIGNvbnN0IGNoZWNrRm9yUG9wdXBDbG9zZWQgPSAoKSA9PiB7XHJcbiAgICAgICAgICBpZiAoIXdpbmRvd1JlZiB8fCB3aW5kb3dSZWYuY2xvc2VkKSB7XHJcbiAgICAgICAgICAgIGNsZWFudXAoKTtcclxuICAgICAgICAgICAgcmVqZWN0KG5ldyBPQXV0aEVycm9yRXZlbnQoJ3BvcHVwX2Nsb3NlZCcsIHt9KSk7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgfTtcclxuICAgICAgICBpZiAoIXdpbmRvd1JlZikge1xyXG4gICAgICAgICAgcmVqZWN0KG5ldyBPQXV0aEVycm9yRXZlbnQoJ3BvcHVwX2Jsb2NrZWQnLCB7fSkpO1xyXG4gICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICBjaGVja0ZvclBvcHVwQ2xvc2VkVGltZXIgPSB3aW5kb3cuc2V0SW50ZXJ2YWwoXHJcbiAgICAgICAgICAgIGNoZWNrRm9yUG9wdXBDbG9zZWQsXHJcbiAgICAgICAgICAgIGNoZWNrRm9yUG9wdXBDbG9zZWRJbnRlcnZhbFxyXG4gICAgICAgICAgKTtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGNvbnN0IGNsZWFudXAgPSAoKSA9PiB7XHJcbiAgICAgICAgICB3aW5kb3cuY2xlYXJJbnRlcnZhbChjaGVja0ZvclBvcHVwQ2xvc2VkVGltZXIpO1xyXG4gICAgICAgICAgd2luZG93LnJlbW92ZUV2ZW50TGlzdGVuZXIoJ21lc3NhZ2UnLCBsaXN0ZW5lcik7XHJcbiAgICAgICAgICBpZiAod2luZG93UmVmICE9PSBudWxsKSB7XHJcbiAgICAgICAgICAgIHdpbmRvd1JlZi5jbG9zZSgpO1xyXG4gICAgICAgICAgfVxyXG4gICAgICAgICAgd2luZG93UmVmID0gbnVsbDtcclxuICAgICAgICB9O1xyXG5cclxuICAgICAgICBjb25zdCBsaXN0ZW5lciA9IChlOiBNZXNzYWdlRXZlbnQpID0+IHtcclxuICAgICAgICAgIGNvbnN0IG1lc3NhZ2UgPSB0aGlzLnByb2Nlc3NNZXNzYWdlRXZlbnRNZXNzYWdlKGUpO1xyXG5cclxuICAgICAgICAgIGlmIChtZXNzYWdlICYmIG1lc3NhZ2UgIT09IG51bGwpIHtcclxuICAgICAgICAgICAgdGhpcy50cnlMb2dpbih7XHJcbiAgICAgICAgICAgICAgY3VzdG9tSGFzaEZyYWdtZW50OiBtZXNzYWdlLFxyXG4gICAgICAgICAgICAgIHByZXZlbnRDbGVhckhhc2hBZnRlckxvZ2luOiB0cnVlLFxyXG4gICAgICAgICAgICAgIGN1c3RvbVJlZGlyZWN0VXJpOiB0aGlzLnNpbGVudFJlZnJlc2hSZWRpcmVjdFVyaVxyXG4gICAgICAgICAgICB9KS50aGVuKFxyXG4gICAgICAgICAgICAgICgpID0+IHtcclxuICAgICAgICAgICAgICAgIGNsZWFudXAoKTtcclxuICAgICAgICAgICAgICAgIHJlc29sdmUoKTtcclxuICAgICAgICAgICAgICB9LFxyXG4gICAgICAgICAgICAgIGVyciA9PiB7XHJcbiAgICAgICAgICAgICAgICBjbGVhbnVwKCk7XHJcbiAgICAgICAgICAgICAgICByZWplY3QoZXJyKTtcclxuICAgICAgICAgICAgICB9XHJcbiAgICAgICAgICAgICk7XHJcbiAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICBjb25zb2xlLmxvZygnZmFsc2UgZXZlbnQgZmlyaW5nJyk7XHJcbiAgICAgICAgICB9XHJcbiAgICAgICAgfTtcclxuXHJcbiAgICAgICAgd2luZG93LmFkZEV2ZW50TGlzdGVuZXIoJ21lc3NhZ2UnLCBsaXN0ZW5lcik7XHJcbiAgICAgIH0pO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgY2FsY3VsYXRlUG9wdXBGZWF0dXJlcyhvcHRpb25zOiB7XHJcbiAgICBoZWlnaHQ/OiBudW1iZXI7XHJcbiAgICB3aWR0aD86IG51bWJlcjtcclxuICB9KTogc3RyaW5nIHtcclxuICAgIC8vIFNwZWNpZnkgYW4gc3RhdGljIGhlaWdodCBhbmQgd2lkdGggYW5kIGNhbGN1bGF0ZSBjZW50ZXJlZCBwb3NpdGlvblxyXG5cclxuICAgIGNvbnN0IGhlaWdodCA9IG9wdGlvbnMuaGVpZ2h0IHx8IDQ3MDtcclxuICAgIGNvbnN0IHdpZHRoID0gb3B0aW9ucy53aWR0aCB8fCA1MDA7XHJcbiAgICBjb25zdCBsZWZ0ID0gd2luZG93LnNjcmVlbkxlZnQgKyAod2luZG93Lm91dGVyV2lkdGggLSB3aWR0aCkgLyAyO1xyXG4gICAgY29uc3QgdG9wID0gd2luZG93LnNjcmVlblRvcCArICh3aW5kb3cub3V0ZXJIZWlnaHQgLSBoZWlnaHQpIC8gMjtcclxuICAgIHJldHVybiBgbG9jYXRpb249bm8sdG9vbGJhcj1ubyx3aWR0aD0ke3dpZHRofSxoZWlnaHQ9JHtoZWlnaHR9LHRvcD0ke3RvcH0sbGVmdD0ke2xlZnR9YDtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBwcm9jZXNzTWVzc2FnZUV2ZW50TWVzc2FnZShlOiBNZXNzYWdlRXZlbnQpOiBzdHJpbmcge1xyXG4gICAgbGV0IGV4cGVjdGVkUHJlZml4ID0gJyMnO1xyXG5cclxuICAgIGlmICh0aGlzLnNpbGVudFJlZnJlc2hNZXNzYWdlUHJlZml4KSB7XHJcbiAgICAgIGV4cGVjdGVkUHJlZml4ICs9IHRoaXMuc2lsZW50UmVmcmVzaE1lc3NhZ2VQcmVmaXg7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCFlIHx8ICFlLmRhdGEgfHwgdHlwZW9mIGUuZGF0YSAhPT0gJ3N0cmluZycpIHtcclxuICAgICAgcmV0dXJuO1xyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IHByZWZpeGVkTWVzc2FnZTogc3RyaW5nID0gZS5kYXRhO1xyXG5cclxuICAgIGlmICghcHJlZml4ZWRNZXNzYWdlLnN0YXJ0c1dpdGgoZXhwZWN0ZWRQcmVmaXgpKSB7XHJcbiAgICAgIHJldHVybjtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gJyMnICsgcHJlZml4ZWRNZXNzYWdlLnN1YnN0cihleHBlY3RlZFByZWZpeC5sZW5ndGgpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGNhblBlcmZvcm1TZXNzaW9uQ2hlY2soKTogYm9vbGVhbiB7XHJcbiAgICBpZiAoIXRoaXMuc2Vzc2lvbkNoZWNrc0VuYWJsZWQpIHtcclxuICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgfVxyXG4gICAgaWYgKCF0aGlzLnNlc3Npb25DaGVja0lGcmFtZVVybCkge1xyXG4gICAgICBjb25zb2xlLndhcm4oXHJcbiAgICAgICAgJ3Nlc3Npb25DaGVja3NFbmFibGVkIGlzIGFjdGl2YXRlZCBidXQgdGhlcmUgaXMgbm8gc2Vzc2lvbkNoZWNrSUZyYW1lVXJsJ1xyXG4gICAgICApO1xyXG4gICAgICByZXR1cm4gZmFsc2U7XHJcbiAgICB9XHJcbiAgICBjb25zdCBzZXNzaW9uU3RhdGUgPSB0aGlzLmdldFNlc3Npb25TdGF0ZSgpO1xyXG4gICAgaWYgKCFzZXNzaW9uU3RhdGUpIHtcclxuICAgICAgY29uc29sZS53YXJuKFxyXG4gICAgICAgICdzZXNzaW9uQ2hlY2tzRW5hYmxlZCBpcyBhY3RpdmF0ZWQgYnV0IHRoZXJlIGlzIG5vIHNlc3Npb25fc3RhdGUnXHJcbiAgICAgICk7XHJcbiAgICAgIHJldHVybiBmYWxzZTtcclxuICAgIH1cclxuICAgIGlmICh0eXBlb2YgdGhpcy5kb2N1bWVudCA9PT0gJ3VuZGVmaW5lZCcpIHtcclxuICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiB0cnVlO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHNldHVwU2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcigpOiB2b2lkIHtcclxuICAgIHRoaXMucmVtb3ZlU2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcigpO1xyXG5cclxuICAgIHRoaXMuc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lciA9IChlOiBNZXNzYWdlRXZlbnQpID0+IHtcclxuICAgICAgY29uc3Qgb3JpZ2luID0gZS5vcmlnaW4udG9Mb3dlckNhc2UoKTtcclxuICAgICAgY29uc3QgaXNzdWVyID0gdGhpcy5pc3N1ZXIudG9Mb3dlckNhc2UoKTtcclxuXHJcbiAgICAgIHRoaXMuZGVidWcoJ3Nlc3Npb25DaGVja0V2ZW50TGlzdGVuZXInKTtcclxuXHJcbiAgICAgIGlmICghaXNzdWVyLnN0YXJ0c1dpdGgob3JpZ2luKSkge1xyXG4gICAgICAgIHRoaXMuZGVidWcoXHJcbiAgICAgICAgICAnc2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcicsXHJcbiAgICAgICAgICAnd3Jvbmcgb3JpZ2luJyxcclxuICAgICAgICAgIG9yaWdpbixcclxuICAgICAgICAgICdleHBlY3RlZCcsXHJcbiAgICAgICAgICBpc3N1ZXIsXHJcbiAgICAgICAgICAnZXZlbnQnLFxyXG4gICAgICAgICAgZVxyXG4gICAgICAgICk7XHJcblxyXG4gICAgICAgIHJldHVybjtcclxuICAgICAgfVxyXG5cclxuICAgICAgLy8gb25seSBydW4gaW4gQW5ndWxhciB6b25lIGlmIGl0IGlzICdjaGFuZ2VkJyBvciAnZXJyb3InXHJcbiAgICAgIHN3aXRjaCAoZS5kYXRhKSB7XHJcbiAgICAgICAgY2FzZSAndW5jaGFuZ2VkJzpcclxuICAgICAgICAgIHRoaXMuaGFuZGxlU2Vzc2lvblVuY2hhbmdlZCgpO1xyXG4gICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgY2FzZSAnY2hhbmdlZCc6XHJcbiAgICAgICAgICB0aGlzLm5nWm9uZS5ydW4oKCkgPT4ge1xyXG4gICAgICAgICAgICB0aGlzLmhhbmRsZVNlc3Npb25DaGFuZ2UoKTtcclxuICAgICAgICAgIH0pO1xyXG4gICAgICAgICAgYnJlYWs7XHJcbiAgICAgICAgY2FzZSAnZXJyb3InOlxyXG4gICAgICAgICAgdGhpcy5uZ1pvbmUucnVuKCgpID0+IHtcclxuICAgICAgICAgICAgdGhpcy5oYW5kbGVTZXNzaW9uRXJyb3IoKTtcclxuICAgICAgICAgIH0pO1xyXG4gICAgICAgICAgYnJlYWs7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIHRoaXMuZGVidWcoJ2dvdCBpbmZvIGZyb20gc2Vzc2lvbiBjaGVjayBpbmZyYW1lJywgZSk7XHJcbiAgICB9O1xyXG5cclxuICAgIC8vIHByZXZlbnQgQW5ndWxhciBmcm9tIHJlZnJlc2hpbmcgdGhlIHZpZXcgb24gZXZlcnkgbWVzc2FnZSAocnVucyBpbiBpbnRlcnZhbHMpXHJcbiAgICB0aGlzLm5nWm9uZS5ydW5PdXRzaWRlQW5ndWxhcigoKSA9PiB7XHJcbiAgICAgIHdpbmRvdy5hZGRFdmVudExpc3RlbmVyKCdtZXNzYWdlJywgdGhpcy5zZXNzaW9uQ2hlY2tFdmVudExpc3RlbmVyKTtcclxuICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGhhbmRsZVNlc3Npb25VbmNoYW5nZWQoKTogdm9pZCB7XHJcbiAgICB0aGlzLmRlYnVnKCdzZXNzaW9uIGNoZWNrJywgJ3Nlc3Npb24gdW5jaGFuZ2VkJyk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgaGFuZGxlU2Vzc2lvbkNoYW5nZSgpOiB2b2lkIHtcclxuICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEluZm9FdmVudCgnc2Vzc2lvbl9jaGFuZ2VkJykpO1xyXG4gICAgdGhpcy5zdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTtcclxuXHJcbiAgICBpZiAoIXRoaXMudXNlU2lsZW50UmVmcmVzaCAmJiB0aGlzLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XHJcbiAgICAgIHRoaXMucmVmcmVzaFRva2VuKClcclxuICAgICAgICAudGhlbihfID0+IHtcclxuICAgICAgICAgIHRoaXMuZGVidWcoJ3Rva2VuIHJlZnJlc2ggYWZ0ZXIgc2Vzc2lvbiBjaGFuZ2Ugd29ya2VkJyk7XHJcbiAgICAgICAgfSlcclxuICAgICAgICAuY2F0Y2goXyA9PiB7XHJcbiAgICAgICAgICB0aGlzLmRlYnVnKCd0b2tlbiByZWZyZXNoIGRpZCBub3Qgd29yayBhZnRlciBzZXNzaW9uIGNoYW5nZWQnKTtcclxuICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEluZm9FdmVudCgnc2Vzc2lvbl90ZXJtaW5hdGVkJykpO1xyXG4gICAgICAgICAgdGhpcy5sb2dPdXQodHJ1ZSk7XHJcbiAgICAgICAgfSk7XHJcbiAgICB9IGVsc2UgaWYgKHRoaXMuc2lsZW50UmVmcmVzaFJlZGlyZWN0VXJpKSB7XHJcbiAgICAgIHRoaXMuc2lsZW50UmVmcmVzaCgpLmNhdGNoKF8gPT5cclxuICAgICAgICB0aGlzLmRlYnVnKCdzaWxlbnQgcmVmcmVzaCBmYWlsZWQgYWZ0ZXIgc2Vzc2lvbiBjaGFuZ2VkJylcclxuICAgICAgKTtcclxuICAgICAgdGhpcy53YWl0Rm9yU2lsZW50UmVmcmVzaEFmdGVyU2Vzc2lvbkNoYW5nZSgpO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdzZXNzaW9uX3Rlcm1pbmF0ZWQnKSk7XHJcbiAgICAgIHRoaXMubG9nT3V0KHRydWUpO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHdhaXRGb3JTaWxlbnRSZWZyZXNoQWZ0ZXJTZXNzaW9uQ2hhbmdlKCk6IHZvaWQge1xyXG4gICAgdGhpcy5ldmVudHNcclxuICAgICAgLnBpcGUoXHJcbiAgICAgICAgZmlsdGVyKFxyXG4gICAgICAgICAgKGU6IE9BdXRoRXZlbnQpID0+XHJcbiAgICAgICAgICAgIGUudHlwZSA9PT0gJ3NpbGVudGx5X3JlZnJlc2hlZCcgfHxcclxuICAgICAgICAgICAgZS50eXBlID09PSAnc2lsZW50X3JlZnJlc2hfdGltZW91dCcgfHxcclxuICAgICAgICAgICAgZS50eXBlID09PSAnc2lsZW50X3JlZnJlc2hfZXJyb3InXHJcbiAgICAgICAgKSxcclxuICAgICAgICBmaXJzdCgpXHJcbiAgICAgIClcclxuICAgICAgLnN1YnNjcmliZShlID0+IHtcclxuICAgICAgICBpZiAoZS50eXBlICE9PSAnc2lsZW50bHlfcmVmcmVzaGVkJykge1xyXG4gICAgICAgICAgdGhpcy5kZWJ1Zygnc2lsZW50IHJlZnJlc2ggZGlkIG5vdCB3b3JrIGFmdGVyIHNlc3Npb24gY2hhbmdlZCcpO1xyXG4gICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoSW5mb0V2ZW50KCdzZXNzaW9uX3Rlcm1pbmF0ZWQnKSk7XHJcbiAgICAgICAgICB0aGlzLmxvZ091dCh0cnVlKTtcclxuICAgICAgICB9XHJcbiAgICAgIH0pO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGhhbmRsZVNlc3Npb25FcnJvcigpOiB2b2lkIHtcclxuICAgIHRoaXMuc3RvcFNlc3Npb25DaGVja1RpbWVyKCk7XHJcbiAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhJbmZvRXZlbnQoJ3Nlc3Npb25fZXJyb3InKSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgcmVtb3ZlU2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcigpOiB2b2lkIHtcclxuICAgIGlmICh0aGlzLnNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIpIHtcclxuICAgICAgd2luZG93LnJlbW92ZUV2ZW50TGlzdGVuZXIoJ21lc3NhZ2UnLCB0aGlzLnNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIpO1xyXG4gICAgICB0aGlzLnNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIgPSBudWxsO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIGluaXRTZXNzaW9uQ2hlY2soKTogdm9pZCB7XHJcbiAgICBpZiAoIXRoaXMuY2FuUGVyZm9ybVNlc3Npb25DaGVjaygpKSB7XHJcbiAgICAgIHJldHVybjtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBleGlzdGluZ0lmcmFtZSA9IHRoaXMuZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXHJcbiAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZVxyXG4gICAgKTtcclxuICAgIGlmIChleGlzdGluZ0lmcmFtZSkge1xyXG4gICAgICB0aGlzLmRvY3VtZW50LmJvZHkucmVtb3ZlQ2hpbGQoZXhpc3RpbmdJZnJhbWUpO1xyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IGlmcmFtZSA9IHRoaXMuZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgnaWZyYW1lJyk7XHJcbiAgICBpZnJhbWUuaWQgPSB0aGlzLnNlc3Npb25DaGVja0lGcmFtZU5hbWU7XHJcblxyXG4gICAgdGhpcy5zZXR1cFNlc3Npb25DaGVja0V2ZW50TGlzdGVuZXIoKTtcclxuXHJcbiAgICBjb25zdCB1cmwgPSB0aGlzLnNlc3Npb25DaGVja0lGcmFtZVVybDtcclxuICAgIGlmcmFtZS5zZXRBdHRyaWJ1dGUoJ3NyYycsIHVybCk7XHJcbiAgICBpZnJhbWUuc3R5bGUuZGlzcGxheSA9ICdub25lJztcclxuICAgIHRoaXMuZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZChpZnJhbWUpO1xyXG5cclxuICAgIHRoaXMuc3RhcnRTZXNzaW9uQ2hlY2tUaW1lcigpO1xyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHN0YXJ0U2Vzc2lvbkNoZWNrVGltZXIoKTogdm9pZCB7XHJcbiAgICB0aGlzLnN0b3BTZXNzaW9uQ2hlY2tUaW1lcigpO1xyXG4gICAgdGhpcy5uZ1pvbmUucnVuT3V0c2lkZUFuZ3VsYXIoKCkgPT4ge1xyXG4gICAgICB0aGlzLnNlc3Npb25DaGVja1RpbWVyID0gc2V0SW50ZXJ2YWwoXHJcbiAgICAgICAgdGhpcy5jaGVja1Nlc3Npb24uYmluZCh0aGlzKSxcclxuICAgICAgICB0aGlzLnNlc3Npb25DaGVja0ludGVydmFsbFxyXG4gICAgICApO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgc3RvcFNlc3Npb25DaGVja1RpbWVyKCk6IHZvaWQge1xyXG4gICAgaWYgKHRoaXMuc2Vzc2lvbkNoZWNrVGltZXIpIHtcclxuICAgICAgY2xlYXJJbnRlcnZhbCh0aGlzLnNlc3Npb25DaGVja1RpbWVyKTtcclxuICAgICAgdGhpcy5zZXNzaW9uQ2hlY2tUaW1lciA9IG51bGw7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwdWJsaWMgY2hlY2tTZXNzaW9uKCk6IHZvaWQge1xyXG4gICAgY29uc3QgaWZyYW1lOiBhbnkgPSB0aGlzLmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFxyXG4gICAgICB0aGlzLnNlc3Npb25DaGVja0lGcmFtZU5hbWVcclxuICAgICk7XHJcblxyXG4gICAgaWYgKCFpZnJhbWUpIHtcclxuICAgICAgdGhpcy5sb2dnZXIud2FybihcclxuICAgICAgICAnY2hlY2tTZXNzaW9uIGRpZCBub3QgZmluZCBpZnJhbWUnLFxyXG4gICAgICAgIHRoaXMuc2Vzc2lvbkNoZWNrSUZyYW1lTmFtZVxyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IHNlc3Npb25TdGF0ZSA9IHRoaXMuZ2V0U2Vzc2lvblN0YXRlKCk7XHJcblxyXG4gICAgaWYgKCFzZXNzaW9uU3RhdGUpIHtcclxuICAgICAgdGhpcy5zdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBtZXNzYWdlID0gdGhpcy5jbGllbnRJZCArICcgJyArIHNlc3Npb25TdGF0ZTtcclxuICAgIGlmcmFtZS5jb250ZW50V2luZG93LnBvc3RNZXNzYWdlKG1lc3NhZ2UsIHRoaXMuaXNzdWVyKTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBhc3luYyBjcmVhdGVMb2dpblVybChcclxuICAgIHN0YXRlID0gJycsXHJcbiAgICBsb2dpbkhpbnQgPSAnJyxcclxuICAgIGN1c3RvbVJlZGlyZWN0VXJpID0gJycsXHJcbiAgICBub1Byb21wdCA9IGZhbHNlLFxyXG4gICAgcGFyYW1zOiBvYmplY3QgPSB7fVxyXG4gICk6IFByb21pc2U8c3RyaW5nPiB7XHJcbiAgICBjb25zdCB0aGF0ID0gdGhpcztcclxuXHJcbiAgICBsZXQgcmVkaXJlY3RVcmk6IHN0cmluZztcclxuXHJcbiAgICBpZiAoY3VzdG9tUmVkaXJlY3RVcmkpIHtcclxuICAgICAgcmVkaXJlY3RVcmkgPSBjdXN0b21SZWRpcmVjdFVyaTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIHJlZGlyZWN0VXJpID0gdGhpcy5yZWRpcmVjdFVyaTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCBub25jZSA9IGF3YWl0IHRoaXMuY3JlYXRlQW5kU2F2ZU5vbmNlKCk7XHJcblxyXG4gICAgaWYgKHN0YXRlKSB7XHJcbiAgICAgIHN0YXRlID1cclxuICAgICAgICBub25jZSArIHRoaXMuY29uZmlnLm5vbmNlU3RhdGVTZXBhcmF0b3IgKyBlbmNvZGVVUklDb21wb25lbnQoc3RhdGUpO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgc3RhdGUgPSBub25jZTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIXRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICF0aGlzLm9pZGMpIHtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKCdFaXRoZXIgcmVxdWVzdEFjY2Vzc1Rva2VuIG9yIG9pZGMgb3IgYm90aCBtdXN0IGJlIHRydWUnKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAodGhpcy5jb25maWcucmVzcG9uc2VUeXBlKSB7XHJcbiAgICAgIHRoaXMucmVzcG9uc2VUeXBlID0gdGhpcy5jb25maWcucmVzcG9uc2VUeXBlO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgaWYgKHRoaXMub2lkYyAmJiB0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbikge1xyXG4gICAgICAgIHRoaXMucmVzcG9uc2VUeXBlID0gJ2lkX3Rva2VuIHRva2VuJztcclxuICAgICAgfSBlbHNlIGlmICh0aGlzLm9pZGMgJiYgIXRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuKSB7XHJcbiAgICAgICAgdGhpcy5yZXNwb25zZVR5cGUgPSAnaWRfdG9rZW4nO1xyXG4gICAgICB9IGVsc2Uge1xyXG4gICAgICAgIHRoaXMucmVzcG9uc2VUeXBlID0gJ3Rva2VuJztcclxuICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IHNlcGVyYXRpb25DaGFyID0gdGhhdC5sb2dpblVybC5pbmRleE9mKCc/JykgPiAtMSA/ICcmJyA6ICc/JztcclxuXHJcbiAgICBsZXQgc2NvcGUgPSB0aGF0LnNjb3BlO1xyXG5cclxuICAgIGlmICh0aGlzLm9pZGMgJiYgIXNjb3BlLm1hdGNoKC8oXnxcXHMpb3BlbmlkKCR8XFxzKS8pKSB7XHJcbiAgICAgIHNjb3BlID0gJ29wZW5pZCAnICsgc2NvcGU7XHJcbiAgICB9XHJcblxyXG4gICAgbGV0IHVybCA9XHJcbiAgICAgIHRoYXQubG9naW5VcmwgK1xyXG4gICAgICBzZXBlcmF0aW9uQ2hhciArXHJcbiAgICAgICdyZXNwb25zZV90eXBlPScgK1xyXG4gICAgICBlbmNvZGVVUklDb21wb25lbnQodGhhdC5yZXNwb25zZVR5cGUpICtcclxuICAgICAgJyZjbGllbnRfaWQ9JyArXHJcbiAgICAgIGVuY29kZVVSSUNvbXBvbmVudCh0aGF0LmNsaWVudElkKSArXHJcbiAgICAgICcmc3RhdGU9JyArXHJcbiAgICAgIGVuY29kZVVSSUNvbXBvbmVudChzdGF0ZSkgK1xyXG4gICAgICAnJnJlZGlyZWN0X3VyaT0nICtcclxuICAgICAgZW5jb2RlVVJJQ29tcG9uZW50KHJlZGlyZWN0VXJpKSArXHJcbiAgICAgICcmc2NvcGU9JyArXHJcbiAgICAgIGVuY29kZVVSSUNvbXBvbmVudChzY29wZSk7XHJcblxyXG4gICAgaWYgKHRoaXMucmVzcG9uc2VUeXBlLmluY2x1ZGVzKCdjb2RlJykgJiYgIXRoaXMuZGlzYWJsZVBLQ0UpIHtcclxuICAgICAgY29uc3QgW1xyXG4gICAgICAgIGNoYWxsZW5nZSxcclxuICAgICAgICB2ZXJpZmllclxyXG4gICAgICBdID0gYXdhaXQgdGhpcy5jcmVhdGVDaGFsbGFuZ2VWZXJpZmllclBhaXJGb3JQS0NFKCk7XHJcblxyXG4gICAgICBpZiAoXHJcbiAgICAgICAgdGhpcy5zYXZlTm9uY2VzSW5Mb2NhbFN0b3JhZ2UgJiZcclxuICAgICAgICB0eXBlb2Ygd2luZG93Wydsb2NhbFN0b3JhZ2UnXSAhPT0gJ3VuZGVmaW5lZCdcclxuICAgICAgKSB7XHJcbiAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ1BLQ0VfdmVyaWZpZXInLCB2ZXJpZmllcik7XHJcbiAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdQS0NFX3ZlcmlmaWVyJywgdmVyaWZpZXIpO1xyXG4gICAgICB9XHJcblxyXG4gICAgICB1cmwgKz0gJyZjb2RlX2NoYWxsZW5nZT0nICsgY2hhbGxlbmdlO1xyXG4gICAgICB1cmwgKz0gJyZjb2RlX2NoYWxsZW5nZV9tZXRob2Q9UzI1Nic7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKGxvZ2luSGludCkge1xyXG4gICAgICB1cmwgKz0gJyZsb2dpbl9oaW50PScgKyBlbmNvZGVVUklDb21wb25lbnQobG9naW5IaW50KTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAodGhhdC5yZXNvdXJjZSkge1xyXG4gICAgICB1cmwgKz0gJyZyZXNvdXJjZT0nICsgZW5jb2RlVVJJQ29tcG9uZW50KHRoYXQucmVzb3VyY2UpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICh0aGF0Lm9pZGMpIHtcclxuICAgICAgdXJsICs9ICcmbm9uY2U9JyArIGVuY29kZVVSSUNvbXBvbmVudChub25jZSk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKG5vUHJvbXB0KSB7XHJcbiAgICAgIHVybCArPSAnJnByb21wdD1ub25lJztcclxuICAgIH1cclxuXHJcbiAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3Qua2V5cyhwYXJhbXMpKSB7XHJcbiAgICAgIHVybCArPVxyXG4gICAgICAgICcmJyArIGVuY29kZVVSSUNvbXBvbmVudChrZXkpICsgJz0nICsgZW5jb2RlVVJJQ29tcG9uZW50KHBhcmFtc1trZXldKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAodGhpcy5jdXN0b21RdWVyeVBhcmFtcykge1xyXG4gICAgICBmb3IgKGNvbnN0IGtleSBvZiBPYmplY3QuZ2V0T3duUHJvcGVydHlOYW1lcyh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSkge1xyXG4gICAgICAgIHVybCArPVxyXG4gICAgICAgICAgJyYnICsga2V5ICsgJz0nICsgZW5jb2RlVVJJQ29tcG9uZW50KHRoaXMuY3VzdG9tUXVlcnlQYXJhbXNba2V5XSk7XHJcbiAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gdXJsO1xyXG4gIH1cclxuXHJcbiAgaW5pdEltcGxpY2l0Rmxvd0ludGVybmFsKFxyXG4gICAgYWRkaXRpb25hbFN0YXRlID0gJycsXHJcbiAgICBwYXJhbXM6IHN0cmluZyB8IG9iamVjdCA9ICcnXHJcbiAgKTogdm9pZCB7XHJcbiAgICBpZiAodGhpcy5pbkltcGxpY2l0Rmxvdykge1xyXG4gICAgICByZXR1cm47XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy5pbkltcGxpY2l0RmxvdyA9IHRydWU7XHJcblxyXG4gICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy5sb2dpblVybCkpIHtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKFxyXG4gICAgICAgIFwibG9naW5VcmwgIG11c3QgdXNlIEhUVFBTICh3aXRoIFRMUyksIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgJ3JlcXVpcmVIdHRwcycgbXVzdCBiZSBzZXQgdG8gJ2ZhbHNlJyBhbmQgYWxsb3cgSFRUUCAod2l0aG91dCBUTFMpLlwiXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgbGV0IGFkZFBhcmFtczogb2JqZWN0ID0ge307XHJcbiAgICBsZXQgbG9naW5IaW50OiBzdHJpbmcgPSBudWxsO1xyXG5cclxuICAgIGlmICh0eXBlb2YgcGFyYW1zID09PSAnc3RyaW5nJykge1xyXG4gICAgICBsb2dpbkhpbnQgPSBwYXJhbXM7XHJcbiAgICB9IGVsc2UgaWYgKHR5cGVvZiBwYXJhbXMgPT09ICdvYmplY3QnKSB7XHJcbiAgICAgIGFkZFBhcmFtcyA9IHBhcmFtcztcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLmNyZWF0ZUxvZ2luVXJsKGFkZGl0aW9uYWxTdGF0ZSwgbG9naW5IaW50LCBudWxsLCBmYWxzZSwgYWRkUGFyYW1zKVxyXG4gICAgICAudGhlbih0aGlzLmNvbmZpZy5vcGVuVXJpKVxyXG4gICAgICAuY2F0Y2goZXJyb3IgPT4ge1xyXG4gICAgICAgIGNvbnNvbGUuZXJyb3IoJ0Vycm9yIGluIGluaXRJbXBsaWNpdEZsb3cnLCBlcnJvcik7XHJcbiAgICAgICAgdGhpcy5pbkltcGxpY2l0RmxvdyA9IGZhbHNlO1xyXG4gICAgICB9KTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFN0YXJ0cyB0aGUgaW1wbGljaXQgZmxvdyBhbmQgcmVkaXJlY3RzIHRvIHVzZXIgdG9cclxuICAgKiB0aGUgYXV0aCBzZXJ2ZXJzJyBsb2dpbiB1cmwuXHJcbiAgICpcclxuICAgKiBAcGFyYW0gYWRkaXRpb25hbFN0YXRlIE9wdGlvbmFsIHN0YXRlIHRoYXQgaXMgcGFzc2VkIGFyb3VuZC5cclxuICAgKiAgWW91J2xsIGZpbmQgdGhpcyBzdGF0ZSBpbiB0aGUgcHJvcGVydHkgYHN0YXRlYCBhZnRlciBgdHJ5TG9naW5gIGxvZ2dlZCBpbiB0aGUgdXNlci5cclxuICAgKiBAcGFyYW0gcGFyYW1zIEhhc2ggd2l0aCBhZGRpdGlvbmFsIHBhcmFtZXRlci4gSWYgaXQgaXMgYSBzdHJpbmcsIGl0IGlzIHVzZWQgZm9yIHRoZVxyXG4gICAqICAgICAgICAgICAgICAgcGFyYW1ldGVyIGxvZ2luSGludCAoZm9yIHRoZSBzYWtlIG9mIGNvbXBhdGliaWxpdHkgd2l0aCBmb3JtZXIgdmVyc2lvbnMpXHJcbiAgICovXHJcbiAgcHVibGljIGluaXRJbXBsaWNpdEZsb3coXHJcbiAgICBhZGRpdGlvbmFsU3RhdGUgPSAnJyxcclxuICAgIHBhcmFtczogc3RyaW5nIHwgb2JqZWN0ID0gJydcclxuICApOiB2b2lkIHtcclxuICAgIGlmICh0aGlzLmxvZ2luVXJsICE9PSAnJykge1xyXG4gICAgICB0aGlzLmluaXRJbXBsaWNpdEZsb3dJbnRlcm5hbChhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcyk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICB0aGlzLmV2ZW50c1xyXG4gICAgICAgIC5waXBlKGZpbHRlcihlID0+IGUudHlwZSA9PT0gJ2Rpc2NvdmVyeV9kb2N1bWVudF9sb2FkZWQnKSlcclxuICAgICAgICAuc3Vic2NyaWJlKF8gPT4gdGhpcy5pbml0SW1wbGljaXRGbG93SW50ZXJuYWwoYWRkaXRpb25hbFN0YXRlLCBwYXJhbXMpKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFJlc2V0IGN1cnJlbnQgaW1wbGljaXQgZmxvd1xyXG4gICAqXHJcbiAgICogQGRlc2NyaXB0aW9uIFRoaXMgbWV0aG9kIGFsbG93cyByZXNldHRpbmcgdGhlIGN1cnJlbnQgaW1wbGljdCBmbG93IGluIG9yZGVyIHRvIGJlIGluaXRpYWxpemVkIGFnYWluLlxyXG4gICAqL1xyXG4gIHB1YmxpYyByZXNldEltcGxpY2l0RmxvdygpOiB2b2lkIHtcclxuICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSBmYWxzZTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBjYWxsT25Ub2tlblJlY2VpdmVkSWZFeGlzdHMob3B0aW9uczogTG9naW5PcHRpb25zKTogdm9pZCB7XHJcbiAgICBjb25zdCB0aGF0ID0gdGhpcztcclxuICAgIGlmIChvcHRpb25zLm9uVG9rZW5SZWNlaXZlZCkge1xyXG4gICAgICBjb25zdCB0b2tlblBhcmFtcyA9IHtcclxuICAgICAgICBpZENsYWltczogdGhhdC5nZXRJZGVudGl0eUNsYWltcygpLFxyXG4gICAgICAgIGlkVG9rZW46IHRoYXQuZ2V0SWRUb2tlbigpLFxyXG4gICAgICAgIGFjY2Vzc1Rva2VuOiB0aGF0LmdldEFjY2Vzc1Rva2VuKCksXHJcbiAgICAgICAgc3RhdGU6IHRoYXQuc3RhdGVcclxuICAgICAgfTtcclxuICAgICAgb3B0aW9ucy5vblRva2VuUmVjZWl2ZWQodG9rZW5QYXJhbXMpO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgcHJvdGVjdGVkIHN0b3JlQWNjZXNzVG9rZW5SZXNwb25zZShcclxuICAgIGFjY2Vzc1Rva2VuOiBzdHJpbmcsXHJcbiAgICByZWZyZXNoVG9rZW46IHN0cmluZyxcclxuICAgIGV4cGlyZXNJbjogbnVtYmVyLFxyXG4gICAgZ3JhbnRlZFNjb3BlczogU3RyaW5nLFxyXG4gICAgY3VzdG9tUGFyYW1ldGVycz86IE1hcDxzdHJpbmcsIHN0cmluZz5cclxuICApOiB2b2lkIHtcclxuICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnYWNjZXNzX3Rva2VuJywgYWNjZXNzVG9rZW4pO1xyXG4gICAgaWYgKGdyYW50ZWRTY29wZXMgJiYgIUFycmF5LmlzQXJyYXkoZ3JhbnRlZFNjb3BlcykpIHtcclxuICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKFxyXG4gICAgICAgICdncmFudGVkX3Njb3BlcycsXHJcbiAgICAgICAgSlNPTi5zdHJpbmdpZnkoZ3JhbnRlZFNjb3Blcy5zcGxpdCgnKycpKVxyXG4gICAgICApO1xyXG4gICAgfSBlbHNlIGlmIChncmFudGVkU2NvcGVzICYmIEFycmF5LmlzQXJyYXkoZ3JhbnRlZFNjb3BlcykpIHtcclxuICAgICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdncmFudGVkX3Njb3BlcycsIEpTT04uc3RyaW5naWZ5KGdyYW50ZWRTY29wZXMpKTtcclxuICAgIH1cclxuXHJcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2FjY2Vzc190b2tlbl9zdG9yZWRfYXQnLCAnJyArIERhdGUubm93KCkpO1xyXG4gICAgaWYgKGV4cGlyZXNJbikge1xyXG4gICAgICBjb25zdCBleHBpcmVzSW5NaWxsaVNlY29uZHMgPSBleHBpcmVzSW4gKiAxMDAwO1xyXG4gICAgICBjb25zdCBub3cgPSBuZXcgRGF0ZSgpO1xyXG4gICAgICBjb25zdCBleHBpcmVzQXQgPSBub3cuZ2V0VGltZSgpICsgZXhwaXJlc0luTWlsbGlTZWNvbmRzO1xyXG4gICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2V4cGlyZXNfYXQnLCAnJyArIGV4cGlyZXNBdCk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHJlZnJlc2hUb2tlbikge1xyXG4gICAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ3JlZnJlc2hfdG9rZW4nLCByZWZyZXNoVG9rZW4pO1xyXG4gICAgfVxyXG4gICAgaWYgKGN1c3RvbVBhcmFtZXRlcnMpIHtcclxuICAgICAgY3VzdG9tUGFyYW1ldGVycy5mb3JFYWNoKCh2YWx1ZTogc3RyaW5nLCBrZXk6IHN0cmluZykgPT4ge1xyXG4gICAgICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbShrZXksIHZhbHVlKTtcclxuICAgICAgfSk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBEZWxlZ2F0ZXMgdG8gdHJ5TG9naW5JbXBsaWNpdEZsb3cgZm9yIHRoZSBzYWtlIG9mIGNvbXBldGFiaWxpdHlcclxuICAgKiBAcGFyYW0gb3B0aW9ucyBPcHRpb25hbCBvcHRpb25zLlxyXG4gICAqL1xyXG4gIHB1YmxpYyB0cnlMb2dpbihvcHRpb25zOiBMb2dpbk9wdGlvbnMgPSBudWxsKTogUHJvbWlzZTxib29sZWFuPiB7XHJcbiAgICBpZiAodGhpcy5jb25maWcucmVzcG9uc2VUeXBlID09PSAnY29kZScpIHtcclxuICAgICAgcmV0dXJuIHRoaXMudHJ5TG9naW5Db2RlRmxvdyhvcHRpb25zKS50aGVuKF8gPT4gdHJ1ZSk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICByZXR1cm4gdGhpcy50cnlMb2dpbkltcGxpY2l0RmxvdyhvcHRpb25zKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIHByaXZhdGUgcGFyc2VRdWVyeVN0cmluZyhxdWVyeVN0cmluZzogc3RyaW5nKTogb2JqZWN0IHtcclxuICAgIGlmICghcXVlcnlTdHJpbmcgfHwgcXVlcnlTdHJpbmcubGVuZ3RoID09PSAwKSB7XHJcbiAgICAgIHJldHVybiB7fTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAocXVlcnlTdHJpbmcuY2hhckF0KDApID09PSAnPycpIHtcclxuICAgICAgcXVlcnlTdHJpbmcgPSBxdWVyeVN0cmluZy5zdWJzdHIoMSk7XHJcbiAgICB9XHJcblxyXG4gICAgcmV0dXJuIHRoaXMudXJsSGVscGVyLnBhcnNlUXVlcnlTdHJpbmcocXVlcnlTdHJpbmcpO1xyXG4gIH1cclxuXHJcbiAgcHVibGljIHRyeUxvZ2luQ29kZUZsb3cob3B0aW9uczogTG9naW5PcHRpb25zID0gbnVsbCk6IFByb21pc2U8dm9pZD4ge1xyXG4gICAgb3B0aW9ucyA9IG9wdGlvbnMgfHwge307XHJcblxyXG4gICAgY29uc3QgcXVlcnlTb3VyY2UgPSBvcHRpb25zLmN1c3RvbUhhc2hGcmFnbWVudFxyXG4gICAgICA/IG9wdGlvbnMuY3VzdG9tSGFzaEZyYWdtZW50LnN1YnN0cmluZygxKVxyXG4gICAgICA6IHdpbmRvdy5sb2NhdGlvbi5zZWFyY2g7XHJcblxyXG4gICAgY29uc3QgcGFydHMgPSB0aGlzLmdldENvZGVQYXJ0c0Zyb21VcmwocXVlcnlTb3VyY2UpO1xyXG5cclxuICAgIGNvbnN0IGNvZGUgPSBwYXJ0c1snY29kZSddO1xyXG4gICAgY29uc3Qgc3RhdGUgPSBwYXJ0c1snc3RhdGUnXTtcclxuXHJcbiAgICBjb25zdCBzZXNzaW9uU3RhdGUgPSBwYXJ0c1snc2Vzc2lvbl9zdGF0ZSddO1xyXG5cclxuICAgIGlmICghb3B0aW9ucy5wcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbikge1xyXG4gICAgICBjb25zdCBocmVmID0gbG9jYXRpb24uaHJlZlxyXG4gICAgICAgIC5yZXBsYWNlKC9bJlxcP11jb2RlPVteJlxcJF0qLywgJycpXHJcbiAgICAgICAgLnJlcGxhY2UoL1smXFw/XXNjb3BlPVteJlxcJF0qLywgJycpXHJcbiAgICAgICAgLnJlcGxhY2UoL1smXFw/XXN0YXRlPVteJlxcJF0qLywgJycpXHJcbiAgICAgICAgLnJlcGxhY2UoL1smXFw/XXNlc3Npb25fc3RhdGU9W14mXFwkXSovLCAnJyk7XHJcblxyXG4gICAgICBoaXN0b3J5LnJlcGxhY2VTdGF0ZShudWxsLCB3aW5kb3cubmFtZSwgaHJlZik7XHJcbiAgICB9XHJcblxyXG4gICAgbGV0IFtub25jZUluU3RhdGUsIHVzZXJTdGF0ZV0gPSB0aGlzLnBhcnNlU3RhdGUoc3RhdGUpO1xyXG4gICAgdGhpcy5zdGF0ZSA9IHVzZXJTdGF0ZTtcclxuXHJcbiAgICBpZiAocGFydHNbJ2Vycm9yJ10pIHtcclxuICAgICAgdGhpcy5kZWJ1ZygnZXJyb3IgdHJ5aW5nIHRvIGxvZ2luJyk7XHJcbiAgICAgIHRoaXMuaGFuZGxlTG9naW5FcnJvcih7fSwgcGFydHMpO1xyXG4gICAgICBjb25zdCBlcnIgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCdjb2RlX2Vycm9yJywge30sIHBhcnRzKTtcclxuICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZXJyKTtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCFub25jZUluU3RhdGUpIHtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSgpO1xyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IHN1Y2Nlc3MgPSB0aGlzLnZhbGlkYXRlTm9uY2Uobm9uY2VJblN0YXRlKTtcclxuICAgIGlmICghc3VjY2Vzcykge1xyXG4gICAgICBjb25zdCBldmVudCA9IG5ldyBPQXV0aEVycm9yRXZlbnQoJ2ludmFsaWRfbm9uY2VfaW5fc3RhdGUnLCBudWxsKTtcclxuICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoZXZlbnQpO1xyXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXZlbnQpO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMuc3RvcmVTZXNzaW9uU3RhdGUoc2Vzc2lvblN0YXRlKTtcclxuXHJcbiAgICBpZiAoY29kZSkge1xyXG4gICAgICByZXR1cm4gdGhpcy5nZXRUb2tlbkZyb21Db2RlKGNvZGUsIG9wdGlvbnMpLnRoZW4oXyA9PiBudWxsKTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFJldHJpZXZlIHRoZSByZXR1cm5lZCBhdXRoIGNvZGUgZnJvbSB0aGUgcmVkaXJlY3QgdXJpIHRoYXQgaGFzIGJlZW4gY2FsbGVkLlxyXG4gICAqIElmIHJlcXVpcmVkIGFsc28gY2hlY2sgaGFzaCwgYXMgd2UgY291bGQgdXNlIGhhc2ggbG9jYXRpb24gc3RyYXRlZ3kuXHJcbiAgICovXHJcbiAgcHJpdmF0ZSBnZXRDb2RlUGFydHNGcm9tVXJsKHF1ZXJ5U3RyaW5nOiBzdHJpbmcpOiBvYmplY3Qge1xyXG4gICAgaWYgKCFxdWVyeVN0cmluZyB8fCBxdWVyeVN0cmluZy5sZW5ndGggPT09IDApIHtcclxuICAgICAgcmV0dXJuIHRoaXMudXJsSGVscGVyLmdldEhhc2hGcmFnbWVudFBhcmFtcygpO1xyXG4gICAgfVxyXG5cclxuICAgIC8vIG5vcm1hbGl6ZSBxdWVyeSBzdHJpbmdcclxuICAgIGlmIChxdWVyeVN0cmluZy5jaGFyQXQoMCkgPT09ICc/Jykge1xyXG4gICAgICBxdWVyeVN0cmluZyA9IHF1ZXJ5U3RyaW5nLnN1YnN0cigxKTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gdGhpcy51cmxIZWxwZXIucGFyc2VRdWVyeVN0cmluZyhxdWVyeVN0cmluZyk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBHZXQgdG9rZW4gdXNpbmcgYW4gaW50ZXJtZWRpYXRlIGNvZGUuIFdvcmtzIGZvciB0aGUgQXV0aG9yaXphdGlvbiBDb2RlIGZsb3cuXHJcbiAgICovXHJcbiAgcHJpdmF0ZSBnZXRUb2tlbkZyb21Db2RlKFxyXG4gICAgY29kZTogc3RyaW5nLFxyXG4gICAgb3B0aW9uczogTG9naW5PcHRpb25zXHJcbiAgKTogUHJvbWlzZTxvYmplY3Q+IHtcclxuICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcygpXHJcbiAgICAgIC5zZXQoJ2dyYW50X3R5cGUnLCAnYXV0aG9yaXphdGlvbl9jb2RlJylcclxuICAgICAgLnNldCgnY29kZScsIGNvZGUpXHJcbiAgICAgIC5zZXQoJ3JlZGlyZWN0X3VyaScsIG9wdGlvbnMuY3VzdG9tUmVkaXJlY3RVcmkgfHwgdGhpcy5yZWRpcmVjdFVyaSk7XHJcblxyXG4gICAgaWYgKCF0aGlzLmRpc2FibGVQS0NFKSB7XHJcbiAgICAgIGxldCBQS0NFVmVyaWZpZXI7XHJcblxyXG4gICAgICBpZiAoXHJcbiAgICAgICAgdGhpcy5zYXZlTm9uY2VzSW5Mb2NhbFN0b3JhZ2UgJiZcclxuICAgICAgICB0eXBlb2Ygd2luZG93Wydsb2NhbFN0b3JhZ2UnXSAhPT0gJ3VuZGVmaW5lZCdcclxuICAgICAgKSB7XHJcbiAgICAgICAgUEtDRVZlcmlmaWVyID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ1BLQ0VfdmVyaWZpZXInKTtcclxuICAgICAgfSBlbHNlIHtcclxuICAgICAgICBQS0NFVmVyaWZpZXIgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ1BLQ0VfdmVyaWZpZXInKTtcclxuICAgICAgfVxyXG5cclxuICAgICAgaWYgKCFQS0NFVmVyaWZpZXIpIHtcclxuICAgICAgICBjb25zb2xlLndhcm4oJ05vIFBLQ0UgdmVyaWZpZXIgZm91bmQgaW4gb2F1dGggc3RvcmFnZSEnKTtcclxuICAgICAgfSBlbHNlIHtcclxuICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdjb2RlX3ZlcmlmaWVyJywgUEtDRVZlcmlmaWVyKTtcclxuICAgICAgfVxyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiB0aGlzLmZldGNoQW5kUHJvY2Vzc1Rva2VuKHBhcmFtcyk7XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIGZldGNoQW5kUHJvY2Vzc1Rva2VuKHBhcmFtczogSHR0cFBhcmFtcyk6IFByb21pc2U8VG9rZW5SZXNwb25zZT4ge1xyXG4gICAgdGhpcy5hc3NlcnRVcmxOb3ROdWxsQW5kQ29ycmVjdFByb3RvY29sKFxyXG4gICAgICB0aGlzLnRva2VuRW5kcG9pbnQsXHJcbiAgICAgICd0b2tlbkVuZHBvaW50J1xyXG4gICAgKTtcclxuICAgIGxldCBoZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKCkuc2V0KFxyXG4gICAgICAnQ29udGVudC1UeXBlJyxcclxuICAgICAgJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCdcclxuICAgICk7XHJcblxyXG4gICAgaWYgKHRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xyXG4gICAgICBjb25zdCBoZWFkZXIgPSBidG9hKGAke3RoaXMuY2xpZW50SWR9OiR7dGhpcy5kdW1teUNsaWVudFNlY3JldH1gKTtcclxuICAgICAgaGVhZGVycyA9IGhlYWRlcnMuc2V0KCdBdXRob3JpemF0aW9uJywgJ0Jhc2ljICcgKyBoZWFkZXIpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XHJcbiAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9pZCcsIHRoaXMuY2xpZW50SWQpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoICYmIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpIHtcclxuICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X3NlY3JldCcsIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiBuZXcgUHJvbWlzZSgocmVzb2x2ZSwgcmVqZWN0KSA9PiB7XHJcbiAgICAgIGlmICh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSB7XHJcbiAgICAgICAgZm9yIChsZXQga2V5IG9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpKSB7XHJcbiAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KGtleSwgdGhpcy5jdXN0b21RdWVyeVBhcmFtc1trZXldKTtcclxuICAgICAgICB9XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIHRoaXMuaHR0cFxyXG4gICAgICAgIC5wb3N0PFRva2VuUmVzcG9uc2U+KHRoaXMudG9rZW5FbmRwb2ludCwgcGFyYW1zLCB7IGhlYWRlcnMgfSlcclxuICAgICAgICAuc3Vic2NyaWJlKFxyXG4gICAgICAgICAgdG9rZW5SZXNwb25zZSA9PiB7XHJcbiAgICAgICAgICAgIHRoaXMuZGVidWcoJ3JlZnJlc2ggdG9rZW5SZXNwb25zZScsIHRva2VuUmVzcG9uc2UpO1xyXG4gICAgICAgICAgICB0aGlzLnN0b3JlQWNjZXNzVG9rZW5SZXNwb25zZShcclxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmFjY2Vzc190b2tlbixcclxuICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLnJlZnJlc2hfdG9rZW4sXHJcbiAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5leHBpcmVzX2luIHx8XHJcbiAgICAgICAgICAgICAgICB0aGlzLmZhbGxiYWNrQWNjZXNzVG9rZW5FeHBpcmF0aW9uVGltZUluU2VjLFxyXG4gICAgICAgICAgICAgIHRva2VuUmVzcG9uc2Uuc2NvcGUsXHJcbiAgICAgICAgICAgICAgdGhpcy5leHRyYWN0UmVjb2duaXplZEN1c3RvbVBhcmFtZXRlcnModG9rZW5SZXNwb25zZSlcclxuICAgICAgICAgICAgKTtcclxuXHJcbiAgICAgICAgICAgIGlmICh0aGlzLm9pZGMgJiYgdG9rZW5SZXNwb25zZS5pZF90b2tlbikge1xyXG4gICAgICAgICAgICAgIHRoaXMucHJvY2Vzc0lkVG9rZW4oXHJcbiAgICAgICAgICAgICAgICB0b2tlblJlc3BvbnNlLmlkX3Rva2VuLFxyXG4gICAgICAgICAgICAgICAgdG9rZW5SZXNwb25zZS5hY2Nlc3NfdG9rZW5cclxuICAgICAgICAgICAgICApXHJcbiAgICAgICAgICAgICAgICAudGhlbihyZXN1bHQgPT4ge1xyXG4gICAgICAgICAgICAgICAgICB0aGlzLnN0b3JlSWRUb2tlbihyZXN1bHQpO1xyXG5cclxuICAgICAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXHJcbiAgICAgICAgICAgICAgICAgICAgbmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpXHJcbiAgICAgICAgICAgICAgICAgICk7XHJcbiAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxyXG4gICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aFN1Y2Nlc3NFdmVudCgndG9rZW5fcmVmcmVzaGVkJylcclxuICAgICAgICAgICAgICAgICAgKTtcclxuXHJcbiAgICAgICAgICAgICAgICAgIHJlc29sdmUodG9rZW5SZXNwb25zZSk7XHJcbiAgICAgICAgICAgICAgICB9KVxyXG4gICAgICAgICAgICAgICAgLmNhdGNoKHJlYXNvbiA9PiB7XHJcbiAgICAgICAgICAgICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KFxyXG4gICAgICAgICAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX3ZhbGlkYXRpb25fZXJyb3InLCByZWFzb24pXHJcbiAgICAgICAgICAgICAgICAgICk7XHJcbiAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ0Vycm9yIHZhbGlkYXRpbmcgdG9rZW5zJyk7XHJcbiAgICAgICAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IocmVhc29uKTtcclxuXHJcbiAgICAgICAgICAgICAgICAgIHJlamVjdChyZWFzb24pO1xyXG4gICAgICAgICAgICAgICAgfSk7XHJcbiAgICAgICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQobmV3IE9BdXRoU3VjY2Vzc0V2ZW50KCd0b2tlbl9yZWNlaXZlZCcpKTtcclxuICAgICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlZnJlc2hlZCcpKTtcclxuXHJcbiAgICAgICAgICAgICAgcmVzb2x2ZSh0b2tlblJlc3BvbnNlKTtcclxuICAgICAgICAgICAgfVxyXG4gICAgICAgICAgfSxcclxuICAgICAgICAgIGVyciA9PiB7XHJcbiAgICAgICAgICAgIGNvbnNvbGUuZXJyb3IoJ0Vycm9yIGdldHRpbmcgdG9rZW4nLCBlcnIpO1xyXG4gICAgICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChcclxuICAgICAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9yZWZyZXNoX2Vycm9yJywgZXJyKVxyXG4gICAgICAgICAgICApO1xyXG4gICAgICAgICAgICByZWplY3QoZXJyKTtcclxuICAgICAgICAgIH1cclxuICAgICAgICApO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBDaGVja3Mgd2hldGhlciB0aGVyZSBhcmUgdG9rZW5zIGluIHRoZSBoYXNoIGZyYWdtZW50XHJcbiAgICogYXMgYSByZXN1bHQgb2YgdGhlIGltcGxpY2l0IGZsb3cuIFRoZXNlIHRva2VucyBhcmVcclxuICAgKiBwYXJzZWQsIHZhbGlkYXRlZCBhbmQgdXNlZCB0byBzaWduIHRoZSB1c2VyIGluIHRvIHRoZVxyXG4gICAqIGN1cnJlbnQgY2xpZW50LlxyXG4gICAqXHJcbiAgICogQHBhcmFtIG9wdGlvbnMgT3B0aW9uYWwgb3B0aW9ucy5cclxuICAgKi9cclxuICBwdWJsaWMgdHJ5TG9naW5JbXBsaWNpdEZsb3cob3B0aW9uczogTG9naW5PcHRpb25zID0gbnVsbCk6IFByb21pc2U8Ym9vbGVhbj4ge1xyXG4gICAgb3B0aW9ucyA9IG9wdGlvbnMgfHwge307XHJcblxyXG4gICAgbGV0IHBhcnRzOiBvYmplY3Q7XHJcblxyXG4gICAgaWYgKG9wdGlvbnMuY3VzdG9tSGFzaEZyYWdtZW50KSB7XHJcbiAgICAgIHBhcnRzID0gdGhpcy51cmxIZWxwZXIuZ2V0SGFzaEZyYWdtZW50UGFyYW1zKG9wdGlvbnMuY3VzdG9tSGFzaEZyYWdtZW50KTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIHBhcnRzID0gdGhpcy51cmxIZWxwZXIuZ2V0SGFzaEZyYWdtZW50UGFyYW1zKCk7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy5kZWJ1ZygncGFyc2VkIHVybCcsIHBhcnRzKTtcclxuXHJcbiAgICBjb25zdCBzdGF0ZSA9IHBhcnRzWydzdGF0ZSddO1xyXG5cclxuICAgIGxldCBbbm9uY2VJblN0YXRlLCB1c2VyU3RhdGVdID0gdGhpcy5wYXJzZVN0YXRlKHN0YXRlKTtcclxuICAgIHRoaXMuc3RhdGUgPSB1c2VyU3RhdGU7XHJcblxyXG4gICAgaWYgKHBhcnRzWydlcnJvciddKSB7XHJcbiAgICAgIHRoaXMuZGVidWcoJ2Vycm9yIHRyeWluZyB0byBsb2dpbicpO1xyXG4gICAgICB0aGlzLmhhbmRsZUxvZ2luRXJyb3Iob3B0aW9ucywgcGFydHMpO1xyXG4gICAgICBjb25zdCBlcnIgPSBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl9lcnJvcicsIHt9LCBwYXJ0cyk7XHJcbiAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGVycik7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgfVxyXG5cclxuICAgIGNvbnN0IGFjY2Vzc1Rva2VuID0gcGFydHNbJ2FjY2Vzc190b2tlbiddO1xyXG4gICAgY29uc3QgaWRUb2tlbiA9IHBhcnRzWydpZF90b2tlbiddO1xyXG4gICAgY29uc3Qgc2Vzc2lvblN0YXRlID0gcGFydHNbJ3Nlc3Npb25fc3RhdGUnXTtcclxuICAgIGNvbnN0IGdyYW50ZWRTY29wZXMgPSBwYXJ0c1snc2NvcGUnXTtcclxuXHJcbiAgICBpZiAoIXRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICF0aGlzLm9pZGMpIHtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KFxyXG4gICAgICAgICdFaXRoZXIgcmVxdWVzdEFjY2Vzc1Rva2VuIG9yIG9pZGMgKG9yIGJvdGgpIG11c3QgYmUgdHJ1ZS4nXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICFhY2Nlc3NUb2tlbikge1xyXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZXNvbHZlKGZhbHNlKTtcclxuICAgIH1cclxuICAgIGlmICh0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhb3B0aW9ucy5kaXNhYmxlT0F1dGgyU3RhdGVDaGVjayAmJiAhc3RhdGUpIHtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShmYWxzZSk7XHJcbiAgICB9XHJcbiAgICBpZiAodGhpcy5vaWRjICYmICFpZFRva2VuKSB7XHJcbiAgICAgIHJldHVybiBQcm9taXNlLnJlc29sdmUoZmFsc2UpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICh0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkICYmICFzZXNzaW9uU3RhdGUpIHtcclxuICAgICAgdGhpcy5sb2dnZXIud2FybihcclxuICAgICAgICAnc2Vzc2lvbiBjaGVja3MgKFNlc3Npb24gU3RhdHVzIENoYW5nZSBOb3RpZmljYXRpb24pICcgK1xyXG4gICAgICAgICAgJ3dlcmUgYWN0aXZhdGVkIGluIHRoZSBjb25maWd1cmF0aW9uIGJ1dCB0aGUgaWRfdG9rZW4gJyArXHJcbiAgICAgICAgICAnZG9lcyBub3QgY29udGFpbiBhIHNlc3Npb25fc3RhdGUgY2xhaW0nXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICFvcHRpb25zLmRpc2FibGVPQXV0aDJTdGF0ZUNoZWNrKSB7XHJcbiAgICAgIGNvbnN0IHN1Y2Nlc3MgPSB0aGlzLnZhbGlkYXRlTm9uY2Uobm9uY2VJblN0YXRlKTtcclxuXHJcbiAgICAgIGlmICghc3VjY2Vzcykge1xyXG4gICAgICAgIGNvbnN0IGV2ZW50ID0gbmV3IE9BdXRoRXJyb3JFdmVudCgnaW52YWxpZF9ub25jZV9pbl9zdGF0ZScsIG51bGwpO1xyXG4gICAgICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KGV2ZW50KTtcclxuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXZlbnQpO1xyXG4gICAgICB9XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuKSB7XHJcbiAgICAgIHRoaXMuc3RvcmVBY2Nlc3NUb2tlblJlc3BvbnNlKFxyXG4gICAgICAgIGFjY2Vzc1Rva2VuLFxyXG4gICAgICAgIG51bGwsXHJcbiAgICAgICAgcGFydHNbJ2V4cGlyZXNfaW4nXSB8fCB0aGlzLmZhbGxiYWNrQWNjZXNzVG9rZW5FeHBpcmF0aW9uVGltZUluU2VjLFxyXG4gICAgICAgIGdyYW50ZWRTY29wZXNcclxuICAgICAgKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIXRoaXMub2lkYykge1xyXG4gICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xyXG4gICAgICBpZiAodGhpcy5jbGVhckhhc2hBZnRlckxvZ2luICYmICFvcHRpb25zLnByZXZlbnRDbGVhckhhc2hBZnRlckxvZ2luKSB7XHJcbiAgICAgICAgbG9jYXRpb24uaGFzaCA9ICcnO1xyXG4gICAgICB9XHJcblxyXG4gICAgICB0aGlzLmNhbGxPblRva2VuUmVjZWl2ZWRJZkV4aXN0cyhvcHRpb25zKTtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZSh0cnVlKTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gdGhpcy5wcm9jZXNzSWRUb2tlbihpZFRva2VuLCBhY2Nlc3NUb2tlbilcclxuICAgICAgLnRoZW4ocmVzdWx0ID0+IHtcclxuICAgICAgICBpZiAob3B0aW9ucy52YWxpZGF0aW9uSGFuZGxlcikge1xyXG4gICAgICAgICAgcmV0dXJuIG9wdGlvbnNcclxuICAgICAgICAgICAgLnZhbGlkYXRpb25IYW5kbGVyKHtcclxuICAgICAgICAgICAgICBhY2Nlc3NUb2tlbjogYWNjZXNzVG9rZW4sXHJcbiAgICAgICAgICAgICAgaWRDbGFpbXM6IHJlc3VsdC5pZFRva2VuQ2xhaW1zLFxyXG4gICAgICAgICAgICAgIGlkVG9rZW46IHJlc3VsdC5pZFRva2VuLFxyXG4gICAgICAgICAgICAgIHN0YXRlOiBzdGF0ZVxyXG4gICAgICAgICAgICB9KVxyXG4gICAgICAgICAgICAudGhlbihfID0+IHJlc3VsdCk7XHJcbiAgICAgICAgfVxyXG4gICAgICAgIHJldHVybiByZXN1bHQ7XHJcbiAgICAgIH0pXHJcbiAgICAgIC50aGVuKHJlc3VsdCA9PiB7XHJcbiAgICAgICAgdGhpcy5zdG9yZUlkVG9rZW4ocmVzdWx0KTtcclxuICAgICAgICB0aGlzLnN0b3JlU2Vzc2lvblN0YXRlKHNlc3Npb25TdGF0ZSk7XHJcbiAgICAgICAgaWYgKHRoaXMuY2xlYXJIYXNoQWZ0ZXJMb2dpbiAmJiAhb3B0aW9ucy5wcmV2ZW50Q2xlYXJIYXNoQWZ0ZXJMb2dpbikge1xyXG4gICAgICAgICAgbG9jYXRpb24uaGFzaCA9ICcnO1xyXG4gICAgICAgIH1cclxuICAgICAgICB0aGlzLmV2ZW50c1N1YmplY3QubmV4dChuZXcgT0F1dGhTdWNjZXNzRXZlbnQoJ3Rva2VuX3JlY2VpdmVkJykpO1xyXG4gICAgICAgIHRoaXMuY2FsbE9uVG9rZW5SZWNlaXZlZElmRXhpc3RzKG9wdGlvbnMpO1xyXG4gICAgICAgIHRoaXMuaW5JbXBsaWNpdEZsb3cgPSBmYWxzZTtcclxuICAgICAgICByZXR1cm4gdHJ1ZTtcclxuICAgICAgfSlcclxuICAgICAgLmNhdGNoKHJlYXNvbiA9PiB7XHJcbiAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXHJcbiAgICAgICAgICBuZXcgT0F1dGhFcnJvckV2ZW50KCd0b2tlbl92YWxpZGF0aW9uX2Vycm9yJywgcmVhc29uKVxyXG4gICAgICAgICk7XHJcbiAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IoJ0Vycm9yIHZhbGlkYXRpbmcgdG9rZW5zJyk7XHJcbiAgICAgICAgdGhpcy5sb2dnZXIuZXJyb3IocmVhc29uKTtcclxuICAgICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QocmVhc29uKTtcclxuICAgICAgfSk7XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIHBhcnNlU3RhdGUoc3RhdGU6IHN0cmluZyk6IFtzdHJpbmcsIHN0cmluZ10ge1xyXG4gICAgbGV0IG5vbmNlID0gc3RhdGU7XHJcbiAgICBsZXQgdXNlclN0YXRlID0gJyc7XHJcblxyXG4gICAgaWYgKHN0YXRlKSB7XHJcbiAgICAgIGNvbnN0IGlkeCA9IHN0YXRlLmluZGV4T2YodGhpcy5jb25maWcubm9uY2VTdGF0ZVNlcGFyYXRvcik7XHJcbiAgICAgIGlmIChpZHggPiAtMSkge1xyXG4gICAgICAgIG5vbmNlID0gc3RhdGUuc3Vic3RyKDAsIGlkeCk7XHJcbiAgICAgICAgdXNlclN0YXRlID0gc3RhdGUuc3Vic3RyKGlkeCArIHRoaXMuY29uZmlnLm5vbmNlU3RhdGVTZXBhcmF0b3IubGVuZ3RoKTtcclxuICAgICAgfVxyXG4gICAgfVxyXG4gICAgcmV0dXJuIFtub25jZSwgdXNlclN0YXRlXTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCB2YWxpZGF0ZU5vbmNlKG5vbmNlSW5TdGF0ZTogc3RyaW5nKTogYm9vbGVhbiB7XHJcbiAgICBsZXQgc2F2ZWROb25jZTtcclxuXHJcbiAgICBpZiAoXHJcbiAgICAgIHRoaXMuc2F2ZU5vbmNlc0luTG9jYWxTdG9yYWdlICYmXHJcbiAgICAgIHR5cGVvZiB3aW5kb3dbJ2xvY2FsU3RvcmFnZSddICE9PSAndW5kZWZpbmVkJ1xyXG4gICAgKSB7XHJcbiAgICAgIHNhdmVkTm9uY2UgPSBsb2NhbFN0b3JhZ2UuZ2V0SXRlbSgnbm9uY2UnKTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIHNhdmVkTm9uY2UgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ25vbmNlJyk7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKHNhdmVkTm9uY2UgIT09IG5vbmNlSW5TdGF0ZSkge1xyXG4gICAgICBjb25zdCBlcnIgPSAnVmFsaWRhdGluZyBhY2Nlc3NfdG9rZW4gZmFpbGVkLCB3cm9uZyBzdGF0ZS9ub25jZS4nO1xyXG4gICAgICBjb25zb2xlLmVycm9yKGVyciwgc2F2ZWROb25jZSwgbm9uY2VJblN0YXRlKTtcclxuICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgfVxyXG4gICAgcmV0dXJuIHRydWU7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgc3RvcmVJZFRva2VuKGlkVG9rZW46IFBhcnNlZElkVG9rZW4pOiB2b2lkIHtcclxuICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnaWRfdG9rZW4nLCBpZFRva2VuLmlkVG9rZW4pO1xyXG4gICAgdGhpcy5fc3RvcmFnZS5zZXRJdGVtKCdpZF90b2tlbl9jbGFpbXNfb2JqJywgaWRUb2tlbi5pZFRva2VuQ2xhaW1zSnNvbik7XHJcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnLCAnJyArIGlkVG9rZW4uaWRUb2tlbkV4cGlyZXNBdCk7XHJcbiAgICB0aGlzLl9zdG9yYWdlLnNldEl0ZW0oJ2lkX3Rva2VuX3N0b3JlZF9hdCcsICcnICsgRGF0ZS5ub3coKSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgc3RvcmVTZXNzaW9uU3RhdGUoc2Vzc2lvblN0YXRlOiBzdHJpbmcpOiB2b2lkIHtcclxuICAgIHRoaXMuX3N0b3JhZ2Uuc2V0SXRlbSgnc2Vzc2lvbl9zdGF0ZScsIHNlc3Npb25TdGF0ZSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgZ2V0U2Vzc2lvblN0YXRlKCk6IHN0cmluZyB7XHJcbiAgICByZXR1cm4gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdzZXNzaW9uX3N0YXRlJyk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgaGFuZGxlTG9naW5FcnJvcihvcHRpb25zOiBMb2dpbk9wdGlvbnMsIHBhcnRzOiBvYmplY3QpOiB2b2lkIHtcclxuICAgIGlmIChvcHRpb25zLm9uTG9naW5FcnJvcikge1xyXG4gICAgICBvcHRpb25zLm9uTG9naW5FcnJvcihwYXJ0cyk7XHJcbiAgICB9XHJcbiAgICBpZiAodGhpcy5jbGVhckhhc2hBZnRlckxvZ2luICYmICFvcHRpb25zLnByZXZlbnRDbGVhckhhc2hBZnRlckxvZ2luKSB7XHJcbiAgICAgIGxvY2F0aW9uLmhhc2ggPSAnJztcclxuICAgIH1cclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIEBpZ25vcmVcclxuICAgKi9cclxuICBwdWJsaWMgcHJvY2Vzc0lkVG9rZW4oXHJcbiAgICBpZFRva2VuOiBzdHJpbmcsXHJcbiAgICBhY2Nlc3NUb2tlbjogc3RyaW5nLFxyXG4gICAgc2tpcE5vbmNlQ2hlY2sgPSBmYWxzZVxyXG4gICk6IFByb21pc2U8UGFyc2VkSWRUb2tlbj4ge1xyXG4gICAgY29uc3QgdG9rZW5QYXJ0cyA9IGlkVG9rZW4uc3BsaXQoJy4nKTtcclxuICAgIGNvbnN0IGhlYWRlckJhc2U2NCA9IHRoaXMucGFkQmFzZTY0KHRva2VuUGFydHNbMF0pO1xyXG4gICAgY29uc3QgaGVhZGVySnNvbiA9IGI2NERlY29kZVVuaWNvZGUoaGVhZGVyQmFzZTY0KTtcclxuICAgIGNvbnN0IGhlYWRlciA9IEpTT04ucGFyc2UoaGVhZGVySnNvbik7XHJcbiAgICBjb25zdCBjbGFpbXNCYXNlNjQgPSB0aGlzLnBhZEJhc2U2NCh0b2tlblBhcnRzWzFdKTtcclxuICAgIGNvbnN0IGNsYWltc0pzb24gPSBiNjREZWNvZGVVbmljb2RlKGNsYWltc0Jhc2U2NCk7XHJcbiAgICBjb25zdCBjbGFpbXMgPSBKU09OLnBhcnNlKGNsYWltc0pzb24pO1xyXG5cclxuICAgIGxldCBzYXZlZE5vbmNlO1xyXG4gICAgaWYgKFxyXG4gICAgICB0aGlzLnNhdmVOb25jZXNJbkxvY2FsU3RvcmFnZSAmJlxyXG4gICAgICB0eXBlb2Ygd2luZG93Wydsb2NhbFN0b3JhZ2UnXSAhPT0gJ3VuZGVmaW5lZCdcclxuICAgICkge1xyXG4gICAgICBzYXZlZE5vbmNlID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0oJ25vbmNlJyk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICBzYXZlZE5vbmNlID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdub25jZScpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmIChBcnJheS5pc0FycmF5KGNsYWltcy5hdWQpKSB7XHJcbiAgICAgIGlmIChjbGFpbXMuYXVkLmV2ZXJ5KHYgPT4gdiAhPT0gdGhpcy5jbGllbnRJZCkpIHtcclxuICAgICAgICBjb25zdCBlcnIgPSAnV3JvbmcgYXVkaWVuY2U6ICcgKyBjbGFpbXMuYXVkLmpvaW4oJywnKTtcclxuICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XHJcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XHJcbiAgICAgIH1cclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIGlmIChjbGFpbXMuYXVkICE9PSB0aGlzLmNsaWVudElkKSB7XHJcbiAgICAgICAgY29uc3QgZXJyID0gJ1dyb25nIGF1ZGllbmNlOiAnICsgY2xhaW1zLmF1ZDtcclxuICAgICAgICB0aGlzLmxvZ2dlci53YXJuKGVycik7XHJcbiAgICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XHJcbiAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICBpZiAoIWNsYWltcy5zdWIpIHtcclxuICAgICAgY29uc3QgZXJyID0gJ05vIHN1YiBjbGFpbSBpbiBpZF90b2tlbic7XHJcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XHJcbiAgICB9XHJcblxyXG4gICAgLyogRm9yIG5vdywgd2Ugb25seSBjaGVjayB3aGV0aGVyIHRoZSBzdWIgYWdhaW5zdFxyXG4gICAgICogc2lsZW50UmVmcmVzaFN1YmplY3Qgd2hlbiBzZXNzaW9uQ2hlY2tzRW5hYmxlZCBpcyBvblxyXG4gICAgICogV2Ugd2lsbCByZWNvbnNpZGVyIGluIGEgbGF0ZXIgdmVyc2lvbiB0byBkbyB0aGlzXHJcbiAgICAgKiBpbiBldmVyeSBvdGhlciBjYXNlIHRvby5cclxuICAgICAqL1xyXG4gICAgaWYgKFxyXG4gICAgICB0aGlzLnNlc3Npb25DaGVja3NFbmFibGVkICYmXHJcbiAgICAgIHRoaXMuc2lsZW50UmVmcmVzaFN1YmplY3QgJiZcclxuICAgICAgdGhpcy5zaWxlbnRSZWZyZXNoU3ViamVjdCAhPT0gY2xhaW1zWydzdWInXVxyXG4gICAgKSB7XHJcbiAgICAgIGNvbnN0IGVyciA9XHJcbiAgICAgICAgJ0FmdGVyIHJlZnJlc2hpbmcsIHdlIGdvdCBhbiBpZF90b2tlbiBmb3IgYW5vdGhlciB1c2VyIChzdWIpLiAnICtcclxuICAgICAgICBgRXhwZWN0ZWQgc3ViOiAke3RoaXMuc2lsZW50UmVmcmVzaFN1YmplY3R9LCByZWNlaXZlZCBzdWI6ICR7Y2xhaW1zWydzdWInXX1gO1xyXG5cclxuICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xyXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIWNsYWltcy5pYXQpIHtcclxuICAgICAgY29uc3QgZXJyID0gJ05vIGlhdCBjbGFpbSBpbiBpZF90b2tlbic7XHJcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCF0aGlzLnNraXBJc3N1ZXJDaGVjayAmJiBjbGFpbXMuaXNzICE9PSB0aGlzLmlzc3Vlcikge1xyXG4gICAgICBjb25zdCBlcnIgPSAnV3JvbmcgaXNzdWVyOiAnICsgY2xhaW1zLmlzcztcclxuICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xyXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcclxuICAgIH1cclxuXHJcbiAgICBpZiAoIXNraXBOb25jZUNoZWNrICYmIGNsYWltcy5ub25jZSAhPT0gc2F2ZWROb25jZSkge1xyXG4gICAgICBjb25zdCBlcnIgPSAnV3Jvbmcgbm9uY2U6ICcgKyBjbGFpbXMubm9uY2U7XHJcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XHJcbiAgICB9XHJcbiAgICAvLyBhdF9oYXNoIGlzIG5vdCBhcHBsaWNhYmxlIHRvIGF1dGhvcml6YXRpb24gY29kZSBmbG93XHJcbiAgICAvLyBhZGRyZXNzaW5nIGh0dHBzOi8vZ2l0aHViLmNvbS9tYW5mcmVkc3RleWVyL2FuZ3VsYXItb2F1dGgyLW9pZGMvaXNzdWVzLzY2MVxyXG4gICAgLy8gaS5lLiBCYXNlZCBvbiBzcGVjIHRoZSBhdF9oYXNoIGNoZWNrIGlzIG9ubHkgdHJ1ZSBmb3IgaW1wbGljaXQgY29kZSBmbG93IG9uIFBpbmcgRmVkZXJhdGVcclxuICAgIC8vIGh0dHBzOi8vd3d3LnBpbmdpZGVudGl0eS5jb20vZGV2ZWxvcGVyL2VuL3Jlc291cmNlcy9vcGVuaWQtY29ubmVjdC1kZXZlbG9wZXJzLWd1aWRlLmh0bWxcclxuICAgIGlmIChcclxuICAgICAgdGhpcy5oYXNPd25Qcm9wZXJ0eSgncmVzcG9uc2VUeXBlJykgJiZcclxuICAgICAgKHRoaXMucmVzcG9uc2VUeXBlID09PSAnY29kZScgfHwgdGhpcy5yZXNwb25zZVR5cGUgPT09ICdpZF90b2tlbicpXHJcbiAgICApIHtcclxuICAgICAgdGhpcy5kaXNhYmxlQXRIYXNoQ2hlY2sgPSB0cnVlO1xyXG4gICAgfVxyXG4gICAgaWYgKFxyXG4gICAgICAhdGhpcy5kaXNhYmxlQXRIYXNoQ2hlY2sgJiZcclxuICAgICAgdGhpcy5yZXF1ZXN0QWNjZXNzVG9rZW4gJiZcclxuICAgICAgIWNsYWltc1snYXRfaGFzaCddXHJcbiAgICApIHtcclxuICAgICAgY29uc3QgZXJyID0gJ0FuIGF0X2hhc2ggaXMgbmVlZGVkISc7XHJcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oZXJyKTtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVqZWN0KGVycik7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3Qgbm93ID0gRGF0ZS5ub3coKTtcclxuICAgIGNvbnN0IGlzc3VlZEF0TVNlYyA9IGNsYWltcy5pYXQgKiAxMDAwO1xyXG4gICAgY29uc3QgZXhwaXJlc0F0TVNlYyA9IGNsYWltcy5leHAgKiAxMDAwO1xyXG4gICAgY29uc3QgY2xvY2tTa2V3SW5NU2VjID0gKHRoaXMuY2xvY2tTa2V3SW5TZWMgfHwgNjAwKSAqIDEwMDA7XHJcblxyXG4gICAgaWYgKFxyXG4gICAgICBpc3N1ZWRBdE1TZWMgLSBjbG9ja1NrZXdJbk1TZWMgPj0gbm93IHx8XHJcbiAgICAgIGV4cGlyZXNBdE1TZWMgKyBjbG9ja1NrZXdJbk1TZWMgPD0gbm93XHJcbiAgICApIHtcclxuICAgICAgY29uc3QgZXJyID0gJ1Rva2VuIGhhcyBleHBpcmVkJztcclxuICAgICAgY29uc29sZS5lcnJvcihlcnIpO1xyXG4gICAgICBjb25zb2xlLmVycm9yKHtcclxuICAgICAgICBub3c6IG5vdyxcclxuICAgICAgICBpc3N1ZWRBdE1TZWM6IGlzc3VlZEF0TVNlYyxcclxuICAgICAgICBleHBpcmVzQXRNU2VjOiBleHBpcmVzQXRNU2VjXHJcbiAgICAgIH0pO1xyXG4gICAgICByZXR1cm4gUHJvbWlzZS5yZWplY3QoZXJyKTtcclxuICAgIH1cclxuXHJcbiAgICBjb25zdCB2YWxpZGF0aW9uUGFyYW1zOiBWYWxpZGF0aW9uUGFyYW1zID0ge1xyXG4gICAgICBhY2Nlc3NUb2tlbjogYWNjZXNzVG9rZW4sXHJcbiAgICAgIGlkVG9rZW46IGlkVG9rZW4sXHJcbiAgICAgIGp3a3M6IHRoaXMuandrcyxcclxuICAgICAgaWRUb2tlbkNsYWltczogY2xhaW1zLFxyXG4gICAgICBpZFRva2VuSGVhZGVyOiBoZWFkZXIsXHJcbiAgICAgIGxvYWRLZXlzOiAoKSA9PiB0aGlzLmxvYWRKd2tzKClcclxuICAgIH07XHJcblxyXG4gICAgaWYgKHRoaXMuZGlzYWJsZUF0SGFzaENoZWNrKSB7XHJcbiAgICAgIHJldHVybiB0aGlzLmNoZWNrU2lnbmF0dXJlKHZhbGlkYXRpb25QYXJhbXMpLnRoZW4oXyA9PiB7XHJcbiAgICAgICAgY29uc3QgcmVzdWx0OiBQYXJzZWRJZFRva2VuID0ge1xyXG4gICAgICAgICAgaWRUb2tlbjogaWRUb2tlbixcclxuICAgICAgICAgIGlkVG9rZW5DbGFpbXM6IGNsYWltcyxcclxuICAgICAgICAgIGlkVG9rZW5DbGFpbXNKc29uOiBjbGFpbXNKc29uLFxyXG4gICAgICAgICAgaWRUb2tlbkhlYWRlcjogaGVhZGVyLFxyXG4gICAgICAgICAgaWRUb2tlbkhlYWRlckpzb246IGhlYWRlckpzb24sXHJcbiAgICAgICAgICBpZFRva2VuRXhwaXJlc0F0OiBleHBpcmVzQXRNU2VjXHJcbiAgICAgICAgfTtcclxuICAgICAgICByZXR1cm4gcmVzdWx0O1xyXG4gICAgICB9KTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gdGhpcy5jaGVja0F0SGFzaCh2YWxpZGF0aW9uUGFyYW1zKS50aGVuKGF0SGFzaFZhbGlkID0+IHtcclxuICAgICAgaWYgKCF0aGlzLmRpc2FibGVBdEhhc2hDaGVjayAmJiB0aGlzLnJlcXVlc3RBY2Nlc3NUb2tlbiAmJiAhYXRIYXNoVmFsaWQpIHtcclxuICAgICAgICBjb25zdCBlcnIgPSAnV3JvbmcgYXRfaGFzaCc7XHJcbiAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xyXG4gICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgICB9XHJcblxyXG4gICAgICByZXR1cm4gdGhpcy5jaGVja1NpZ25hdHVyZSh2YWxpZGF0aW9uUGFyYW1zKS50aGVuKF8gPT4ge1xyXG4gICAgICAgIGNvbnN0IGF0SGFzaENoZWNrRW5hYmxlZCA9ICF0aGlzLmRpc2FibGVBdEhhc2hDaGVjaztcclxuICAgICAgICBjb25zdCByZXN1bHQ6IFBhcnNlZElkVG9rZW4gPSB7XHJcbiAgICAgICAgICBpZFRva2VuOiBpZFRva2VuLFxyXG4gICAgICAgICAgaWRUb2tlbkNsYWltczogY2xhaW1zLFxyXG4gICAgICAgICAgaWRUb2tlbkNsYWltc0pzb246IGNsYWltc0pzb24sXHJcbiAgICAgICAgICBpZFRva2VuSGVhZGVyOiBoZWFkZXIsXHJcbiAgICAgICAgICBpZFRva2VuSGVhZGVySnNvbjogaGVhZGVySnNvbixcclxuICAgICAgICAgIGlkVG9rZW5FeHBpcmVzQXQ6IGV4cGlyZXNBdE1TZWNcclxuICAgICAgICB9O1xyXG4gICAgICAgIGlmIChhdEhhc2hDaGVja0VuYWJsZWQpIHtcclxuICAgICAgICAgIHJldHVybiB0aGlzLmNoZWNrQXRIYXNoKHZhbGlkYXRpb25QYXJhbXMpLnRoZW4oYXRIYXNoVmFsaWQxID0+IHtcclxuICAgICAgICAgICAgaWYgKHRoaXMucmVxdWVzdEFjY2Vzc1Rva2VuICYmICFhdEhhc2hWYWxpZDEpIHtcclxuICAgICAgICAgICAgICBjb25zdCBlcnIgPSAnV3JvbmcgYXRfaGFzaCc7XHJcbiAgICAgICAgICAgICAgdGhpcy5sb2dnZXIud2FybihlcnIpO1xyXG4gICAgICAgICAgICAgIHJldHVybiBQcm9taXNlLnJlamVjdChlcnIpO1xyXG4gICAgICAgICAgICB9IGVsc2Uge1xyXG4gICAgICAgICAgICAgIHJldHVybiByZXN1bHQ7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgIH0pO1xyXG4gICAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgICByZXR1cm4gcmVzdWx0O1xyXG4gICAgICAgIH1cclxuICAgICAgfSk7XHJcbiAgICB9KTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFJldHVybnMgdGhlIHJlY2VpdmVkIGNsYWltcyBhYm91dCB0aGUgdXNlci5cclxuICAgKi9cclxuICBwdWJsaWMgZ2V0SWRlbnRpdHlDbGFpbXMoKTogb2JqZWN0IHtcclxuICAgIGNvbnN0IGNsYWltcyA9IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fY2xhaW1zX29iaicpO1xyXG4gICAgaWYgKCFjbGFpbXMpIHtcclxuICAgICAgcmV0dXJuIG51bGw7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gSlNPTi5wYXJzZShjbGFpbXMpO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogUmV0dXJucyB0aGUgZ3JhbnRlZCBzY29wZXMgZnJvbSB0aGUgc2VydmVyLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBnZXRHcmFudGVkU2NvcGVzKCk6IG9iamVjdCB7XHJcbiAgICBjb25zdCBzY29wZXMgPSB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2dyYW50ZWRfc2NvcGVzJyk7XHJcbiAgICBpZiAoIXNjb3Blcykge1xyXG4gICAgICByZXR1cm4gbnVsbDtcclxuICAgIH1cclxuICAgIHJldHVybiBKU09OLnBhcnNlKHNjb3Blcyk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBSZXR1cm5zIHRoZSBjdXJyZW50IGlkX3Rva2VuLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBnZXRJZFRva2VuKCk6IHN0cmluZyB7XHJcbiAgICByZXR1cm4gdGhpcy5fc3RvcmFnZSA/IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW4nKSA6IG51bGw7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgcGFkQmFzZTY0KGJhc2U2NGRhdGEpOiBzdHJpbmcge1xyXG4gICAgd2hpbGUgKGJhc2U2NGRhdGEubGVuZ3RoICUgNCAhPT0gMCkge1xyXG4gICAgICBiYXNlNjRkYXRhICs9ICc9JztcclxuICAgIH1cclxuICAgIHJldHVybiBiYXNlNjRkYXRhO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogUmV0dXJucyB0aGUgY3VycmVudCBhY2Nlc3NfdG9rZW4uXHJcbiAgICovXHJcbiAgcHVibGljIGdldEFjY2Vzc1Rva2VuKCk6IHN0cmluZyB7XHJcbiAgICByZXR1cm4gdGhpcy5fc3RvcmFnZSA/IHRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnYWNjZXNzX3Rva2VuJykgOiBudWxsO1xyXG4gIH1cclxuXHJcbiAgcHVibGljIGdldFJlZnJlc2hUb2tlbigpOiBzdHJpbmcge1xyXG4gICAgcmV0dXJuIHRoaXMuX3N0b3JhZ2UgPyB0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ3JlZnJlc2hfdG9rZW4nKSA6IG51bGw7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBSZXR1cm5zIHRoZSBleHBpcmF0aW9uIGRhdGUgb2YgdGhlIGFjY2Vzc190b2tlblxyXG4gICAqIGFzIG1pbGxpc2Vjb25kcyBzaW5jZSAxOTcwLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBnZXRBY2Nlc3NUb2tlbkV4cGlyYXRpb24oKTogbnVtYmVyIHtcclxuICAgIGlmICghdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdleHBpcmVzX2F0JykpIHtcclxuICAgICAgcmV0dXJuIG51bGw7XHJcbiAgICB9XHJcbiAgICByZXR1cm4gcGFyc2VJbnQodGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdleHBpcmVzX2F0JyksIDEwKTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBnZXRBY2Nlc3NUb2tlblN0b3JlZEF0KCk6IG51bWJlciB7XHJcbiAgICByZXR1cm4gcGFyc2VJbnQodGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdhY2Nlc3NfdG9rZW5fc3RvcmVkX2F0JyksIDEwKTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBnZXRJZFRva2VuU3RvcmVkQXQoKTogbnVtYmVyIHtcclxuICAgIHJldHVybiBwYXJzZUludCh0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2lkX3Rva2VuX3N0b3JlZF9hdCcpLCAxMCk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBSZXR1cm5zIHRoZSBleHBpcmF0aW9uIGRhdGUgb2YgdGhlIGlkX3Rva2VuXHJcbiAgICogYXMgbWlsbGlzZWNvbmRzIHNpbmNlIDE5NzAuXHJcbiAgICovXHJcbiAgcHVibGljIGdldElkVG9rZW5FeHBpcmF0aW9uKCk6IG51bWJlciB7XHJcbiAgICBpZiAoIXRoaXMuX3N0b3JhZ2UuZ2V0SXRlbSgnaWRfdG9rZW5fZXhwaXJlc19hdCcpKSB7XHJcbiAgICAgIHJldHVybiBudWxsO1xyXG4gICAgfVxyXG5cclxuICAgIHJldHVybiBwYXJzZUludCh0aGlzLl9zdG9yYWdlLmdldEl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnKSwgMTApO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogQ2hlY2tlcywgd2hldGhlciB0aGVyZSBpcyBhIHZhbGlkIGFjY2Vzc190b2tlbi5cclxuICAgKi9cclxuICBwdWJsaWMgaGFzVmFsaWRBY2Nlc3NUb2tlbigpOiBib29sZWFuIHtcclxuICAgIGlmICh0aGlzLmdldEFjY2Vzc1Rva2VuKCkpIHtcclxuICAgICAgY29uc3QgZXhwaXJlc0F0ID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdleHBpcmVzX2F0Jyk7XHJcbiAgICAgIGNvbnN0IG5vdyA9IG5ldyBEYXRlKCk7XHJcbiAgICAgIGlmIChleHBpcmVzQXQgJiYgcGFyc2VJbnQoZXhwaXJlc0F0LCAxMCkgPCBub3cuZ2V0VGltZSgpKSB7XHJcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICB9XHJcblxyXG4gICAgICByZXR1cm4gdHJ1ZTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gZmFsc2U7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBDaGVja3Mgd2hldGhlciB0aGVyZSBpcyBhIHZhbGlkIGlkX3Rva2VuLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBoYXNWYWxpZElkVG9rZW4oKTogYm9vbGVhbiB7XHJcbiAgICBpZiAodGhpcy5nZXRJZFRva2VuKCkpIHtcclxuICAgICAgY29uc3QgZXhwaXJlc0F0ID0gdGhpcy5fc3RvcmFnZS5nZXRJdGVtKCdpZF90b2tlbl9leHBpcmVzX2F0Jyk7XHJcbiAgICAgIGNvbnN0IG5vdyA9IG5ldyBEYXRlKCk7XHJcbiAgICAgIGlmIChleHBpcmVzQXQgJiYgcGFyc2VJbnQoZXhwaXJlc0F0LCAxMCkgPCBub3cuZ2V0VGltZSgpKSB7XHJcbiAgICAgICAgcmV0dXJuIGZhbHNlO1xyXG4gICAgICB9XHJcblxyXG4gICAgICByZXR1cm4gdHJ1ZTtcclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gZmFsc2U7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBSZXRyaWV2ZSBhIHNhdmVkIGN1c3RvbSBwcm9wZXJ0eSBvZiB0aGUgVG9rZW5SZXBvbnNlIG9iamVjdC4gT25seSBpZiBwcmVkZWZpbmVkIGluIGF1dGhjb25maWcuXHJcbiAgICovXHJcbiAgcHVibGljIGdldEN1c3RvbVRva2VuUmVzcG9uc2VQcm9wZXJ0eShyZXF1ZXN0ZWRQcm9wZXJ0eTogc3RyaW5nKTogYW55IHtcclxuICAgIHJldHVybiB0aGlzLl9zdG9yYWdlICYmXHJcbiAgICAgIHRoaXMuY29uZmlnLmN1c3RvbVRva2VuUGFyYW1ldGVycyAmJlxyXG4gICAgICB0aGlzLmNvbmZpZy5jdXN0b21Ub2tlblBhcmFtZXRlcnMuaW5kZXhPZihyZXF1ZXN0ZWRQcm9wZXJ0eSkgPj0gMCAmJlxyXG4gICAgICB0aGlzLl9zdG9yYWdlLmdldEl0ZW0ocmVxdWVzdGVkUHJvcGVydHkpICE9PSBudWxsXHJcbiAgICAgID8gSlNPTi5wYXJzZSh0aGlzLl9zdG9yYWdlLmdldEl0ZW0ocmVxdWVzdGVkUHJvcGVydHkpKVxyXG4gICAgICA6IG51bGw7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBSZXR1cm5zIHRoZSBhdXRoLWhlYWRlciB0aGF0IGNhbiBiZSB1c2VkXHJcbiAgICogdG8gdHJhbnNtaXQgdGhlIGFjY2Vzc190b2tlbiB0byBhIHNlcnZpY2VcclxuICAgKi9cclxuICBwdWJsaWMgYXV0aG9yaXphdGlvbkhlYWRlcigpOiBzdHJpbmcge1xyXG4gICAgcmV0dXJuICdCZWFyZXIgJyArIHRoaXMuZ2V0QWNjZXNzVG9rZW4oKTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFJlbW92ZXMgYWxsIHRva2VucyBhbmQgbG9ncyB0aGUgdXNlciBvdXQuXHJcbiAgICogSWYgYSBsb2dvdXQgdXJsIGlzIGNvbmZpZ3VyZWQsIHRoZSB1c2VyIGlzXHJcbiAgICogcmVkaXJlY3RlZCB0byBpdCB3aXRoIG9wdGlvbmFsIHN0YXRlIHBhcmFtZXRlci5cclxuICAgKiBAcGFyYW0gbm9SZWRpcmVjdFRvTG9nb3V0VXJsXHJcbiAgICogQHBhcmFtIHN0YXRlXHJcbiAgICovXHJcbiAgcHVibGljIGxvZ091dCgpOiB2b2lkO1xyXG4gIHB1YmxpYyBsb2dPdXQoY3VzdG9tUGFyYW1ldGVyczogb2JqZWN0KTogdm9pZDtcclxuICBwdWJsaWMgbG9nT3V0KG5vUmVkaXJlY3RUb0xvZ291dFVybDogYm9vbGVhbik6IHZvaWQ7XHJcbiAgcHVibGljIGxvZ091dChub1JlZGlyZWN0VG9Mb2dvdXRVcmw6IGJvb2xlYW4sIHN0YXRlOiBzdHJpbmcpOiB2b2lkO1xyXG4gIHB1YmxpYyBsb2dPdXQoY3VzdG9tUGFyYW1ldGVyczogYm9vbGVhbiB8IG9iamVjdCA9IHt9LCBzdGF0ZSA9ICcnKTogdm9pZCB7XHJcbiAgICBsZXQgbm9SZWRpcmVjdFRvTG9nb3V0VXJsID0gZmFsc2U7XHJcbiAgICBpZiAodHlwZW9mIGN1c3RvbVBhcmFtZXRlcnMgPT09ICdib29sZWFuJykge1xyXG4gICAgICBub1JlZGlyZWN0VG9Mb2dvdXRVcmwgPSBjdXN0b21QYXJhbWV0ZXJzO1xyXG4gICAgICBjdXN0b21QYXJhbWV0ZXJzID0ge307XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgaWRfdG9rZW4gPSB0aGlzLmdldElkVG9rZW4oKTtcclxuICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnYWNjZXNzX3Rva2VuJyk7XHJcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2lkX3Rva2VuJyk7XHJcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ3JlZnJlc2hfdG9rZW4nKTtcclxuXHJcbiAgICBpZiAodGhpcy5zYXZlTm9uY2VzSW5Mb2NhbFN0b3JhZ2UpIHtcclxuICAgICAgbG9jYWxTdG9yYWdlLnJlbW92ZUl0ZW0oJ25vbmNlJyk7XHJcbiAgICAgIGxvY2FsU3RvcmFnZS5yZW1vdmVJdGVtKCdQS0NFX3ZlcmlmaWVyJyk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ25vbmNlJyk7XHJcbiAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnUEtDRV92ZXJpZmllcicpO1xyXG4gICAgfVxyXG5cclxuICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnZXhwaXJlc19hdCcpO1xyXG4gICAgdGhpcy5fc3RvcmFnZS5yZW1vdmVJdGVtKCdpZF90b2tlbl9jbGFpbXNfb2JqJyk7XHJcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2lkX3Rva2VuX2V4cGlyZXNfYXQnKTtcclxuICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnaWRfdG9rZW5fc3RvcmVkX2F0Jyk7XHJcbiAgICB0aGlzLl9zdG9yYWdlLnJlbW92ZUl0ZW0oJ2FjY2Vzc190b2tlbl9zdG9yZWRfYXQnKTtcclxuICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnZ3JhbnRlZF9zY29wZXMnKTtcclxuICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbSgnc2Vzc2lvbl9zdGF0ZScpO1xyXG4gICAgaWYgKHRoaXMuY29uZmlnLmN1c3RvbVRva2VuUGFyYW1ldGVycykge1xyXG4gICAgICB0aGlzLmNvbmZpZy5jdXN0b21Ub2tlblBhcmFtZXRlcnMuZm9yRWFjaChjdXN0b21QYXJhbSA9PlxyXG4gICAgICAgIHRoaXMuX3N0b3JhZ2UucmVtb3ZlSXRlbShjdXN0b21QYXJhbSlcclxuICAgICAgKTtcclxuICAgIH1cclxuICAgIHRoaXMuc2lsZW50UmVmcmVzaFN1YmplY3QgPSBudWxsO1xyXG5cclxuICAgIHRoaXMuZXZlbnRzU3ViamVjdC5uZXh0KG5ldyBPQXV0aEluZm9FdmVudCgnbG9nb3V0JykpO1xyXG5cclxuICAgIGlmICghdGhpcy5sb2dvdXRVcmwpIHtcclxuICAgICAgcmV0dXJuO1xyXG4gICAgfVxyXG4gICAgaWYgKG5vUmVkaXJlY3RUb0xvZ291dFVybCkge1xyXG4gICAgICByZXR1cm47XHJcbiAgICB9XHJcblxyXG4gICAgaWYgKCFpZF90b2tlbiAmJiAhdGhpcy5wb3N0TG9nb3V0UmVkaXJlY3RVcmkpIHtcclxuICAgICAgcmV0dXJuO1xyXG4gICAgfVxyXG5cclxuICAgIGxldCBsb2dvdXRVcmw6IHN0cmluZztcclxuXHJcbiAgICBpZiAoIXRoaXMudmFsaWRhdGVVcmxGb3JIdHRwcyh0aGlzLmxvZ291dFVybCkpIHtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKFxyXG4gICAgICAgIFwibG9nb3V0VXJsICBtdXN0IHVzZSBIVFRQUyAod2l0aCBUTFMpLCBvciBjb25maWcgdmFsdWUgZm9yIHByb3BlcnR5ICdyZXF1aXJlSHR0cHMnIG11c3QgYmUgc2V0IHRvICdmYWxzZScgYW5kIGFsbG93IEhUVFAgKHdpdGhvdXQgVExTKS5cIlxyXG4gICAgICApO1xyXG4gICAgfVxyXG5cclxuICAgIC8vIEZvciBiYWNrd2FyZCBjb21wYXRpYmlsaXR5XHJcbiAgICBpZiAodGhpcy5sb2dvdXRVcmwuaW5kZXhPZigne3snKSA+IC0xKSB7XHJcbiAgICAgIGxvZ291dFVybCA9IHRoaXMubG9nb3V0VXJsXHJcbiAgICAgICAgLnJlcGxhY2UoL1xce1xce2lkX3Rva2VuXFx9XFx9LywgaWRfdG9rZW4pXHJcbiAgICAgICAgLnJlcGxhY2UoL1xce1xce2NsaWVudF9pZFxcfVxcfS8sIHRoaXMuY2xpZW50SWQpO1xyXG4gICAgfSBlbHNlIHtcclxuICAgICAgbGV0IHBhcmFtcyA9IG5ldyBIdHRwUGFyYW1zKCk7XHJcblxyXG4gICAgICBpZiAoaWRfdG9rZW4pIHtcclxuICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdpZF90b2tlbl9oaW50JywgaWRfdG9rZW4pO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBjb25zdCBwb3N0TG9nb3V0VXJsID0gdGhpcy5wb3N0TG9nb3V0UmVkaXJlY3RVcmkgfHwgdGhpcy5yZWRpcmVjdFVyaTtcclxuICAgICAgaWYgKHBvc3RMb2dvdXRVcmwpIHtcclxuICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdwb3N0X2xvZ291dF9yZWRpcmVjdF91cmknLCBwb3N0TG9nb3V0VXJsKTtcclxuXHJcbiAgICAgICAgaWYgKHN0YXRlKSB7XHJcbiAgICAgICAgICBwYXJhbXMgPSBwYXJhbXMuc2V0KCdzdGF0ZScsIHN0YXRlKTtcclxuICAgICAgICB9XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGZvciAobGV0IGtleSBpbiBjdXN0b21QYXJhbWV0ZXJzKSB7XHJcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldChrZXksIGN1c3RvbVBhcmFtZXRlcnNba2V5XSk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGxvZ291dFVybCA9XHJcbiAgICAgICAgdGhpcy5sb2dvdXRVcmwgK1xyXG4gICAgICAgICh0aGlzLmxvZ291dFVybC5pbmRleE9mKCc/JykgPiAtMSA/ICcmJyA6ICc/JykgK1xyXG4gICAgICAgIHBhcmFtcy50b1N0cmluZygpO1xyXG4gICAgfVxyXG4gICAgdGhpcy5jb25maWcub3BlblVyaShsb2dvdXRVcmwpO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogQGlnbm9yZVxyXG4gICAqL1xyXG4gIHB1YmxpYyBjcmVhdGVBbmRTYXZlTm9uY2UoKTogUHJvbWlzZTxzdHJpbmc+IHtcclxuICAgIGNvbnN0IHRoYXQgPSB0aGlzO1xyXG4gICAgcmV0dXJuIHRoaXMuY3JlYXRlTm9uY2UoKS50aGVuKGZ1bmN0aW9uKG5vbmNlOiBhbnkpIHtcclxuICAgICAgLy8gVXNlIGxvY2FsU3RvcmFnZSBmb3Igbm9uY2UgaWYgcG9zc2libGVcclxuICAgICAgLy8gbG9jYWxTdG9yYWdlIGlzIHRoZSBvbmx5IHN0b3JhZ2Ugd2hvIHN1cnZpdmVzIGFcclxuICAgICAgLy8gcmVkaXJlY3QgaW4gQUxMIGJyb3dzZXJzIChhbHNvIElFKVxyXG4gICAgICAvLyBPdGhlcndpZXNlIHdlJ2QgZm9yY2UgdGVhbXMgd2hvIGhhdmUgdG8gc3VwcG9ydFxyXG4gICAgICAvLyBJRSBpbnRvIHVzaW5nIGxvY2FsU3RvcmFnZSBmb3IgZXZlcnl0aGluZ1xyXG4gICAgICBpZiAoXHJcbiAgICAgICAgdGhhdC5zYXZlTm9uY2VzSW5Mb2NhbFN0b3JhZ2UgJiZcclxuICAgICAgICB0eXBlb2Ygd2luZG93Wydsb2NhbFN0b3JhZ2UnXSAhPT0gJ3VuZGVmaW5lZCdcclxuICAgICAgKSB7XHJcbiAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oJ25vbmNlJywgbm9uY2UpO1xyXG4gICAgICB9IGVsc2Uge1xyXG4gICAgICAgIHRoYXQuX3N0b3JhZ2Uuc2V0SXRlbSgnbm9uY2UnLCBub25jZSk7XHJcbiAgICAgIH1cclxuICAgICAgcmV0dXJuIG5vbmNlO1xyXG4gICAgfSk7XHJcbiAgfVxyXG5cclxuICAvKipcclxuICAgKiBAaWdub3JlXHJcbiAgICovXHJcbiAgcHVibGljIG5nT25EZXN0cm95KCk6IHZvaWQge1xyXG4gICAgdGhpcy5jbGVhckFjY2Vzc1Rva2VuVGltZXIoKTtcclxuICAgIHRoaXMuY2xlYXJJZFRva2VuVGltZXIoKTtcclxuXHJcbiAgICB0aGlzLnJlbW92ZVNpbGVudFJlZnJlc2hFdmVudExpc3RlbmVyKCk7XHJcbiAgICBjb25zdCBzaWxlbnRSZWZyZXNoRnJhbWUgPSB0aGlzLmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFxyXG4gICAgICB0aGlzLnNpbGVudFJlZnJlc2hJRnJhbWVOYW1lXHJcbiAgICApO1xyXG4gICAgaWYgKHNpbGVudFJlZnJlc2hGcmFtZSkge1xyXG4gICAgICBzaWxlbnRSZWZyZXNoRnJhbWUucmVtb3ZlKCk7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy5zdG9wU2Vzc2lvbkNoZWNrVGltZXIoKTtcclxuICAgIHRoaXMucmVtb3ZlU2Vzc2lvbkNoZWNrRXZlbnRMaXN0ZW5lcigpO1xyXG4gICAgY29uc3Qgc2Vzc2lvbkNoZWNrRnJhbWUgPSB0aGlzLmRvY3VtZW50LmdldEVsZW1lbnRCeUlkKFxyXG4gICAgICB0aGlzLnNlc3Npb25DaGVja0lGcmFtZU5hbWVcclxuICAgICk7XHJcbiAgICBpZiAoc2Vzc2lvbkNoZWNrRnJhbWUpIHtcclxuICAgICAgc2Vzc2lvbkNoZWNrRnJhbWUucmVtb3ZlKCk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgY3JlYXRlTm9uY2UoKTogUHJvbWlzZTxzdHJpbmc+IHtcclxuICAgIHJldHVybiBuZXcgUHJvbWlzZShyZXNvbHZlID0+IHtcclxuICAgICAgaWYgKHRoaXMucm5nVXJsKSB7XHJcbiAgICAgICAgdGhyb3cgbmV3IEVycm9yKFxyXG4gICAgICAgICAgJ2NyZWF0ZU5vbmNlIHdpdGggcm5nLXdlYi1hcGkgaGFzIG5vdCBiZWVuIGltcGxlbWVudGVkIHNvIGZhcidcclxuICAgICAgICApO1xyXG4gICAgICB9XHJcblxyXG4gICAgICAvKlxyXG4gICAgICAgKiBUaGlzIGFscGhhYmV0IGlzIGZyb206XHJcbiAgICAgICAqIGh0dHBzOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM3NjM2I3NlY3Rpb24tNC4xXHJcbiAgICAgICAqXHJcbiAgICAgICAqIFtBLVpdIC8gW2Etel0gLyBbMC05XSAvIFwiLVwiIC8gXCIuXCIgLyBcIl9cIiAvIFwiflwiXHJcbiAgICAgICAqL1xyXG4gICAgICBjb25zdCB1bnJlc2VydmVkID1cclxuICAgICAgICAnQUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODktLl9+JztcclxuICAgICAgbGV0IHNpemUgPSA0NTtcclxuICAgICAgbGV0IGlkID0gJyc7XHJcblxyXG4gICAgICBjb25zdCBjcnlwdG8gPVxyXG4gICAgICAgIHR5cGVvZiBzZWxmID09PSAndW5kZWZpbmVkJyA/IG51bGwgOiBzZWxmLmNyeXB0byB8fCBzZWxmWydtc0NyeXB0byddO1xyXG4gICAgICBpZiAoY3J5cHRvKSB7XHJcbiAgICAgICAgbGV0IGJ5dGVzID0gbmV3IFVpbnQ4QXJyYXkoc2l6ZSk7XHJcbiAgICAgICAgY3J5cHRvLmdldFJhbmRvbVZhbHVlcyhieXRlcyk7XHJcblxyXG4gICAgICAgIC8vIE5lZWRlZCBmb3IgSUVcclxuICAgICAgICBpZiAoIWJ5dGVzLm1hcCkge1xyXG4gICAgICAgICAgKGJ5dGVzIGFzIGFueSkubWFwID0gQXJyYXkucHJvdG90eXBlLm1hcDtcclxuICAgICAgICB9XHJcblxyXG4gICAgICAgIGJ5dGVzID0gYnl0ZXMubWFwKHggPT4gdW5yZXNlcnZlZC5jaGFyQ29kZUF0KHggJSB1bnJlc2VydmVkLmxlbmd0aCkpO1xyXG4gICAgICAgIGlkID0gU3RyaW5nLmZyb21DaGFyQ29kZS5hcHBseShudWxsLCBieXRlcyk7XHJcbiAgICAgIH0gZWxzZSB7XHJcbiAgICAgICAgd2hpbGUgKDAgPCBzaXplLS0pIHtcclxuICAgICAgICAgIGlkICs9IHVucmVzZXJ2ZWRbKE1hdGgucmFuZG9tKCkgKiB1bnJlc2VydmVkLmxlbmd0aCkgfCAwXTtcclxuICAgICAgICB9XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIHJlc29sdmUoYmFzZTY0VXJsRW5jb2RlKGlkKSk7XHJcbiAgICB9KTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBhc3luYyBjaGVja0F0SGFzaChwYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMpOiBQcm9taXNlPGJvb2xlYW4+IHtcclxuICAgIGlmICghdGhpcy50b2tlblZhbGlkYXRpb25IYW5kbGVyKSB7XHJcbiAgICAgIHRoaXMubG9nZ2VyLndhcm4oXHJcbiAgICAgICAgJ05vIHRva2VuVmFsaWRhdGlvbkhhbmRsZXIgY29uZmlndXJlZC4gQ2Fubm90IGNoZWNrIGF0X2hhc2guJ1xyXG4gICAgICApO1xyXG4gICAgICByZXR1cm4gdHJ1ZTtcclxuICAgIH1cclxuICAgIHJldHVybiB0aGlzLnRva2VuVmFsaWRhdGlvbkhhbmRsZXIudmFsaWRhdGVBdEhhc2gocGFyYW1zKTtcclxuICB9XHJcblxyXG4gIHByb3RlY3RlZCBjaGVja1NpZ25hdHVyZShwYXJhbXM6IFZhbGlkYXRpb25QYXJhbXMpOiBQcm9taXNlPGFueT4ge1xyXG4gICAgaWYgKCF0aGlzLnRva2VuVmFsaWRhdGlvbkhhbmRsZXIpIHtcclxuICAgICAgdGhpcy5sb2dnZXIud2FybihcclxuICAgICAgICAnTm8gdG9rZW5WYWxpZGF0aW9uSGFuZGxlciBjb25maWd1cmVkLiBDYW5ub3QgY2hlY2sgc2lnbmF0dXJlLidcclxuICAgICAgKTtcclxuICAgICAgcmV0dXJuIFByb21pc2UucmVzb2x2ZShudWxsKTtcclxuICAgIH1cclxuICAgIHJldHVybiB0aGlzLnRva2VuVmFsaWRhdGlvbkhhbmRsZXIudmFsaWRhdGVTaWduYXR1cmUocGFyYW1zKTtcclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFN0YXJ0IHRoZSBpbXBsaWNpdCBmbG93IG9yIHRoZSBjb2RlIGZsb3csXHJcbiAgICogZGVwZW5kaW5nIG9uIHlvdXIgY29uZmlndXJhdGlvbi5cclxuICAgKi9cclxuICBwdWJsaWMgaW5pdExvZ2luRmxvdyhhZGRpdGlvbmFsU3RhdGUgPSAnJywgcGFyYW1zID0ge30pOiB2b2lkIHtcclxuICAgIGlmICh0aGlzLnJlc3BvbnNlVHlwZSA9PT0gJ2NvZGUnKSB7XHJcbiAgICAgIHJldHVybiB0aGlzLmluaXRDb2RlRmxvdyhhZGRpdGlvbmFsU3RhdGUsIHBhcmFtcyk7XHJcbiAgICB9IGVsc2Uge1xyXG4gICAgICByZXR1cm4gdGhpcy5pbml0SW1wbGljaXRGbG93KGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKTtcclxuICAgIH1cclxuICB9XHJcblxyXG4gIC8qKlxyXG4gICAqIFN0YXJ0cyB0aGUgYXV0aG9yaXphdGlvbiBjb2RlIGZsb3cgYW5kIHJlZGlyZWN0cyB0byB1c2VyIHRvXHJcbiAgICogdGhlIGF1dGggc2VydmVycyBsb2dpbiB1cmwuXHJcbiAgICovXHJcbiAgcHVibGljIGluaXRDb2RlRmxvdyhhZGRpdGlvbmFsU3RhdGUgPSAnJywgcGFyYW1zID0ge30pOiB2b2lkIHtcclxuICAgIGlmICh0aGlzLmxvZ2luVXJsICE9PSAnJykge1xyXG4gICAgICB0aGlzLmluaXRDb2RlRmxvd0ludGVybmFsKGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKTtcclxuICAgIH0gZWxzZSB7XHJcbiAgICAgIHRoaXMuZXZlbnRzXHJcbiAgICAgICAgLnBpcGUoZmlsdGVyKGUgPT4gZS50eXBlID09PSAnZGlzY292ZXJ5X2RvY3VtZW50X2xvYWRlZCcpKVxyXG4gICAgICAgIC5zdWJzY3JpYmUoXyA9PiB0aGlzLmluaXRDb2RlRmxvd0ludGVybmFsKGFkZGl0aW9uYWxTdGF0ZSwgcGFyYW1zKSk7XHJcbiAgICB9XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIGluaXRDb2RlRmxvd0ludGVybmFsKGFkZGl0aW9uYWxTdGF0ZSA9ICcnLCBwYXJhbXMgPSB7fSk6IHZvaWQge1xyXG4gICAgaWYgKCF0aGlzLnZhbGlkYXRlVXJsRm9ySHR0cHModGhpcy5sb2dpblVybCkpIHtcclxuICAgICAgdGhyb3cgbmV3IEVycm9yKFxyXG4gICAgICAgIFwibG9naW5VcmwgIG11c3QgdXNlIEhUVFBTICh3aXRoIFRMUyksIG9yIGNvbmZpZyB2YWx1ZSBmb3IgcHJvcGVydHkgJ3JlcXVpcmVIdHRwcycgbXVzdCBiZSBzZXQgdG8gJ2ZhbHNlJyBhbmQgYWxsb3cgSFRUUCAod2l0aG91dCBUTFMpLlwiXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgdGhpcy5jcmVhdGVMb2dpblVybChhZGRpdGlvbmFsU3RhdGUsICcnLCBudWxsLCBmYWxzZSwgcGFyYW1zKVxyXG4gICAgICAudGhlbih0aGlzLmNvbmZpZy5vcGVuVXJpKVxyXG4gICAgICAuY2F0Y2goZXJyb3IgPT4ge1xyXG4gICAgICAgIGNvbnNvbGUuZXJyb3IoJ0Vycm9yIGluIGluaXRBdXRob3JpemF0aW9uQ29kZUZsb3cnKTtcclxuICAgICAgICBjb25zb2xlLmVycm9yKGVycm9yKTtcclxuICAgICAgfSk7XHJcbiAgfVxyXG5cclxuICBwcm90ZWN0ZWQgYXN5bmMgY3JlYXRlQ2hhbGxhbmdlVmVyaWZpZXJQYWlyRm9yUEtDRSgpOiBQcm9taXNlPFxyXG4gICAgW3N0cmluZywgc3RyaW5nXVxyXG4gID4ge1xyXG4gICAgaWYgKCF0aGlzLmNyeXB0bykge1xyXG4gICAgICB0aHJvdyBuZXcgRXJyb3IoXHJcbiAgICAgICAgJ1BLQ0Ugc3VwcG9ydCBmb3IgY29kZSBmbG93IG5lZWRzIGEgQ3J5cHRvSGFuZGVyLiBEaWQgeW91IGltcG9ydCB0aGUgT0F1dGhNb2R1bGUgdXNpbmcgZm9yUm9vdCgpID8nXHJcbiAgICAgICk7XHJcbiAgICB9XHJcblxyXG4gICAgY29uc3QgdmVyaWZpZXIgPSBhd2FpdCB0aGlzLmNyZWF0ZU5vbmNlKCk7XHJcbiAgICBjb25zdCBjaGFsbGVuZ2VSYXcgPSBhd2FpdCB0aGlzLmNyeXB0by5jYWxjSGFzaCh2ZXJpZmllciwgJ3NoYS0yNTYnKTtcclxuICAgIGNvbnN0IGNoYWxsZW5nZSA9IGJhc2U2NFVybEVuY29kZShjaGFsbGVuZ2VSYXcpO1xyXG5cclxuICAgIHJldHVybiBbY2hhbGxlbmdlLCB2ZXJpZmllcl07XHJcbiAgfVxyXG5cclxuICBwcml2YXRlIGV4dHJhY3RSZWNvZ25pemVkQ3VzdG9tUGFyYW1ldGVycyhcclxuICAgIHRva2VuUmVzcG9uc2U6IFRva2VuUmVzcG9uc2VcclxuICApOiBNYXA8c3RyaW5nLCBzdHJpbmc+IHtcclxuICAgIGxldCBmb3VuZFBhcmFtZXRlcnM6IE1hcDxzdHJpbmcsIHN0cmluZz4gPSBuZXcgTWFwPHN0cmluZywgc3RyaW5nPigpO1xyXG4gICAgaWYgKCF0aGlzLmNvbmZpZy5jdXN0b21Ub2tlblBhcmFtZXRlcnMpIHtcclxuICAgICAgcmV0dXJuIGZvdW5kUGFyYW1ldGVycztcclxuICAgIH1cclxuICAgIHRoaXMuY29uZmlnLmN1c3RvbVRva2VuUGFyYW1ldGVycy5mb3JFYWNoKChyZWNvZ25pemVkUGFyYW1ldGVyOiBzdHJpbmcpID0+IHtcclxuICAgICAgaWYgKHRva2VuUmVzcG9uc2VbcmVjb2duaXplZFBhcmFtZXRlcl0pIHtcclxuICAgICAgICBmb3VuZFBhcmFtZXRlcnMuc2V0KFxyXG4gICAgICAgICAgcmVjb2duaXplZFBhcmFtZXRlcixcclxuICAgICAgICAgIEpTT04uc3RyaW5naWZ5KHRva2VuUmVzcG9uc2VbcmVjb2duaXplZFBhcmFtZXRlcl0pXHJcbiAgICAgICAgKTtcclxuICAgICAgfVxyXG4gICAgfSk7XHJcbiAgICByZXR1cm4gZm91bmRQYXJhbWV0ZXJzO1xyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogUmV2b2tlcyB0aGUgYXV0aCB0b2tlbiB0byBzZWN1cmUgdGhlIHZ1bG5hcmFiaWxpdHlcclxuICAgKiBvZiB0aGUgdG9rZW4gaXNzdWVkIGFsbG93aW5nIHRoZSBhdXRob3JpemF0aW9uIHNlcnZlciB0byBjbGVhblxyXG4gICAqIHVwIGFueSBzZWN1cml0eSBjcmVkZW50aWFscyBhc3NvY2lhdGVkIHdpdGggdGhlIGF1dGhvcml6YXRpb25cclxuICAgKi9cclxuICBwdWJsaWMgcmV2b2tlVG9rZW5BbmRMb2dvdXQoXHJcbiAgICBjdXN0b21QYXJhbWV0ZXJzOiBvYmplY3QgPSB7fSxcclxuICAgIGlnbm9yZUNvcnNJc3N1ZXMgPSBmYWxzZVxyXG4gICk6IFByb21pc2U8YW55PiB7XHJcbiAgICBsZXQgcmV2b2tlRW5kcG9pbnQgPSB0aGlzLnJldm9jYXRpb25FbmRwb2ludDtcclxuICAgIGxldCBhY2Nlc3NUb2tlbiA9IHRoaXMuZ2V0QWNjZXNzVG9rZW4oKTtcclxuICAgIGxldCByZWZyZXNoVG9rZW4gPSB0aGlzLmdldFJlZnJlc2hUb2tlbigpO1xyXG5cclxuICAgIGlmICghYWNjZXNzVG9rZW4pIHtcclxuICAgICAgcmV0dXJuO1xyXG4gICAgfVxyXG5cclxuICAgIGxldCBwYXJhbXMgPSBuZXcgSHR0cFBhcmFtcygpO1xyXG5cclxuICAgIGxldCBoZWFkZXJzID0gbmV3IEh0dHBIZWFkZXJzKCkuc2V0KFxyXG4gICAgICAnQ29udGVudC1UeXBlJyxcclxuICAgICAgJ2FwcGxpY2F0aW9uL3gtd3d3LWZvcm0tdXJsZW5jb2RlZCdcclxuICAgICk7XHJcblxyXG4gICAgaWYgKHRoaXMudXNlSHR0cEJhc2ljQXV0aCkge1xyXG4gICAgICBjb25zdCBoZWFkZXIgPSBidG9hKGAke3RoaXMuY2xpZW50SWR9OiR7dGhpcy5kdW1teUNsaWVudFNlY3JldH1gKTtcclxuICAgICAgaGVhZGVycyA9IGhlYWRlcnMuc2V0KCdBdXRob3JpemF0aW9uJywgJ0Jhc2ljICcgKyBoZWFkZXIpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoKSB7XHJcbiAgICAgIHBhcmFtcyA9IHBhcmFtcy5zZXQoJ2NsaWVudF9pZCcsIHRoaXMuY2xpZW50SWQpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICghdGhpcy51c2VIdHRwQmFzaWNBdXRoICYmIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpIHtcclxuICAgICAgcGFyYW1zID0gcGFyYW1zLnNldCgnY2xpZW50X3NlY3JldCcsIHRoaXMuZHVtbXlDbGllbnRTZWNyZXQpO1xyXG4gICAgfVxyXG5cclxuICAgIGlmICh0aGlzLmN1c3RvbVF1ZXJ5UGFyYW1zKSB7XHJcbiAgICAgIGZvciAoY29uc3Qga2V5IG9mIE9iamVjdC5nZXRPd25Qcm9wZXJ0eU5hbWVzKHRoaXMuY3VzdG9tUXVlcnlQYXJhbXMpKSB7XHJcbiAgICAgICAgcGFyYW1zID0gcGFyYW1zLnNldChrZXksIHRoaXMuY3VzdG9tUXVlcnlQYXJhbXNba2V5XSk7XHJcbiAgICAgIH1cclxuICAgIH1cclxuXHJcbiAgICByZXR1cm4gbmV3IFByb21pc2UoKHJlc29sdmUsIHJlamVjdCkgPT4ge1xyXG4gICAgICBsZXQgcmV2b2tlQWNjZXNzVG9rZW46IE9ic2VydmFibGU8dm9pZD47XHJcbiAgICAgIGxldCByZXZva2VSZWZyZXNoVG9rZW46IE9ic2VydmFibGU8dm9pZD47XHJcblxyXG4gICAgICBpZiAoYWNjZXNzVG9rZW4pIHtcclxuICAgICAgICBsZXQgcmV2b2thdGlvblBhcmFtcyA9IHBhcmFtc1xyXG4gICAgICAgICAgLnNldCgndG9rZW4nLCBhY2Nlc3NUb2tlbilcclxuICAgICAgICAgIC5zZXQoJ3Rva2VuX3R5cGVfaGludCcsICdhY2Nlc3NfdG9rZW4nKTtcclxuICAgICAgICByZXZva2VBY2Nlc3NUb2tlbiA9IHRoaXMuaHR0cC5wb3N0PHZvaWQ+KFxyXG4gICAgICAgICAgcmV2b2tlRW5kcG9pbnQsXHJcbiAgICAgICAgICByZXZva2F0aW9uUGFyYW1zLFxyXG4gICAgICAgICAgeyBoZWFkZXJzIH1cclxuICAgICAgICApO1xyXG4gICAgICB9IGVsc2Uge1xyXG4gICAgICAgIHJldm9rZUFjY2Vzc1Rva2VuID0gb2YobnVsbCk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGlmIChyZWZyZXNoVG9rZW4pIHtcclxuICAgICAgICBsZXQgcmV2b2thdGlvblBhcmFtcyA9IHBhcmFtc1xyXG4gICAgICAgICAgLnNldCgndG9rZW4nLCByZWZyZXNoVG9rZW4pXHJcbiAgICAgICAgICAuc2V0KCd0b2tlbl90eXBlX2hpbnQnLCAncmVmcmVzaF90b2tlbicpO1xyXG4gICAgICAgIHJldm9rZVJlZnJlc2hUb2tlbiA9IHRoaXMuaHR0cC5wb3N0PHZvaWQ+KFxyXG4gICAgICAgICAgcmV2b2tlRW5kcG9pbnQsXHJcbiAgICAgICAgICByZXZva2F0aW9uUGFyYW1zLFxyXG4gICAgICAgICAgeyBoZWFkZXJzIH1cclxuICAgICAgICApO1xyXG4gICAgICB9IGVsc2Uge1xyXG4gICAgICAgIHJldm9rZVJlZnJlc2hUb2tlbiA9IG9mKG51bGwpO1xyXG4gICAgICB9XHJcblxyXG4gICAgICBpZiAoaWdub3JlQ29yc0lzc3Vlcykge1xyXG4gICAgICAgIHJldm9rZUFjY2Vzc1Rva2VuID0gcmV2b2tlQWNjZXNzVG9rZW4ucGlwZShcclxuICAgICAgICAgIGNhdGNoRXJyb3IoKGVycjogSHR0cEVycm9yUmVzcG9uc2UpID0+IHtcclxuICAgICAgICAgICAgaWYgKGVyci5zdGF0dXMgPT09IDApIHtcclxuICAgICAgICAgICAgICByZXR1cm4gb2Y8dm9pZD4obnVsbCk7XHJcbiAgICAgICAgICAgIH1cclxuICAgICAgICAgICAgcmV0dXJuIHRocm93RXJyb3IoZXJyKTtcclxuICAgICAgICAgIH0pXHJcbiAgICAgICAgKTtcclxuXHJcbiAgICAgICAgcmV2b2tlUmVmcmVzaFRva2VuID0gcmV2b2tlUmVmcmVzaFRva2VuLnBpcGUoXHJcbiAgICAgICAgICBjYXRjaEVycm9yKChlcnI6IEh0dHBFcnJvclJlc3BvbnNlKSA9PiB7XHJcbiAgICAgICAgICAgIGlmIChlcnIuc3RhdHVzID09PSAwKSB7XHJcbiAgICAgICAgICAgICAgcmV0dXJuIG9mPHZvaWQ+KG51bGwpO1xyXG4gICAgICAgICAgICB9XHJcbiAgICAgICAgICAgIHJldHVybiB0aHJvd0Vycm9yKGVycik7XHJcbiAgICAgICAgICB9KVxyXG4gICAgICAgICk7XHJcbiAgICAgIH1cclxuXHJcbiAgICAgIGNvbWJpbmVMYXRlc3QoW3Jldm9rZUFjY2Vzc1Rva2VuLCByZXZva2VSZWZyZXNoVG9rZW5dKS5zdWJzY3JpYmUoXHJcbiAgICAgICAgcmVzID0+IHtcclxuICAgICAgICAgIHRoaXMubG9nT3V0KGN1c3RvbVBhcmFtZXRlcnMpO1xyXG4gICAgICAgICAgcmVzb2x2ZShyZXMpO1xyXG4gICAgICAgICAgdGhpcy5sb2dnZXIuaW5mbygnVG9rZW4gc3VjY2Vzc2Z1bGx5IHJldm9rZWQnKTtcclxuICAgICAgICB9LFxyXG4gICAgICAgIGVyciA9PiB7XHJcbiAgICAgICAgICB0aGlzLmxvZ2dlci5lcnJvcignRXJyb3IgcmV2b2tpbmcgdG9rZW4nLCBlcnIpO1xyXG4gICAgICAgICAgdGhpcy5ldmVudHNTdWJqZWN0Lm5leHQoXHJcbiAgICAgICAgICAgIG5ldyBPQXV0aEVycm9yRXZlbnQoJ3Rva2VuX3Jldm9rZV9lcnJvcicsIGVycilcclxuICAgICAgICAgICk7XHJcbiAgICAgICAgICByZWplY3QoZXJyKTtcclxuICAgICAgICB9XHJcbiAgICAgICk7XHJcbiAgICB9KTtcclxuICB9XHJcbn1cclxuIl19