export class AuthConfig {
    constructor(json) {
        /**
         * The client's id as registered with the auth server
         */
        this.clientId = '';
        /**
         * The client's redirectUri as registered with the auth server
         */
        this.redirectUri = '';
        /**
         * An optional second redirectUri where the auth server
         * redirects the user to after logging out.
         */
        this.postLogoutRedirectUri = '';
        /**
         * The auth server's endpoint that allows to log
         * the user in when using implicit flow.
         */
        this.loginUrl = '';
        /**
         * The requested scopes
         */
        this.scope = 'openid profile';
        this.resource = '';
        this.rngUrl = '';
        /**
         * Defines whether to use OpenId Connect during
         * implicit flow.
         */
        this.oidc = true;
        /**
         * Defines whether to request an access token during
         * implicit flow.
         */
        this.requestAccessToken = true;
        this.options = null;
        /**
         * The issuer's uri.
         */
        this.issuer = '';
        /**
         * The logout url.
         */
        this.logoutUrl = '';
        /**
         * Defines whether to clear the hash fragment after logging in.
         */
        this.clearHashAfterLogin = true;
        /**
         * Url of the token endpoint as defined by OpenId Connect and OAuth 2.
         */
        this.tokenEndpoint = null;
        /**
         * Url of the revocation endpoint as defined by OpenId Connect and OAuth 2.
         */
        this.revocationEndpoint = null;
        /**
         * Names of known parameters sent out in the TokenResponse. https://tools.ietf.org/html/rfc6749#section-5.1
         */
        this.customTokenParameters = [];
        /**
         * Url of the userinfo endpoint as defined by OpenId Connect.
         */
        this.userinfoEndpoint = null;
        this.responseType = '';
        /**
         * Defines whether additional debug information should
         * be shown at the console. Note that in certain browsers
         * the verbosity of the console needs to be explicitly set
         * to include Debug level messages.
         */
        this.showDebugInformation = false;
        /**
         * The redirect uri used when doing silent refresh.
         */
        this.silentRefreshRedirectUri = '';
        this.silentRefreshMessagePrefix = '';
        /**
         * Set this to true to display the iframe used for
         * silent refresh for debugging.
         */
        this.silentRefreshShowIFrame = false;
        /**
         * Timeout for silent refresh.
         * @internal
         * depreacted b/c of typo, see silentRefreshTimeout
         */
        this.siletRefreshTimeout = 1000 * 20;
        /**
         * Timeout for silent refresh.
         */
        this.silentRefreshTimeout = 1000 * 20;
        /**
         * Some auth servers don't allow using password flow
         * w/o a client secret while the standards do not
         * demand for it. In this case, you can set a password
         * here. As this password is exposed to the public
         * it does not bring additional security and is therefore
         * as good as using no password.
         */
        this.dummyClientSecret = null;
        /**
         * Defines whether https is required.
         * The default value is remoteOnly which only allows
         * http for localhost, while every other domains need
         * to be used with https.
         */
        this.requireHttps = 'remoteOnly';
        /**
         * Defines whether every url provided by the discovery
         * document has to start with the issuer's url.
         */
        this.strictDiscoveryDocumentValidation = true;
        /**
         * JSON Web Key Set (https://tools.ietf.org/html/rfc7517)
         * with keys used to validate received id_tokens.
         * This is taken out of the disovery document. Can be set manually too.
         */
        this.jwks = null;
        /**
         * Map with additional query parameter that are appended to
         * the request when initializing implicit flow.
         */
        this.customQueryParams = null;
        this.silentRefreshIFrameName = 'angular-oauth-oidc-silent-refresh-iframe';
        /**
         * Defines when the token_timeout event should be raised.
         * If you set this to the default value 0.75, the event
         * is triggered after 75% of the token's life time.
         */
        this.timeoutFactor = 0.75;
        /**
         * If true, the lib will try to check whether the user
         * is still logged in on a regular basis as described
         * in http://openid.net/specs/openid-connect-session-1_0.html#ChangeNotification
         */
        this.sessionChecksEnabled = false;
        /**
         * Interval in msec for checking the session
         * according to http://openid.net/specs/openid-connect-session-1_0.html#ChangeNotification
         */
        this.sessionCheckIntervall = 3 * 1000;
        /**
         * Url for the iframe used for session checks
         */
        this.sessionCheckIFrameUrl = null;
        /**
         * Name of the iframe to use for session checks
         */
        this.sessionCheckIFrameName = 'angular-oauth-oidc-check-session-iframe';
        /**
         * This property has been introduced to disable at_hash checks
         * and is indented for Identity Provider that does not deliver
         * an at_hash EVEN THOUGH its recommended by the OIDC specs.
         * Of course, when disabling these checks the we are bypassing
         * a security check which means we are more vulnerable.
         */
        this.disableAtHashCheck = false;
        /**
         * Defines wether to check the subject of a refreshed token after silent refresh.
         * Normally, it should be the same as before.
         */
        this.skipSubjectCheck = false;
        this.useIdTokenHintForSilentRefresh = false;
        /**
         * Defined whether to skip the validation of the issuer in the discovery document.
         * Normally, the discovey document's url starts with the url of the issuer.
         */
        this.skipIssuerCheck = false;
        /**
         * final state sent to issuer is built as follows:
         * state = nonce + nonceStateSeparator + additional state
         * Default separator is ';' (encoded %3B).
         * In rare cases, this character might be forbidden or inconvenient to use by the issuer so it can be customized.
         */
        this.nonceStateSeparator = ';';
        /**
         * Set this to true to use HTTP BASIC auth for AJAX calls
         */
        this.useHttpBasicAuth = false;
        /**
         * The interceptors waits this time span if there is no token
         */
        this.waitForTokenInMsec = 0;
        /**
         * Code Flow is by defauld used together with PKCI which is also higly recommented.
         * You can disbale it here by setting this flag to true.
         * https://tools.ietf.org/html/rfc7636#section-1.1
         */
        this.disablePKCE = false;
        /**
         * This property allows you to override the method that is used to open the login url,
         * allowing a way for implementations to specify their own method of routing to new
         * urls.
         */
        this.openUri = uri => {
            location.href = uri;
        };
        if (json) {
            Object.assign(this, json);
        }
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYXV0aC5jb25maWcuanMiLCJzb3VyY2VSb290IjoiQzovVXNlcnMvZGllZ28uYXV5b24vUHJvamVjdHMvdGVsdXMvYW5ndWxhci1vYXV0aDItb2lkYy9wcm9qZWN0cy9saWIvc3JjLyIsInNvdXJjZXMiOlsiYXV0aC5jb25maWcudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsTUFBTSxPQUFPLFVBQVU7SUE2UHJCLFlBQVksSUFBMEI7UUE1UHRDOztXQUVHO1FBQ0ksYUFBUSxHQUFJLEVBQUUsQ0FBQztRQUV0Qjs7V0FFRztRQUNJLGdCQUFXLEdBQUksRUFBRSxDQUFDO1FBRXpCOzs7V0FHRztRQUNJLDBCQUFxQixHQUFJLEVBQUUsQ0FBQztRQUVuQzs7O1dBR0c7UUFDSSxhQUFRLEdBQUksRUFBRSxDQUFDO1FBRXRCOztXQUVHO1FBQ0ksVUFBSyxHQUFJLGdCQUFnQixDQUFDO1FBRTFCLGFBQVEsR0FBSSxFQUFFLENBQUM7UUFFZixXQUFNLEdBQUksRUFBRSxDQUFDO1FBRXBCOzs7V0FHRztRQUNJLFNBQUksR0FBSSxJQUFJLENBQUM7UUFFcEI7OztXQUdHO1FBQ0ksdUJBQWtCLEdBQUksSUFBSSxDQUFDO1FBRTNCLFlBQU8sR0FBUyxJQUFJLENBQUM7UUFFNUI7O1dBRUc7UUFDSSxXQUFNLEdBQUksRUFBRSxDQUFDO1FBRXBCOztXQUVHO1FBQ0ksY0FBUyxHQUFJLEVBQUUsQ0FBQztRQUV2Qjs7V0FFRztRQUNJLHdCQUFtQixHQUFJLElBQUksQ0FBQztRQUVuQzs7V0FFRztRQUNJLGtCQUFhLEdBQVksSUFBSSxDQUFDO1FBRXJDOztXQUVHO1FBQ0ksdUJBQWtCLEdBQVksSUFBSSxDQUFDO1FBRTFDOztXQUVHO1FBQ0ksMEJBQXFCLEdBQWMsRUFBRSxDQUFDO1FBRTdDOztXQUVHO1FBQ0kscUJBQWdCLEdBQVksSUFBSSxDQUFDO1FBRWpDLGlCQUFZLEdBQUksRUFBRSxDQUFDO1FBRTFCOzs7OztXQUtHO1FBQ0kseUJBQW9CLEdBQUksS0FBSyxDQUFDO1FBRXJDOztXQUVHO1FBQ0ksNkJBQXdCLEdBQUksRUFBRSxDQUFDO1FBRS9CLCtCQUEwQixHQUFJLEVBQUUsQ0FBQztRQUV4Qzs7O1dBR0c7UUFDSSw0QkFBdUIsR0FBSSxLQUFLLENBQUM7UUFFeEM7Ozs7V0FJRztRQUNJLHdCQUFtQixHQUFZLElBQUksR0FBRyxFQUFFLENBQUM7UUFFaEQ7O1dBRUc7UUFDSSx5QkFBb0IsR0FBWSxJQUFJLEdBQUcsRUFBRSxDQUFDO1FBRWpEOzs7Ozs7O1dBT0c7UUFDSSxzQkFBaUIsR0FBWSxJQUFJLENBQUM7UUFFekM7Ozs7O1dBS0c7UUFDSSxpQkFBWSxHQUE0QixZQUFZLENBQUM7UUFFNUQ7OztXQUdHO1FBQ0ksc0NBQWlDLEdBQUksSUFBSSxDQUFDO1FBRWpEOzs7O1dBSUc7UUFDSSxTQUFJLEdBQVksSUFBSSxDQUFDO1FBRTVCOzs7V0FHRztRQUNJLHNCQUFpQixHQUFZLElBQUksQ0FBQztRQUVsQyw0QkFBdUIsR0FBSSwwQ0FBMEMsQ0FBQztRQUU3RTs7OztXQUlHO1FBQ0ksa0JBQWEsR0FBSSxJQUFJLENBQUM7UUFFN0I7Ozs7V0FJRztRQUNJLHlCQUFvQixHQUFJLEtBQUssQ0FBQztRQUVyQzs7O1dBR0c7UUFDSSwwQkFBcUIsR0FBSSxDQUFDLEdBQUcsSUFBSSxDQUFDO1FBRXpDOztXQUVHO1FBQ0ksMEJBQXFCLEdBQVksSUFBSSxDQUFDO1FBRTdDOztXQUVHO1FBQ0ksMkJBQXNCLEdBQUkseUNBQXlDLENBQUM7UUFFM0U7Ozs7OztXQU1HO1FBQ0ksdUJBQWtCLEdBQUksS0FBSyxDQUFDO1FBRW5DOzs7V0FHRztRQUNJLHFCQUFnQixHQUFJLEtBQUssQ0FBQztRQUUxQixtQ0FBOEIsR0FBSSxLQUFLLENBQUM7UUFFL0M7OztXQUdHO1FBQ0ksb0JBQWUsR0FBSSxLQUFLLENBQUM7UUFTaEM7Ozs7O1dBS0c7UUFDSSx3QkFBbUIsR0FBSSxHQUFHLENBQUM7UUFFbEM7O1dBRUc7UUFDSSxxQkFBZ0IsR0FBSSxLQUFLLENBQUM7UUFPakM7O1dBRUc7UUFDSSx1QkFBa0IsR0FBSSxDQUFDLENBQUM7UUFVL0I7Ozs7V0FJRztRQUNJLGdCQUFXLEdBQUksS0FBSyxDQUFDO1FBUTVCOzs7O1dBSUc7UUFDSSxZQUFPLEdBQTJCLEdBQUcsQ0FBQyxFQUFFO1lBQzdDLFFBQVEsQ0FBQyxJQUFJLEdBQUcsR0FBRyxDQUFDO1FBQ3RCLENBQUMsQ0FBQztRQVpBLElBQUksSUFBSSxFQUFFO1lBQ1IsTUFBTSxDQUFDLE1BQU0sQ0FBQyxJQUFJLEVBQUUsSUFBSSxDQUFDLENBQUM7U0FDM0I7SUFDSCxDQUFDO0NBVUYiLCJzb3VyY2VzQ29udGVudCI6WyJleHBvcnQgY2xhc3MgQXV0aENvbmZpZyB7XHJcbiAgLyoqXHJcbiAgICogVGhlIGNsaWVudCdzIGlkIGFzIHJlZ2lzdGVyZWQgd2l0aCB0aGUgYXV0aCBzZXJ2ZXJcclxuICAgKi9cclxuICBwdWJsaWMgY2xpZW50SWQ/ID0gJyc7XHJcblxyXG4gIC8qKlxyXG4gICAqIFRoZSBjbGllbnQncyByZWRpcmVjdFVyaSBhcyByZWdpc3RlcmVkIHdpdGggdGhlIGF1dGggc2VydmVyXHJcbiAgICovXHJcbiAgcHVibGljIHJlZGlyZWN0VXJpPyA9ICcnO1xyXG5cclxuICAvKipcclxuICAgKiBBbiBvcHRpb25hbCBzZWNvbmQgcmVkaXJlY3RVcmkgd2hlcmUgdGhlIGF1dGggc2VydmVyXHJcbiAgICogcmVkaXJlY3RzIHRoZSB1c2VyIHRvIGFmdGVyIGxvZ2dpbmcgb3V0LlxyXG4gICAqL1xyXG4gIHB1YmxpYyBwb3N0TG9nb3V0UmVkaXJlY3RVcmk/ID0gJyc7XHJcblxyXG4gIC8qKlxyXG4gICAqIFRoZSBhdXRoIHNlcnZlcidzIGVuZHBvaW50IHRoYXQgYWxsb3dzIHRvIGxvZ1xyXG4gICAqIHRoZSB1c2VyIGluIHdoZW4gdXNpbmcgaW1wbGljaXQgZmxvdy5cclxuICAgKi9cclxuICBwdWJsaWMgbG9naW5Vcmw/ID0gJyc7XHJcblxyXG4gIC8qKlxyXG4gICAqIFRoZSByZXF1ZXN0ZWQgc2NvcGVzXHJcbiAgICovXHJcbiAgcHVibGljIHNjb3BlPyA9ICdvcGVuaWQgcHJvZmlsZSc7XHJcblxyXG4gIHB1YmxpYyByZXNvdXJjZT8gPSAnJztcclxuXHJcbiAgcHVibGljIHJuZ1VybD8gPSAnJztcclxuXHJcbiAgLyoqXHJcbiAgICogRGVmaW5lcyB3aGV0aGVyIHRvIHVzZSBPcGVuSWQgQ29ubmVjdCBkdXJpbmdcclxuICAgKiBpbXBsaWNpdCBmbG93LlxyXG4gICAqL1xyXG4gIHB1YmxpYyBvaWRjPyA9IHRydWU7XHJcblxyXG4gIC8qKlxyXG4gICAqIERlZmluZXMgd2hldGhlciB0byByZXF1ZXN0IGFuIGFjY2VzcyB0b2tlbiBkdXJpbmdcclxuICAgKiBpbXBsaWNpdCBmbG93LlxyXG4gICAqL1xyXG4gIHB1YmxpYyByZXF1ZXN0QWNjZXNzVG9rZW4/ID0gdHJ1ZTtcclxuXHJcbiAgcHVibGljIG9wdGlvbnM/OiBhbnkgPSBudWxsO1xyXG5cclxuICAvKipcclxuICAgKiBUaGUgaXNzdWVyJ3MgdXJpLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBpc3N1ZXI/ID0gJyc7XHJcblxyXG4gIC8qKlxyXG4gICAqIFRoZSBsb2dvdXQgdXJsLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBsb2dvdXRVcmw/ID0gJyc7XHJcblxyXG4gIC8qKlxyXG4gICAqIERlZmluZXMgd2hldGhlciB0byBjbGVhciB0aGUgaGFzaCBmcmFnbWVudCBhZnRlciBsb2dnaW5nIGluLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBjbGVhckhhc2hBZnRlckxvZ2luPyA9IHRydWU7XHJcblxyXG4gIC8qKlxyXG4gICAqIFVybCBvZiB0aGUgdG9rZW4gZW5kcG9pbnQgYXMgZGVmaW5lZCBieSBPcGVuSWQgQ29ubmVjdCBhbmQgT0F1dGggMi5cclxuICAgKi9cclxuICBwdWJsaWMgdG9rZW5FbmRwb2ludD86IHN0cmluZyA9IG51bGw7XHJcblxyXG4gIC8qKlxyXG4gICAqIFVybCBvZiB0aGUgcmV2b2NhdGlvbiBlbmRwb2ludCBhcyBkZWZpbmVkIGJ5IE9wZW5JZCBDb25uZWN0IGFuZCBPQXV0aCAyLlxyXG4gICAqL1xyXG4gIHB1YmxpYyByZXZvY2F0aW9uRW5kcG9pbnQ/OiBzdHJpbmcgPSBudWxsO1xyXG5cclxuICAvKipcclxuICAgKiBOYW1lcyBvZiBrbm93biBwYXJhbWV0ZXJzIHNlbnQgb3V0IGluIHRoZSBUb2tlblJlc3BvbnNlLiBodHRwczovL3Rvb2xzLmlldGYub3JnL2h0bWwvcmZjNjc0OSNzZWN0aW9uLTUuMVxyXG4gICAqL1xyXG4gIHB1YmxpYyBjdXN0b21Ub2tlblBhcmFtZXRlcnM/OiBzdHJpbmdbXSA9IFtdO1xyXG5cclxuICAvKipcclxuICAgKiBVcmwgb2YgdGhlIHVzZXJpbmZvIGVuZHBvaW50IGFzIGRlZmluZWQgYnkgT3BlbklkIENvbm5lY3QuXHJcbiAgICovXHJcbiAgcHVibGljIHVzZXJpbmZvRW5kcG9pbnQ/OiBzdHJpbmcgPSBudWxsO1xyXG5cclxuICBwdWJsaWMgcmVzcG9uc2VUeXBlPyA9ICcnO1xyXG5cclxuICAvKipcclxuICAgKiBEZWZpbmVzIHdoZXRoZXIgYWRkaXRpb25hbCBkZWJ1ZyBpbmZvcm1hdGlvbiBzaG91bGRcclxuICAgKiBiZSBzaG93biBhdCB0aGUgY29uc29sZS4gTm90ZSB0aGF0IGluIGNlcnRhaW4gYnJvd3NlcnNcclxuICAgKiB0aGUgdmVyYm9zaXR5IG9mIHRoZSBjb25zb2xlIG5lZWRzIHRvIGJlIGV4cGxpY2l0bHkgc2V0XHJcbiAgICogdG8gaW5jbHVkZSBEZWJ1ZyBsZXZlbCBtZXNzYWdlcy5cclxuICAgKi9cclxuICBwdWJsaWMgc2hvd0RlYnVnSW5mb3JtYXRpb24/ID0gZmFsc2U7XHJcblxyXG4gIC8qKlxyXG4gICAqIFRoZSByZWRpcmVjdCB1cmkgdXNlZCB3aGVuIGRvaW5nIHNpbGVudCByZWZyZXNoLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBzaWxlbnRSZWZyZXNoUmVkaXJlY3RVcmk/ID0gJyc7XHJcblxyXG4gIHB1YmxpYyBzaWxlbnRSZWZyZXNoTWVzc2FnZVByZWZpeD8gPSAnJztcclxuXHJcbiAgLyoqXHJcbiAgICogU2V0IHRoaXMgdG8gdHJ1ZSB0byBkaXNwbGF5IHRoZSBpZnJhbWUgdXNlZCBmb3JcclxuICAgKiBzaWxlbnQgcmVmcmVzaCBmb3IgZGVidWdnaW5nLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBzaWxlbnRSZWZyZXNoU2hvd0lGcmFtZT8gPSBmYWxzZTtcclxuXHJcbiAgLyoqXHJcbiAgICogVGltZW91dCBmb3Igc2lsZW50IHJlZnJlc2guXHJcbiAgICogQGludGVybmFsXHJcbiAgICogZGVwcmVhY3RlZCBiL2Mgb2YgdHlwbywgc2VlIHNpbGVudFJlZnJlc2hUaW1lb3V0XHJcbiAgICovXHJcbiAgcHVibGljIHNpbGV0UmVmcmVzaFRpbWVvdXQ/OiBudW1iZXIgPSAxMDAwICogMjA7XHJcblxyXG4gIC8qKlxyXG4gICAqIFRpbWVvdXQgZm9yIHNpbGVudCByZWZyZXNoLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBzaWxlbnRSZWZyZXNoVGltZW91dD86IG51bWJlciA9IDEwMDAgKiAyMDtcclxuXHJcbiAgLyoqXHJcbiAgICogU29tZSBhdXRoIHNlcnZlcnMgZG9uJ3QgYWxsb3cgdXNpbmcgcGFzc3dvcmQgZmxvd1xyXG4gICAqIHcvbyBhIGNsaWVudCBzZWNyZXQgd2hpbGUgdGhlIHN0YW5kYXJkcyBkbyBub3RcclxuICAgKiBkZW1hbmQgZm9yIGl0LiBJbiB0aGlzIGNhc2UsIHlvdSBjYW4gc2V0IGEgcGFzc3dvcmRcclxuICAgKiBoZXJlLiBBcyB0aGlzIHBhc3N3b3JkIGlzIGV4cG9zZWQgdG8gdGhlIHB1YmxpY1xyXG4gICAqIGl0IGRvZXMgbm90IGJyaW5nIGFkZGl0aW9uYWwgc2VjdXJpdHkgYW5kIGlzIHRoZXJlZm9yZVxyXG4gICAqIGFzIGdvb2QgYXMgdXNpbmcgbm8gcGFzc3dvcmQuXHJcbiAgICovXHJcbiAgcHVibGljIGR1bW15Q2xpZW50U2VjcmV0Pzogc3RyaW5nID0gbnVsbDtcclxuXHJcbiAgLyoqXHJcbiAgICogRGVmaW5lcyB3aGV0aGVyIGh0dHBzIGlzIHJlcXVpcmVkLlxyXG4gICAqIFRoZSBkZWZhdWx0IHZhbHVlIGlzIHJlbW90ZU9ubHkgd2hpY2ggb25seSBhbGxvd3NcclxuICAgKiBodHRwIGZvciBsb2NhbGhvc3QsIHdoaWxlIGV2ZXJ5IG90aGVyIGRvbWFpbnMgbmVlZFxyXG4gICAqIHRvIGJlIHVzZWQgd2l0aCBodHRwcy5cclxuICAgKi9cclxuICBwdWJsaWMgcmVxdWlyZUh0dHBzPzogYm9vbGVhbiB8ICdyZW1vdGVPbmx5JyA9ICdyZW1vdGVPbmx5JztcclxuXHJcbiAgLyoqXHJcbiAgICogRGVmaW5lcyB3aGV0aGVyIGV2ZXJ5IHVybCBwcm92aWRlZCBieSB0aGUgZGlzY292ZXJ5XHJcbiAgICogZG9jdW1lbnQgaGFzIHRvIHN0YXJ0IHdpdGggdGhlIGlzc3VlcidzIHVybC5cclxuICAgKi9cclxuICBwdWJsaWMgc3RyaWN0RGlzY292ZXJ5RG9jdW1lbnRWYWxpZGF0aW9uPyA9IHRydWU7XHJcblxyXG4gIC8qKlxyXG4gICAqIEpTT04gV2ViIEtleSBTZXQgKGh0dHBzOi8vdG9vbHMuaWV0Zi5vcmcvaHRtbC9yZmM3NTE3KVxyXG4gICAqIHdpdGgga2V5cyB1c2VkIHRvIHZhbGlkYXRlIHJlY2VpdmVkIGlkX3Rva2Vucy5cclxuICAgKiBUaGlzIGlzIHRha2VuIG91dCBvZiB0aGUgZGlzb3ZlcnkgZG9jdW1lbnQuIENhbiBiZSBzZXQgbWFudWFsbHkgdG9vLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBqd2tzPzogb2JqZWN0ID0gbnVsbDtcclxuXHJcbiAgLyoqXHJcbiAgICogTWFwIHdpdGggYWRkaXRpb25hbCBxdWVyeSBwYXJhbWV0ZXIgdGhhdCBhcmUgYXBwZW5kZWQgdG9cclxuICAgKiB0aGUgcmVxdWVzdCB3aGVuIGluaXRpYWxpemluZyBpbXBsaWNpdCBmbG93LlxyXG4gICAqL1xyXG4gIHB1YmxpYyBjdXN0b21RdWVyeVBhcmFtcz86IG9iamVjdCA9IG51bGw7XHJcblxyXG4gIHB1YmxpYyBzaWxlbnRSZWZyZXNoSUZyYW1lTmFtZT8gPSAnYW5ndWxhci1vYXV0aC1vaWRjLXNpbGVudC1yZWZyZXNoLWlmcmFtZSc7XHJcblxyXG4gIC8qKlxyXG4gICAqIERlZmluZXMgd2hlbiB0aGUgdG9rZW5fdGltZW91dCBldmVudCBzaG91bGQgYmUgcmFpc2VkLlxyXG4gICAqIElmIHlvdSBzZXQgdGhpcyB0byB0aGUgZGVmYXVsdCB2YWx1ZSAwLjc1LCB0aGUgZXZlbnRcclxuICAgKiBpcyB0cmlnZ2VyZWQgYWZ0ZXIgNzUlIG9mIHRoZSB0b2tlbidzIGxpZmUgdGltZS5cclxuICAgKi9cclxuICBwdWJsaWMgdGltZW91dEZhY3Rvcj8gPSAwLjc1O1xyXG5cclxuICAvKipcclxuICAgKiBJZiB0cnVlLCB0aGUgbGliIHdpbGwgdHJ5IHRvIGNoZWNrIHdoZXRoZXIgdGhlIHVzZXJcclxuICAgKiBpcyBzdGlsbCBsb2dnZWQgaW4gb24gYSByZWd1bGFyIGJhc2lzIGFzIGRlc2NyaWJlZFxyXG4gICAqIGluIGh0dHA6Ly9vcGVuaWQubmV0L3NwZWNzL29wZW5pZC1jb25uZWN0LXNlc3Npb24tMV8wLmh0bWwjQ2hhbmdlTm90aWZpY2F0aW9uXHJcbiAgICovXHJcbiAgcHVibGljIHNlc3Npb25DaGVja3NFbmFibGVkPyA9IGZhbHNlO1xyXG5cclxuICAvKipcclxuICAgKiBJbnRlcnZhbCBpbiBtc2VjIGZvciBjaGVja2luZyB0aGUgc2Vzc2lvblxyXG4gICAqIGFjY29yZGluZyB0byBodHRwOi8vb3BlbmlkLm5ldC9zcGVjcy9vcGVuaWQtY29ubmVjdC1zZXNzaW9uLTFfMC5odG1sI0NoYW5nZU5vdGlmaWNhdGlvblxyXG4gICAqL1xyXG4gIHB1YmxpYyBzZXNzaW9uQ2hlY2tJbnRlcnZhbGw/ID0gMyAqIDEwMDA7XHJcblxyXG4gIC8qKlxyXG4gICAqIFVybCBmb3IgdGhlIGlmcmFtZSB1c2VkIGZvciBzZXNzaW9uIGNoZWNrc1xyXG4gICAqL1xyXG4gIHB1YmxpYyBzZXNzaW9uQ2hlY2tJRnJhbWVVcmw/OiBzdHJpbmcgPSBudWxsO1xyXG5cclxuICAvKipcclxuICAgKiBOYW1lIG9mIHRoZSBpZnJhbWUgdG8gdXNlIGZvciBzZXNzaW9uIGNoZWNrc1xyXG4gICAqL1xyXG4gIHB1YmxpYyBzZXNzaW9uQ2hlY2tJRnJhbWVOYW1lPyA9ICdhbmd1bGFyLW9hdXRoLW9pZGMtY2hlY2stc2Vzc2lvbi1pZnJhbWUnO1xyXG5cclxuICAvKipcclxuICAgKiBUaGlzIHByb3BlcnR5IGhhcyBiZWVuIGludHJvZHVjZWQgdG8gZGlzYWJsZSBhdF9oYXNoIGNoZWNrc1xyXG4gICAqIGFuZCBpcyBpbmRlbnRlZCBmb3IgSWRlbnRpdHkgUHJvdmlkZXIgdGhhdCBkb2VzIG5vdCBkZWxpdmVyXHJcbiAgICogYW4gYXRfaGFzaCBFVkVOIFRIT1VHSCBpdHMgcmVjb21tZW5kZWQgYnkgdGhlIE9JREMgc3BlY3MuXHJcbiAgICogT2YgY291cnNlLCB3aGVuIGRpc2FibGluZyB0aGVzZSBjaGVja3MgdGhlIHdlIGFyZSBieXBhc3NpbmdcclxuICAgKiBhIHNlY3VyaXR5IGNoZWNrIHdoaWNoIG1lYW5zIHdlIGFyZSBtb3JlIHZ1bG5lcmFibGUuXHJcbiAgICovXHJcbiAgcHVibGljIGRpc2FibGVBdEhhc2hDaGVjaz8gPSBmYWxzZTtcclxuXHJcbiAgLyoqXHJcbiAgICogRGVmaW5lcyB3ZXRoZXIgdG8gY2hlY2sgdGhlIHN1YmplY3Qgb2YgYSByZWZyZXNoZWQgdG9rZW4gYWZ0ZXIgc2lsZW50IHJlZnJlc2guXHJcbiAgICogTm9ybWFsbHksIGl0IHNob3VsZCBiZSB0aGUgc2FtZSBhcyBiZWZvcmUuXHJcbiAgICovXHJcbiAgcHVibGljIHNraXBTdWJqZWN0Q2hlY2s/ID0gZmFsc2U7XHJcblxyXG4gIHB1YmxpYyB1c2VJZFRva2VuSGludEZvclNpbGVudFJlZnJlc2g/ID0gZmFsc2U7XHJcblxyXG4gIC8qKlxyXG4gICAqIERlZmluZWQgd2hldGhlciB0byBza2lwIHRoZSB2YWxpZGF0aW9uIG9mIHRoZSBpc3N1ZXIgaW4gdGhlIGRpc2NvdmVyeSBkb2N1bWVudC5cclxuICAgKiBOb3JtYWxseSwgdGhlIGRpc2NvdmV5IGRvY3VtZW50J3MgdXJsIHN0YXJ0cyB3aXRoIHRoZSB1cmwgb2YgdGhlIGlzc3Vlci5cclxuICAgKi9cclxuICBwdWJsaWMgc2tpcElzc3VlckNoZWNrPyA9IGZhbHNlO1xyXG5cclxuICAvKipcclxuICAgKiBBY2NvcmRpbmcgdG8gcmZjNjc0OSBpdCBpcyByZWNvbW1lbmRlZCAoYnV0IG5vdCByZXF1aXJlZCkgdGhhdCB0aGUgYXV0aFxyXG4gICAqIHNlcnZlciBleHBvc2VzIHRoZSBhY2Nlc3NfdG9rZW4ncyBsaWZlIHRpbWUgaW4gc2Vjb25kcy5cclxuICAgKiBUaGlzIGlzIGEgZmFsbGJhY2sgdmFsdWUgZm9yIHRoZSBjYXNlIHRoaXMgdmFsdWUgaXMgbm90IGV4cG9zZWQuXHJcbiAgICovXHJcbiAgcHVibGljIGZhbGxiYWNrQWNjZXNzVG9rZW5FeHBpcmF0aW9uVGltZUluU2VjPzogbnVtYmVyO1xyXG5cclxuICAvKipcclxuICAgKiBmaW5hbCBzdGF0ZSBzZW50IHRvIGlzc3VlciBpcyBidWlsdCBhcyBmb2xsb3dzOlxyXG4gICAqIHN0YXRlID0gbm9uY2UgKyBub25jZVN0YXRlU2VwYXJhdG9yICsgYWRkaXRpb25hbCBzdGF0ZVxyXG4gICAqIERlZmF1bHQgc2VwYXJhdG9yIGlzICc7JyAoZW5jb2RlZCAlM0IpLlxyXG4gICAqIEluIHJhcmUgY2FzZXMsIHRoaXMgY2hhcmFjdGVyIG1pZ2h0IGJlIGZvcmJpZGRlbiBvciBpbmNvbnZlbmllbnQgdG8gdXNlIGJ5IHRoZSBpc3N1ZXIgc28gaXQgY2FuIGJlIGN1c3RvbWl6ZWQuXHJcbiAgICovXHJcbiAgcHVibGljIG5vbmNlU3RhdGVTZXBhcmF0b3I/ID0gJzsnO1xyXG5cclxuICAvKipcclxuICAgKiBTZXQgdGhpcyB0byB0cnVlIHRvIHVzZSBIVFRQIEJBU0lDIGF1dGggZm9yIEFKQVggY2FsbHNcclxuICAgKi9cclxuICBwdWJsaWMgdXNlSHR0cEJhc2ljQXV0aD8gPSBmYWxzZTtcclxuXHJcbiAgLyoqXHJcbiAgICogVGhlIHdpbmRvdyBvZiB0aW1lIChpbiBzZWNvbmRzKSB0byBhbGxvdyB0aGUgY3VycmVudCB0aW1lIHRvIGRldmlhdGUgd2hlbiB2YWxpZGF0aW5nIGlkX3Rva2VuJ3MgaWF0IGFuZCBleHAgdmFsdWVzLlxyXG4gICAqL1xyXG4gIHB1YmxpYyBjbG9ja1NrZXdJblNlYz86IG51bWJlcjtcclxuXHJcbiAgLyoqXHJcbiAgICogVGhlIGludGVyY2VwdG9ycyB3YWl0cyB0aGlzIHRpbWUgc3BhbiBpZiB0aGVyZSBpcyBubyB0b2tlblxyXG4gICAqL1xyXG4gIHB1YmxpYyB3YWl0Rm9yVG9rZW5Jbk1zZWM/ID0gMDtcclxuXHJcbiAgLyoqXHJcbiAgICogU2V0IHRoaXMgdG8gdHJ1ZSBpZiB5b3Ugd2FudCB0byB1c2Ugc2lsZW50IHJlZnJlc2ggdG9nZXRoZXIgd2l0aFxyXG4gICAqIGNvZGUgZmxvdy4gQXMgc2lsZW50IHJlZnJlc2ggaXMgdGhlIG9ubHkgb3B0aW9uIGZvciByZWZyZXNoaW5nXHJcbiAgICogd2l0aCBpbXBsaWNpdCBmbG93LCB5b3UgZG9uJ3QgbmVlZCB0byBleHBsaWNpdGx5IHR1cm4gaXQgb24gaW5cclxuICAgKiB0aGlzIGNhc2UuXHJcbiAgICovXHJcbiAgcHVibGljIHVzZVNpbGVudFJlZnJlc2g/O1xyXG5cclxuICAvKipcclxuICAgKiBDb2RlIEZsb3cgaXMgYnkgZGVmYXVsZCB1c2VkIHRvZ2V0aGVyIHdpdGggUEtDSSB3aGljaCBpcyBhbHNvIGhpZ2x5IHJlY29tbWVudGVkLlxyXG4gICAqIFlvdSBjYW4gZGlzYmFsZSBpdCBoZXJlIGJ5IHNldHRpbmcgdGhpcyBmbGFnIHRvIHRydWUuXHJcbiAgICogaHR0cHM6Ly90b29scy5pZXRmLm9yZy9odG1sL3JmYzc2MzYjc2VjdGlvbi0xLjFcclxuICAgKi9cclxuICBwdWJsaWMgZGlzYWJsZVBLQ0U/ID0gZmFsc2U7XHJcblxyXG4gIGNvbnN0cnVjdG9yKGpzb24/OiBQYXJ0aWFsPEF1dGhDb25maWc+KSB7XHJcbiAgICBpZiAoanNvbikge1xyXG4gICAgICBPYmplY3QuYXNzaWduKHRoaXMsIGpzb24pO1xyXG4gICAgfVxyXG4gIH1cclxuXHJcbiAgLyoqXHJcbiAgICogVGhpcyBwcm9wZXJ0eSBhbGxvd3MgeW91IHRvIG92ZXJyaWRlIHRoZSBtZXRob2QgdGhhdCBpcyB1c2VkIHRvIG9wZW4gdGhlIGxvZ2luIHVybCxcclxuICAgKiBhbGxvd2luZyBhIHdheSBmb3IgaW1wbGVtZW50YXRpb25zIHRvIHNwZWNpZnkgdGhlaXIgb3duIG1ldGhvZCBvZiByb3V0aW5nIHRvIG5ld1xyXG4gICAqIHVybHMuXHJcbiAgICovXHJcbiAgcHVibGljIG9wZW5Vcmk/OiAodXJpOiBzdHJpbmcpID0+IHZvaWQgPSB1cmkgPT4ge1xyXG4gICAgbG9jYXRpb24uaHJlZiA9IHVyaTtcclxuICB9O1xyXG59XHJcbiJdfQ==