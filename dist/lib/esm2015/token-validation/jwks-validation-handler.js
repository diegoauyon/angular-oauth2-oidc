import { NullValidationHandler } from './null-validation-handler';
const err = `PLEASE READ THIS CAREFULLY:

Beginning with angular-oauth2-oidc version 9, the JwksValidationHandler
has been moved to an library of its own. If you need it for implementing
OAuth2/OIDC **implicit flow**, please install it using npm:

  npm i angular-oauth2-oidc-jwks --save

After that, you can import it into your application:

  import { JwksValidationHandler } from 'angular-oauth2-oidc-jwks';

Please note, that this dependency is not needed for the **code flow**,
which is nowadays the **recommented** one for single page applications.
This also results in smaller bundle sizes.
`;
/**
 * This is just a dummy of the JwksValidationHandler
 * telling the users that the real one has been moved
 * to an library of its own, namely angular-oauth2-oidc-utils
 */
export class JwksValidationHandler extends NullValidationHandler {
    constructor() {
        super();
        console.error(err);
    }
}
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiandrcy12YWxpZGF0aW9uLWhhbmRsZXIuanMiLCJzb3VyY2VSb290IjoiIiwic291cmNlcyI6WyIuLi8uLi8uLi8uLi9wcm9qZWN0cy9saWIvc3JjL3Rva2VuLXZhbGlkYXRpb24vandrcy12YWxpZGF0aW9uLWhhbmRsZXIudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUEsT0FBTyxFQUFFLHFCQUFxQixFQUFFLE1BQU0sMkJBQTJCLENBQUM7QUFFbEUsTUFBTSxHQUFHLEdBQUc7Ozs7Ozs7Ozs7Ozs7OztDQWVYLENBQUM7QUFFRjs7OztHQUlHO0FBQ0gsTUFBTSxPQUFPLHFCQUFzQixTQUFRLHFCQUFxQjtJQUM5RDtRQUNFLEtBQUssRUFBRSxDQUFDO1FBQ1IsT0FBTyxDQUFDLEtBQUssQ0FBQyxHQUFHLENBQUMsQ0FBQztJQUNyQixDQUFDO0NBQ0YiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBOdWxsVmFsaWRhdGlvbkhhbmRsZXIgfSBmcm9tICcuL251bGwtdmFsaWRhdGlvbi1oYW5kbGVyJztcclxuXHJcbmNvbnN0IGVyciA9IGBQTEVBU0UgUkVBRCBUSElTIENBUkVGVUxMWTpcclxuXHJcbkJlZ2lubmluZyB3aXRoIGFuZ3VsYXItb2F1dGgyLW9pZGMgdmVyc2lvbiA5LCB0aGUgSndrc1ZhbGlkYXRpb25IYW5kbGVyXHJcbmhhcyBiZWVuIG1vdmVkIHRvIGFuIGxpYnJhcnkgb2YgaXRzIG93bi4gSWYgeW91IG5lZWQgaXQgZm9yIGltcGxlbWVudGluZ1xyXG5PQXV0aDIvT0lEQyAqKmltcGxpY2l0IGZsb3cqKiwgcGxlYXNlIGluc3RhbGwgaXQgdXNpbmcgbnBtOlxyXG5cclxuICBucG0gaSBhbmd1bGFyLW9hdXRoMi1vaWRjLWp3a3MgLS1zYXZlXHJcblxyXG5BZnRlciB0aGF0LCB5b3UgY2FuIGltcG9ydCBpdCBpbnRvIHlvdXIgYXBwbGljYXRpb246XHJcblxyXG4gIGltcG9ydCB7IEp3a3NWYWxpZGF0aW9uSGFuZGxlciB9IGZyb20gJ2FuZ3VsYXItb2F1dGgyLW9pZGMtandrcyc7XHJcblxyXG5QbGVhc2Ugbm90ZSwgdGhhdCB0aGlzIGRlcGVuZGVuY3kgaXMgbm90IG5lZWRlZCBmb3IgdGhlICoqY29kZSBmbG93KiosXHJcbndoaWNoIGlzIG5vd2FkYXlzIHRoZSAqKnJlY29tbWVudGVkKiogb25lIGZvciBzaW5nbGUgcGFnZSBhcHBsaWNhdGlvbnMuXHJcblRoaXMgYWxzbyByZXN1bHRzIGluIHNtYWxsZXIgYnVuZGxlIHNpemVzLlxyXG5gO1xyXG5cclxuLyoqXHJcbiAqIFRoaXMgaXMganVzdCBhIGR1bW15IG9mIHRoZSBKd2tzVmFsaWRhdGlvbkhhbmRsZXJcclxuICogdGVsbGluZyB0aGUgdXNlcnMgdGhhdCB0aGUgcmVhbCBvbmUgaGFzIGJlZW4gbW92ZWRcclxuICogdG8gYW4gbGlicmFyeSBvZiBpdHMgb3duLCBuYW1lbHkgYW5ndWxhci1vYXV0aDItb2lkYy11dGlsc1xyXG4gKi9cclxuZXhwb3J0IGNsYXNzIEp3a3NWYWxpZGF0aW9uSGFuZGxlciBleHRlbmRzIE51bGxWYWxpZGF0aW9uSGFuZGxlciB7XHJcbiAgY29uc3RydWN0b3IoKSB7XHJcbiAgICBzdXBlcigpO1xyXG4gICAgY29uc29sZS5lcnJvcihlcnIpO1xyXG4gIH1cclxufVxyXG4iXX0=