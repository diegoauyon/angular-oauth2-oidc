import { OAuthStorage, OAuthLogger } from './types';
import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { HTTP_INTERCEPTORS } from '@angular/common/http';
import { OAuthService } from './oauth-service';
import { UrlHelperService } from './url-helper.service';
import { OAuthModuleConfig } from './oauth-module.config';
import { OAuthResourceServerErrorHandler, OAuthNoopResourceServerErrorHandler } from './interceptors/resource-server-error-handler';
import { DefaultOAuthInterceptor } from './interceptors/default-oauth.interceptor';
import { ValidationHandler } from './token-validation/validation-handler';
import { NullValidationHandler } from './token-validation/null-validation-handler';
import { createDefaultLogger, createDefaultStorage } from './factories';
import { HashHandler, DefaultHashHandler } from './token-validation/hash-handler';
export class OAuthModule {
    static forRoot(config = null, validationHandlerClass = NullValidationHandler) {
        return {
            ngModule: OAuthModule,
            providers: [
                OAuthService,
                UrlHelperService,
                { provide: OAuthLogger, useFactory: createDefaultLogger },
                { provide: OAuthStorage, useFactory: createDefaultStorage },
                { provide: ValidationHandler, useClass: validationHandlerClass },
                { provide: HashHandler, useClass: DefaultHashHandler },
                {
                    provide: OAuthResourceServerErrorHandler,
                    useClass: OAuthNoopResourceServerErrorHandler
                },
                { provide: OAuthModuleConfig, useValue: config },
                {
                    provide: HTTP_INTERCEPTORS,
                    useClass: DefaultOAuthInterceptor,
                    multi: true
                }
            ]
        };
    }
}
OAuthModule.decorators = [
    { type: NgModule, args: [{
                imports: [CommonModule],
                declarations: [],
                exports: []
            },] }
];
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiYW5ndWxhci1vYXV0aC1vaWRjLm1vZHVsZS5qcyIsInNvdXJjZVJvb3QiOiJDOi9Vc2Vycy9kaWVnby5hdXlvbi9Qcm9qZWN0cy90ZWx1cy9hbmd1bGFyLW9hdXRoMi1vaWRjL3Byb2plY3RzL2xpYi9zcmMvIiwic291cmNlcyI6WyJhbmd1bGFyLW9hdXRoLW9pZGMubW9kdWxlLnRzIl0sIm5hbWVzIjpbXSwibWFwcGluZ3MiOiJBQUFBLE9BQU8sRUFBRSxZQUFZLEVBQUUsV0FBVyxFQUFFLE1BQU0sU0FBUyxDQUFDO0FBQ3BELE9BQU8sRUFBRSxRQUFRLEVBQXVCLE1BQU0sZUFBZSxDQUFDO0FBQzlELE9BQU8sRUFBRSxZQUFZLEVBQUUsTUFBTSxpQkFBaUIsQ0FBQztBQUMvQyxPQUFPLEVBQUUsaUJBQWlCLEVBQUUsTUFBTSxzQkFBc0IsQ0FBQztBQUV6RCxPQUFPLEVBQUUsWUFBWSxFQUFFLE1BQU0saUJBQWlCLENBQUM7QUFDL0MsT0FBTyxFQUFFLGdCQUFnQixFQUFFLE1BQU0sc0JBQXNCLENBQUM7QUFFeEQsT0FBTyxFQUFFLGlCQUFpQixFQUFFLE1BQU0sdUJBQXVCLENBQUM7QUFDMUQsT0FBTyxFQUNMLCtCQUErQixFQUMvQixtQ0FBbUMsRUFDcEMsTUFBTSw4Q0FBOEMsQ0FBQztBQUN0RCxPQUFPLEVBQUUsdUJBQXVCLEVBQUUsTUFBTSwwQ0FBMEMsQ0FBQztBQUNuRixPQUFPLEVBQUUsaUJBQWlCLEVBQUUsTUFBTSx1Q0FBdUMsQ0FBQztBQUMxRSxPQUFPLEVBQUUscUJBQXFCLEVBQUUsTUFBTSw0Q0FBNEMsQ0FBQztBQUNuRixPQUFPLEVBQUUsbUJBQW1CLEVBQUUsb0JBQW9CLEVBQUUsTUFBTSxhQUFhLENBQUM7QUFDeEUsT0FBTyxFQUNMLFdBQVcsRUFDWCxrQkFBa0IsRUFDbkIsTUFBTSxpQ0FBaUMsQ0FBQztBQU96QyxNQUFNLE9BQU8sV0FBVztJQUN0QixNQUFNLENBQUMsT0FBTyxDQUNaLFNBQTRCLElBQUksRUFDaEMsc0JBQXNCLEdBQUcscUJBQXFCO1FBRTlDLE9BQU87WUFDTCxRQUFRLEVBQUUsV0FBVztZQUNyQixTQUFTLEVBQUU7Z0JBQ1QsWUFBWTtnQkFDWixnQkFBZ0I7Z0JBQ2hCLEVBQUUsT0FBTyxFQUFFLFdBQVcsRUFBRSxVQUFVLEVBQUUsbUJBQW1CLEVBQUU7Z0JBQ3pELEVBQUUsT0FBTyxFQUFFLFlBQVksRUFBRSxVQUFVLEVBQUUsb0JBQW9CLEVBQUU7Z0JBQzNELEVBQUUsT0FBTyxFQUFFLGlCQUFpQixFQUFFLFFBQVEsRUFBRSxzQkFBc0IsRUFBRTtnQkFDaEUsRUFBRSxPQUFPLEVBQUUsV0FBVyxFQUFFLFFBQVEsRUFBRSxrQkFBa0IsRUFBRTtnQkFDdEQ7b0JBQ0UsT0FBTyxFQUFFLCtCQUErQjtvQkFDeEMsUUFBUSxFQUFFLG1DQUFtQztpQkFDOUM7Z0JBQ0QsRUFBRSxPQUFPLEVBQUUsaUJBQWlCLEVBQUUsUUFBUSxFQUFFLE1BQU0sRUFBRTtnQkFDaEQ7b0JBQ0UsT0FBTyxFQUFFLGlCQUFpQjtvQkFDMUIsUUFBUSxFQUFFLHVCQUF1QjtvQkFDakMsS0FBSyxFQUFFLElBQUk7aUJBQ1o7YUFDRjtTQUNGLENBQUM7SUFDSixDQUFDOzs7WUEvQkYsUUFBUSxTQUFDO2dCQUNSLE9BQU8sRUFBRSxDQUFDLFlBQVksQ0FBQztnQkFDdkIsWUFBWSxFQUFFLEVBQUU7Z0JBQ2hCLE9BQU8sRUFBRSxFQUFFO2FBQ1oiLCJzb3VyY2VzQ29udGVudCI6WyJpbXBvcnQgeyBPQXV0aFN0b3JhZ2UsIE9BdXRoTG9nZ2VyIH0gZnJvbSAnLi90eXBlcyc7XHJcbmltcG9ydCB7IE5nTW9kdWxlLCBNb2R1bGVXaXRoUHJvdmlkZXJzIH0gZnJvbSAnQGFuZ3VsYXIvY29yZSc7XHJcbmltcG9ydCB7IENvbW1vbk1vZHVsZSB9IGZyb20gJ0Bhbmd1bGFyL2NvbW1vbic7XHJcbmltcG9ydCB7IEhUVFBfSU5URVJDRVBUT1JTIH0gZnJvbSAnQGFuZ3VsYXIvY29tbW9uL2h0dHAnO1xyXG5cclxuaW1wb3J0IHsgT0F1dGhTZXJ2aWNlIH0gZnJvbSAnLi9vYXV0aC1zZXJ2aWNlJztcclxuaW1wb3J0IHsgVXJsSGVscGVyU2VydmljZSB9IGZyb20gJy4vdXJsLWhlbHBlci5zZXJ2aWNlJztcclxuXHJcbmltcG9ydCB7IE9BdXRoTW9kdWxlQ29uZmlnIH0gZnJvbSAnLi9vYXV0aC1tb2R1bGUuY29uZmlnJztcclxuaW1wb3J0IHtcclxuICBPQXV0aFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyLFxyXG4gIE9BdXRoTm9vcFJlc291cmNlU2VydmVyRXJyb3JIYW5kbGVyXHJcbn0gZnJvbSAnLi9pbnRlcmNlcHRvcnMvcmVzb3VyY2Utc2VydmVyLWVycm9yLWhhbmRsZXInO1xyXG5pbXBvcnQgeyBEZWZhdWx0T0F1dGhJbnRlcmNlcHRvciB9IGZyb20gJy4vaW50ZXJjZXB0b3JzL2RlZmF1bHQtb2F1dGguaW50ZXJjZXB0b3InO1xyXG5pbXBvcnQgeyBWYWxpZGF0aW9uSGFuZGxlciB9IGZyb20gJy4vdG9rZW4tdmFsaWRhdGlvbi92YWxpZGF0aW9uLWhhbmRsZXInO1xyXG5pbXBvcnQgeyBOdWxsVmFsaWRhdGlvbkhhbmRsZXIgfSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vbnVsbC12YWxpZGF0aW9uLWhhbmRsZXInO1xyXG5pbXBvcnQgeyBjcmVhdGVEZWZhdWx0TG9nZ2VyLCBjcmVhdGVEZWZhdWx0U3RvcmFnZSB9IGZyb20gJy4vZmFjdG9yaWVzJztcclxuaW1wb3J0IHtcclxuICBIYXNoSGFuZGxlcixcclxuICBEZWZhdWx0SGFzaEhhbmRsZXJcclxufSBmcm9tICcuL3Rva2VuLXZhbGlkYXRpb24vaGFzaC1oYW5kbGVyJztcclxuXHJcbkBOZ01vZHVsZSh7XHJcbiAgaW1wb3J0czogW0NvbW1vbk1vZHVsZV0sXHJcbiAgZGVjbGFyYXRpb25zOiBbXSxcclxuICBleHBvcnRzOiBbXVxyXG59KVxyXG5leHBvcnQgY2xhc3MgT0F1dGhNb2R1bGUge1xyXG4gIHN0YXRpYyBmb3JSb290KFxyXG4gICAgY29uZmlnOiBPQXV0aE1vZHVsZUNvbmZpZyA9IG51bGwsXHJcbiAgICB2YWxpZGF0aW9uSGFuZGxlckNsYXNzID0gTnVsbFZhbGlkYXRpb25IYW5kbGVyXHJcbiAgKTogTW9kdWxlV2l0aFByb3ZpZGVyczxPQXV0aE1vZHVsZT4ge1xyXG4gICAgcmV0dXJuIHtcclxuICAgICAgbmdNb2R1bGU6IE9BdXRoTW9kdWxlLFxyXG4gICAgICBwcm92aWRlcnM6IFtcclxuICAgICAgICBPQXV0aFNlcnZpY2UsXHJcbiAgICAgICAgVXJsSGVscGVyU2VydmljZSxcclxuICAgICAgICB7IHByb3ZpZGU6IE9BdXRoTG9nZ2VyLCB1c2VGYWN0b3J5OiBjcmVhdGVEZWZhdWx0TG9nZ2VyIH0sXHJcbiAgICAgICAgeyBwcm92aWRlOiBPQXV0aFN0b3JhZ2UsIHVzZUZhY3Rvcnk6IGNyZWF0ZURlZmF1bHRTdG9yYWdlIH0sXHJcbiAgICAgICAgeyBwcm92aWRlOiBWYWxpZGF0aW9uSGFuZGxlciwgdXNlQ2xhc3M6IHZhbGlkYXRpb25IYW5kbGVyQ2xhc3MgfSxcclxuICAgICAgICB7IHByb3ZpZGU6IEhhc2hIYW5kbGVyLCB1c2VDbGFzczogRGVmYXVsdEhhc2hIYW5kbGVyIH0sXHJcbiAgICAgICAge1xyXG4gICAgICAgICAgcHJvdmlkZTogT0F1dGhSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlcixcclxuICAgICAgICAgIHVzZUNsYXNzOiBPQXV0aE5vb3BSZXNvdXJjZVNlcnZlckVycm9ySGFuZGxlclxyXG4gICAgICAgIH0sXHJcbiAgICAgICAgeyBwcm92aWRlOiBPQXV0aE1vZHVsZUNvbmZpZywgdXNlVmFsdWU6IGNvbmZpZyB9LFxyXG4gICAgICAgIHtcclxuICAgICAgICAgIHByb3ZpZGU6IEhUVFBfSU5URVJDRVBUT1JTLFxyXG4gICAgICAgICAgdXNlQ2xhc3M6IERlZmF1bHRPQXV0aEludGVyY2VwdG9yLFxyXG4gICAgICAgICAgbXVsdGk6IHRydWVcclxuICAgICAgICB9XHJcbiAgICAgIF1cclxuICAgIH07XHJcbiAgfVxyXG59XHJcbiJdfQ==