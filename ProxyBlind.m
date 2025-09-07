// ProxyBlind.m
// 目标：让 App 感知不到代理；放过证书校验以便中间人抓包。
// 依赖：fishhook （把 fishhook.c / fishhook.h 放同目录）

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import "fishhook.h"

#pragma mark - 工具

static CFDictionaryRef CFDictRetainBridge(NSDictionary *d) {
    return (CFDictionaryRef)CFRetain((__bridge CFTypeRef)(d ?: @{}));
}
static NSDictionary *EmptyProxyDict(void) {
    return @{
        (__bridge NSString *)kCFNetworkProxiesHTTPEnable: @0,
        (__bridge NSString *)kCFNetworkProxiesHTTPSEnable: @0,
        (__bridge NSString *)kCFNetworkProxiesSOCKSEnable: @0,
    };
}

#pragma mark - ① 伪装：系统“无代理”

// CFNetworkCopySystemProxySettings -> 返回“无代理”
typedef CFDictionaryRef (*PFN_CFNetworkCopySystemProxySettings)(void);
static PFN_CFNetworkCopySystemProxySettings orig_CFNetworkCopySystemProxySettings = NULL;
static CFDictionaryRef fake_CFNetworkCopySystemProxySettings(void) {
    return CFDictRetainBridge(EmptyProxyDict());
}

// 额外覆盖：SCDynamicStoreCopyProxies / CFNetworkCopyProxiesForURL
typedef CFDictionaryRef (*PFN_SCDynamicStoreCopyProxies)(void *);
static PFN_SCDynamicStoreCopyProxies orig_SCDynamicStoreCopyProxies = NULL;
static CFDictionaryRef fake_SCDynamicStoreCopyProxies(void *store) {
    return CFDictRetainBridge(EmptyProxyDict());
}

typedef CFArrayRef (*PFN_CFNetworkCopyProxiesForURL)(CFURLRef, CFDictionaryRef);
static PFN_CFNetworkCopyProxiesForURL orig_CFNetworkCopyProxiesForURL = NULL;
static CFArrayRef fake_CFNetworkCopyProxiesForURL(CFURLRef url, CFDictionaryRef proxySettings) {
    // 返回空数组：表示“没有可用代理”
    CFArrayRef empty = CFArrayCreate(kCFAllocatorDefault, NULL, 0, &kCFTypeArrayCallBacks);
    return empty;
}

// getenv("http_proxy"/"https_proxy"/"all_proxy") -> NULL
static char *(*orig_getenv)(const char *) = NULL;
static char *fake_getenv(const char *name) {
    if (name) {
        if (!strcasecmp(name, "http_proxy") ||
            !strcasecmp(name, "https_proxy") ||
            !strcasecmp(name, "all_proxy")  ||
            !strcasecmp(name, "HTTP_PROXY") ||
            !strcasecmp(name, "HTTPS_PROXY")||
            !strcasecmp(name, "ALL_PROXY")) {
            return NULL;
        }
    }
    return orig_getenv ? orig_getenv(name) : NULL;
}

#pragma mark - ② 放过 HTTPS 证书校验（Pinning 绕过）

// iOS 13+ 新接口
typedef bool (*PFN_SecTrustEvaluateWithError)(SecTrustRef, CFErrorRef *);
static PFN_SecTrustEvaluateWithError orig_SecTrustEvaluateWithError = NULL;
static bool fake_SecTrustEvaluateWithError(SecTrustRef trust, CFErrorRef *error) {
    return true; // 直接通过
}

// 旧接口（某些三方库仍调用）
typedef OSStatus (*PFN_SecTrustEvaluate)(SecTrustRef, SecTrustResultType *);
static PFN_SecTrustEvaluate orig_SecTrustEvaluate = NULL;
static OSStatus fake_SecTrustEvaluate(SecTrustRef trust, SecTrustResultType *result) {
    if (result) *result = kSecTrustResultProceed;
    return errSecSuccess;
}

// 兜底：NSURLSession challenge → 直接使用凭据
static void (*orig_NSURLSession_delegate_challenge)(id, SEL, NSURLSession*, NSURLAuthenticationChallenge*, void(^)(NSURLSessionAuthChallengeDisposition, NSURLCredential*)) = NULL;

static void swz_NSURLSession_delegate_challenge(id self, SEL _cmd,
                                                NSURLSession *session,
                                                NSURLAuthenticationChallenge *challenge,
                                                void (^completionHandler)(NSURLSessionAuthChallengeDisposition, NSURLCredential *)) {
    SecTrustRef trust = challenge.protectionSpace.serverTrust;
    if (trust && completionHandler) {
        NSURLCredential *cred = [NSURLCredential credentialForTrust:trust];
        completionHandler(NSURLSessionAuthChallengeUseCredential, cred);
        return;
    }
    if (orig_NSURLSession_delegate_challenge) {
        orig_NSURLSession_delegate_challenge(self, _cmd, session, challenge, completionHandler);
    }
}

#pragma mark - 安装

__attribute__((constructor))
static void _proxyblind_init(void) {
    @autoreleasepool {
        // fishhook 绑定
        struct rebinding rbs[] = {
            {"CFNetworkCopySystemProxySettings", (void *)fake_CFNetworkCopySystemProxySettings, (void **)&orig_CFNetworkCopySystemProxySettings},
            {"SCDynamicStoreCopyProxies",        (void *)fake_SCDynamicStoreCopyProxies,        (void **)&orig_SCDynamicStoreCopyProxies},
            {"CFNetworkCopyProxiesForURL",       (void *)fake_CFNetworkCopyProxiesForURL,       (void **)&orig_CFNetworkCopyProxiesForURL},
            {"getenv",                            (void *)fake_getenv,                           (void **)&orig_getenv},
            {"SecTrustEvaluateWithError",         (void *)fake_SecTrustEvaluateWithError,        (void **)&orig_SecTrustEvaluateWithError},
            {"SecTrustEvaluate",                  (void *)fake_SecTrustEvaluate,                 (void **)&orig_SecTrustEvaluate},
        };
        rebind_symbols(rbs, sizeof(rbs)/sizeof(rbs[0]));

        // swizzle NSURLSession 的 challenge 兜底（有些库走 delegate）
        Class cls = NSClassFromString(@"NSURLSession");
        SEL sel = NSSelectorFromString(@"URLSession:didReceiveChallenge:completionHandler:");
        Method m = cls ? class_getInstanceMethod(cls, sel) : NULL;
        if (m) {
            orig_NSURLSession_delegate_challenge = (void *)method_getImplementation(m);
            method_setImplementation(m, (IMP)swz_NSURLSession_delegate_challenge);
        }
    }
}
