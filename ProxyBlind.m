// ProxyBlind.m  —  无日志，只在安装时弹窗一次“已生效”
// 需要同目录 fishhook.c / fishhook.h

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#import <UIKit/UIKit.h>
#import "fishhook.h"

#pragma mark - 弹窗（只弹一次）

static void PopupOnce(NSString *title, NSString *msg) {
    static BOOL shown = NO;
    if (shown) return;
    shown = YES;
    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *a = [UIAlertController alertControllerWithTitle:title
                                                                   message:msg
                                                            preferredStyle:UIAlertControllerStyleAlert];
        [a addAction:[UIAlertAction actionWithTitle:@"知道了" style:UIAlertActionStyleDefault handler:nil]];
        UIWindow *win = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
        UIViewController *vc = win.rootViewController;
        while (vc.presentedViewController) vc = vc.presentedViewController;
        [vc presentViewController:a animated:YES completion:nil];
    });
}

#pragma mark - 工具

static CFDictionaryRef CFRetainBridge(NSDictionary *d) {
    return (CFDictionaryRef)CFRetain((__bridge CFTypeRef)(d ?: @{}));
}
static NSDictionary *EmptyProxyDict(void) {
    return @{
        (__bridge NSString *)kCFNetworkProxiesHTTPEnable:  @0,
        (__bridge NSString *)kCFNetworkProxiesHTTPSEnable: @0,
        (__bridge NSString *)kCFNetworkProxiesSOCKSEnable: @0,
    };
}

#pragma mark - ① CFNetwork：系统级代理清空

typedef CFDictionaryRef (*PFN_CFNetworkCopySystemProxySettings)(void);
static PFN_CFNetworkCopySystemProxySettings orig_CFNetworkCopySystemProxySettings;
static CFDictionaryRef fake_CFNetworkCopySystemProxySettings(void) {
    return CFRetainBridge(EmptyProxyDict());
}

typedef CFDictionaryRef (*PFN_SCDynamicStoreCopyProxies)(void *store);
static PFN_SCDynamicStoreCopyProxies orig_SCDynamicStoreCopyProxies;
static CFDictionaryRef fake_SCDynamicStoreCopyProxies(void *store) {
    return CFRetainBridge(EmptyProxyDict());
}

typedef CFArrayRef (*PFN_CFNetworkCopyProxiesForURL)(CFURLRef, CFDictionaryRef);
static PFN_CFNetworkCopyProxiesForURL orig_CFNetworkCopyProxiesForURL;
static CFArrayRef fake_CFNetworkCopyProxiesForURL(CFURLRef url, CFDictionaryRef settings) {
    return CFArrayCreate(kCFAllocatorDefault, NULL, 0, &kCFTypeArrayCallBacks);
}

#pragma mark - ② 环境变量：getenv 系

static char *(*orig_getenv)(const char *name);
static char *fake_getenv(const char *name) {
    if (!name) return NULL;
    if (!strncasecmp(name, "http_proxy", 10) ||
        !strncasecmp(name, "https_proxy",11) ||
        !strncasecmp(name, "all_proxy",  9) ||
        !strncasecmp(name, "HTTP_PROXY",10) ||
        !strncasecmp(name, "HTTPS_PROXY",11) ||
        !strncasecmp(name, "ALL_PROXY",  9)) {
        return NULL;
    }
    return orig_getenv(name);
}

#pragma mark - ③ 会话级：NSURLSessionConfiguration

static NSURLSessionConfiguration* (*orig_defCfg)(id, SEL);
static NSURLSessionConfiguration* (*orig_ephCfg)(id, SEL);

static NSURLSessionConfiguration* sanitizeCfg(NSURLSessionConfiguration *cfg) {
    if (!cfg) return cfg;
    // 清空代理字典
    cfg.connectionProxyDictionary = @{};
    // 兼容某些私有字段
    @try { [cfg setValue:EmptyProxyDict() forKey:@"_connectionProxyDictionary"]; } @catch (...) {}
    return cfg;
}
static NSURLSessionConfiguration* swz_defCfg(id self, SEL _cmd) {
    return sanitizeCfg(orig_defCfg(self, _cmd));
}
static NSURLSessionConfiguration* swz_ephCfg(id self, SEL _cmd) {
    return sanitizeCfg(orig_ephCfg(self, _cmd));
}

#pragma mark - ④ 兜底：CFStream 属性级

typedef CFTypeRef (*PFN_CFReadStreamCopyProperty)(CFReadStreamRef, CFStringRef);
static PFN_CFReadStreamCopyProperty orig_CFReadStreamCopyProperty;

static CFTypeRef fake_CFReadStreamCopyProperty(CFReadStreamRef stream, CFStringRef propName) {
    if (propName == kCFStreamPropertyHTTPProxy ||
        propName == kCFStreamPropertySOCKSProxy ||
        CFEqual(propName, CFSTR("kCFStreamPropertyHTTPSProxy"))) {
        return CFRetainBridge(EmptyProxyDict());
    }
    return orig_CFReadStreamCopyProperty ? orig_CFReadStreamCopyProperty(stream, propName) : NULL;
}

#pragma mark - 安装 Hook

__attribute__((constructor))
static void _proxy_blind_init(void) {
    @autoreleasepool {
        // ① CFNetwork 钩子
        rebind_symbols((struct rebinding[3]){
            {"CFNetworkCopySystemProxySettings", (void *)fake_CFNetworkCopySystemProxySettings, (void **)&orig_CFNetworkCopySystemProxySettings},
            {"SCDynamicStoreCopyProxies",       (void *)fake_SCDynamicStoreCopyProxies,       (void **)&orig_SCDynamicStoreCopyProxies},
            {"CFNetworkCopyProxiesForURL",      (void *)fake_CFNetworkCopyProxiesForURL,      (void **)&orig_CFNetworkCopyProxiesForURL},
        }, 3);

        // ② 环境变量
        rebind_symbols((struct rebinding[1]){
            {"getenv", (void *)fake_getenv, (void **)&orig_getenv},
        }, 1);

        // ③ NSURLSessionConfiguration
        Class Cfg = NSURLSessionConfiguration.class;
        if (Cfg) {
            Method m1 = class_getClassMethod(Cfg, @selector(defaultSessionConfiguration));
            if (m1) { orig_defCfg = (void *)method_getImplementation(m1);
                      method_setImplementation(m1, (IMP)swz_defCfg); }
            Method m2 = class_getClassMethod(Cfg, @selector(ephemeralSessionConfiguration));
            if (m2) { orig_ephCfg = (void *)method_getImplementation(m2);
                      method_setImplementation(m2, (IMP)swz_ephCfg); }
        }

        // ④ CFStream 兜底
        rebind_symbols((struct rebinding[1]){
            {"CFReadStreamCopyProperty", (void *)fake_CFReadStreamCopyProperty, (void **)&orig_CFReadStreamCopyProperty},
        }, 1);

        // 只弹一次
        PopupOnce(@"ProxyBlind 已生效", @"已隐藏系统/会话/环境变量的代理设置。");
    }
}
