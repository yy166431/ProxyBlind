//
//  ProxyBlind.m
//  让 App 读取不到任何代理设置（HTTP/HTTPS/SOCKS/PAC/环境变量/流级），绕过“是否使用代理”的检测。
//  依赖：fishhook.h / fishhook.c 同目录
//

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreFoundation/CoreFoundation.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <Security/Security.h>
#import "fishhook.h"

#pragma mark - 工具

static CFDictionaryRef CFRetainBridge(NSDictionary *d) {
    return (CFDictionaryRef)CFRetain((__bridge CFTypeRef)(d ? d : @{}));
}

// 空代理字典：不包含任何键（避免触发 iOS 的“不可用”常量）
static NSDictionary *PB_EmptyProxyDictObj(void) {
    return @{};   // ✅ 关键修复：不再使用 kCFNetworkProxies* 常量
}
static CFDictionaryRef PB_EmptyProxyDict(void) {
    return CFRetainBridge(PB_EmptyProxyDictObj());
}

// 直连数组（用于 *CopyProxiesForURL / PAC）
static CFArrayRef PB_EmptyProxyArray(void) {
    CFArrayCallBacks callbacks = kCFTypeArrayCallBacks;
    return CFArrayCreate(kCFAllocatorDefault, NULL, 0, &callbacks);
}

// 只弹一次小提示
static void PB_ShowOnce(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        dispatch_async(dispatch_get_main_queue(), ^{
            UIApplication *app = UIApplication.sharedApplication;
            if (!app) return;
            UIWindow *win = app.keyWindow ?: app.windows.firstObject;
            if (!win) return;
            UIViewController *vc = win.rootViewController;
            if (!vc) return;
            while (vc.presentedViewController) vc = vc.presentedViewController;

            UIAlertController *ac =
            [UIAlertController alertControllerWithTitle:@"ProxyBlind 已启用"
                                                message:@"已将系统/会话/PAC/环境变量/流级代理统一伪装为“无代理”。"
                                         preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"知道了" style:UIAlertActionStyleDefault handler:nil]];
            [vc presentViewController:ac animated:YES completion:nil];
        });
    });
}

#pragma mark - 1) 系统层代理

typedef CFDictionaryRef (*PFN_CFNetworkCopySystemProxySettings)(void);
static PFN_CFNetworkCopySystemProxySettings orig_CFNetworkCopySystemProxySettings = NULL;
static CFDictionaryRef fake_CFNetworkCopySystemProxySettings(void) {
    return PB_EmptyProxyDict();
}

typedef CFDictionaryRef (*PFN_SCDynamicStoreCopyProxies)(SCDynamicStoreRef store);
static PFN_SCDynamicStoreCopyProxies orig_SCDynamicStoreCopyProxies = NULL;
static CFDictionaryRef fake_SCDynamicStoreCopyProxies(SCDynamicStoreRef store) {
    (void)store;
    return PB_EmptyProxyDict();
}

typedef CFArrayRef (*PFN_CFNetworkCopyProxiesForURL)(CFURLRef url, CFDictionaryRef proxySettings);
static PFN_CFNetworkCopyProxiesForURL orig_CFNetworkCopyProxiesForURL = NULL;
static CFArrayRef fake_CFNetworkCopyProxiesForURL(CFURLRef url, CFDictionaryRef proxySettings) {
    (void)url; (void)proxySettings;
    return PB_EmptyProxyArray();
}

#pragma mark - 2) PAC（脚本/URL）

typedef CFArrayRef (*PFN_CFNetworkCopyProxiesForAutoConfigurationScript)(CFStringRef script, CFURLRef url);
static PFN_CFNetworkCopyProxiesForAutoConfigurationScript orig_CFNetworkCopyProxiesForAutoConfigurationScript = NULL;
static CFArrayRef fake_CFNetworkCopyProxiesForAutoConfigurationScript(CFStringRef script, CFURLRef url) {
    (void)script; (void)url;
    return PB_EmptyProxyArray();
}

typedef CFArrayRef (*PFN_CFNetworkCopyProxiesForAutoConfigurationURL)(CFURLRef url, CFErrorRef *error);
static PFN_CFNetworkCopyProxiesForAutoConfigurationURL orig_CFNetworkCopyProxiesForAutoConfigurationURL = NULL;
static CFArrayRef fake_CFNetworkCopyProxiesForAutoConfigurationURL(CFURLRef url, CFErrorRef *error) {
    (void)url; if (error) *error = NULL;
    return PB_EmptyProxyArray();
}

#pragma mark - 3) 环境变量

static char *(*orig_getenv)(const char *name) = NULL;
static char *fake_getenv(const char *name) {
    if (name) {
        if (!strncasecmp(name, "http_proxy", 10)  ||
            !strncasecmp(name, "https_proxy",11) ||
            !strncasecmp(name, "all_proxy", 9)   ||
            !strncasecmp(name, "HTTP_PROXY",10)  ||
            !strncasecmp(name, "HTTPS_PROXY",11) ||
            !strncasecmp(name, "ALL_PROXY", 9)) {
            return NULL; // 视为未设置
        }
    }
    return orig_getenv ? orig_getenv(name) : NULL;
}

#pragma mark - 4) 流级兜底：拦截设置“Proxy”相关属性

typedef Boolean (*PFN_CFReadStreamSetProperty)(CFReadStreamRef stream, CFStringRef propertyName, CFTypeRef propertyValue);
static PFN_CFReadStreamSetProperty orig_CFReadStreamSetProperty = NULL;

static Boolean fake_CFReadStreamSetProperty(CFReadStreamRef stream, CFStringRef propertyName, CFTypeRef propertyValue) {
    if (propertyName) {
        CFStringRef desc = CFCopyDescription(propertyName);
        bool block = false;
        if (desc) {
            CFRange r = CFStringFind(desc, CFSTR("Proxy"), kCFCompareCaseInsensitive);
            block = (r.location != kCFNotFound);
            CFRelease(desc);
        }
        if (block) return true; // 伪成功，不设置
    }
    return orig_CFReadStreamSetProperty ? orig_CFReadStreamSetProperty(stream, propertyName, propertyValue) : false;
}

#pragma mark - 安装

__attribute__((constructor))
static void _proxyblind_init(void) {
    @autoreleasepool {
        struct rebinding rbs[] = {
            {"CFNetworkCopySystemProxySettings",            (void *)fake_CFNetworkCopySystemProxySettings,            (void **)&orig_CFNetworkCopySystemProxySettings},
            {"SCDynamicStoreCopyProxies",                   (void *)fake_SCDynamicStoreCopyProxies,                   (void **)&orig_SCDynamicStoreCopyProxies},
            {"CFNetworkCopyProxiesForURL",                  (void *)fake_CFNetworkCopyProxiesForURL,                  (void **)&orig_CFNetworkCopyProxiesForURL},
            {"CFNetworkCopyProxiesForAutoConfigurationScript",(void *)fake_CFNetworkCopyProxiesForAutoConfigurationScript,(void **)&orig_CFNetworkCopyProxiesForAutoConfigurationScript},
            {"CFNetworkCopyProxiesForAutoConfigurationURL", (void *)fake_CFNetworkCopyProxiesForAutoConfigurationURL, (void **)&orig_CFNetworkCopyProxiesForAutoConfigurationURL},
            {"getenv",                                      (void *)fake_getenv,                                      (void **)&orig_getenv},
            {"CFReadStreamSetProperty",                     (void *)fake_CFReadStreamSetProperty,                     (void **)&orig_CFReadStreamSetProperty},
        };
        rebind_symbols(rbs, sizeof(rbs)/sizeof(rbs[0]));

        PB_ShowOnce();
    }
}
