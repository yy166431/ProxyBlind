//
//  ProxyBlind.m
//  目标：让 App 读取不到任何代理设置（HTTP/HTTPS/SOCKS/PAC/环境变量/流级别），
//       以绕过「是否在使用代理」一类检测。
//  实现：fishhook + CFNetwork/SystemConfiguration 钩子，全部回“直连”。
//  日志：不输出；仅在库加载后弹一次提示，便于确认生效。
//  依赖：fishhook.h / fishhook.c 同目录即可。
//

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <SystemConfiguration/SystemConfiguration.h>
#import <Security/Security.h>
#import "fishhook.h"

#pragma mark - 小工具

static CFDictionaryRef CFRetainBridge(NSDictionary *d) {
    return (CFDictionaryRef)CFRetain((__bridge CFTypeRef)(d ? d : @{}));
}

// 空代理字典：全部“未启用”
static NSDictionary *PB_EmptyProxyDictObj(void) {
    // 不直接引用 kCFNetworkProxies* 常量，避免在 iOS SDK 上出现“不可用”编译错误；
    // 以 NSString 写入同名 key 即可满足调用方读取。
    return @{
        (__bridge NSString *)kCFNetworkProxiesHTTPEnable  : @0,
        (__bridge NSString *)kCFNetworkProxiesHTTPSEnable : @0,
        (__bridge NSString *)kCFNetworkProxiesSOCKSEnable : @0,
    };
}
static CFDictionaryRef PB_EmptyProxyDict(void) {
    return CFRetainBridge(PB_EmptyProxyDictObj());
}

// 直连数组（用于 *CopyProxiesForURL / PAC 等 API 返回值）
static CFArrayRef PB_EmptyProxyArray(void) {
    CFArrayCallBacks callbacks = kCFTypeArrayCallBacks;
    return CFArrayCreate(kCFAllocatorDefault, NULL, 0, &callbacks);
}

// 只弹一次的小提示
static void PB_ShowOnce(void) {
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *title = @"ProxyBlind 已启用";
            NSString *msg   = @"已将系统/会话/脚本/环境变量/流级代理统一伪装为“无代理”。";
            UIAlertController *ac = [UIAlertController alertControllerWithTitle:title
                                                                        message:msg
                                                                 preferredStyle:UIAlertControllerStyleAlert];
            [ac addAction:[UIAlertAction actionWithTitle:@"知道了" style:UIAlertActionStyleDefault handler:nil]];
            UIWindow *win = UIApplication.sharedApplication.keyWindow ?: UIApplication.sharedApplication.windows.firstObject;
            UIViewController *vc = win.rootViewController;
            while (vc.presentedViewController) { vc = vc.presentedViewController; }
            [vc presentViewController:ac animated:YES completion:nil];
        });
    });
}

#pragma mark - 1) 系统层代理：CFNetworkCopySystemProxySettings / SCDynamicStoreCopyProxies / CFNetworkCopyProxiesForURL

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

#pragma mark - 2) PAC：脚本/URL 两种入口也回“直连”

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

#pragma mark - 3) 环境变量：getenv("http_proxy"/"https_proxy"/"all_proxy"...)

static char *(*orig_getenv)(const char *name) = NULL;
static char *fake_getenv(const char *name) {
    if (name) {
        if (!strncasecmp(name, "http_proxy", 10) ||
            !strncasecmp(name, "https_proxy",11) ||
            !strncasecmp(name, "all_proxy", 9)  ||
            !strncasecmp(name, "HTTP_PROXY",10) ||
            !strncasecmp(name, "HTTPS_PROXY",11)||
            !strncasecmp(name, "ALL_PROXY", 9)) {
            return NULL; // 视为未设置
        }
    }
    return orig_getenv ? orig_getenv(name) : NULL;
}

#pragma mark - 4) 流级别兜底：拦截 CFReadStreamSetProperty 里的“代理属性”

typedef Boolean (*PFN_CFReadStreamSetProperty)(CFReadStreamRef stream, CFStringRef propertyName, CFTypeRef propertyValue);
static PFN_CFReadStreamSetProperty orig_CFReadStreamSetProperty = NULL;

static Boolean fake_CFReadStreamSetProperty(CFReadStreamRef stream, CFStringRef propertyName, CFTypeRef propertyValue) {
    // 不直接引用 kCFStreamPropertyHTTPProxy 等常量（有平台可用性限制），
    // 用描述名里包含“Proxy”来判断并吞掉。
    if (propertyName) {
        CFStringRef desc = CFCopyDescription(propertyName);
        BOOL isProxyKey = NO;
        if (desc) {
            CFRange r = CFStringFind(desc, CFSTR("Proxy"), kCFCompareCaseInsensitive);
            isProxyKey = (r.location != kCFNotFound);
            CFRelease(desc);
        }
        if (isProxyKey) {
            // 伪成功，但不真正设置（效果等价于“无代理”）
            return true;
        }
    }
    return orig_CFReadStreamSetProperty ? orig_CFReadStreamSetProperty(stream, propertyName, propertyValue) : false;
}

#pragma mark - 安装钩子

__attribute__((constructor))
static void _proxyblind_init(void) {
    @autoreleasepool {
        struct rebinding rbs[] = {
            // 系统层
            {"CFNetworkCopySystemProxySettings", (void *)fake_CFNetworkCopySystemProxySettings, (void **)&orig_CFNetworkCopySystemProxySettings},
            {"SCDynamicStoreCopyProxies",        (void *)fake_SCDynamicStoreCopyProxies,        (void **)&orig_SCDynamicStoreCopyProxies},
            {"CFNetworkCopyProxiesForURL",       (void *)fake_CFNetworkCopyProxiesForURL,       (void **)&orig_CFNetworkCopyProxiesForURL},
            // PAC
            {"CFNetworkCopyProxiesForAutoConfigurationScript", (void *)fake_CFNetworkCopyProxiesForAutoConfigurationScript, (void **)&orig_CFNetworkCopyProxiesForAutoConfigurationScript},
            {"CFNetworkCopyProxiesForAutoConfigurationURL",    (void *)fake_CFNetworkCopyProxiesForAutoConfigurationURL,    (void **)&orig_CFNetworkCopyProxiesForAutoConfigurationURL},
            // 环境变量
            {"getenv", (void *)fake_getenv, (void **)&orig_getenv},
            // 流级别兜底
            {"CFReadStreamSetProperty", (void *)fake_CFReadStreamSetProperty, (void **)&orig_CFReadStreamSetProperty},
        };
        rebind_symbols(rbs, sizeof(rbs)/sizeof(rbs[0]));

        PB_ShowOnce();
    }
}
