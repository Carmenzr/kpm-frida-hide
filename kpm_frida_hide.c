// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * kpm-frida-hide - 让 /proc/<pid>/maps 里不再出现 "frida" 字样。
 *
 * 原理：maps 每一行的文件路径最终由 d_path() 生成。这里 inline-hook d_path()，
 * 在原函数返回后把结果里的 "frida" 就地改写成 "jits_"（长度相同，不改长度），
 * 于是 memfd:frida-agent-64.so 变成 memfd:jits_-agent-64.so，字符串扫描失效。
 *
 * 只做字符串改写，不碰内核结构体布局，跨 KMI 相对安全；卸载即恢复。
 */
#include <compiler.h>
#include <kpmodule.h>
#include <hook.h>
#include <kallsyms.h>
#include <linux/printk.h>
#include <common.h>

KPM_NAME("kpm-frida-hide");
KPM_VERSION("1.0.0");
KPM_LICENSE("GPL v2");
KPM_AUTHOR("carmenzr");
KPM_DESCRIPTION("Replace the word frida in d_path output (proc maps)");

static char *(*orig_d_path)(const void *path, char *buf, int buflen);
static void *d_path_addr;

static void scrub(char *s)
{
    char *p = s;

    /* 原地替换，长度不变：frida -> jits_ */
    while (p[0] && p[1] && p[2] && p[3] && p[4]) {
        if (p[0] == 'f' && p[1] == 'r' && p[2] == 'i' &&
            p[3] == 'd' && p[4] == 'a') {
            p[0] = 'j';
            p[1] = 'i';
            p[2] = 't';
            p[3] = 's';
            p[4] = '_';
        }
        p++;
    }
}

static char *hook_d_path(const void *path, char *buf, int buflen)
{
    char *ret = orig_d_path(path, buf, buflen);

    if (ret)
        scrub(ret);
    return ret;
}

static long kpm_init(const char *args, const char *event, void *__user reserved)
{
    hook_err_t err;

    d_path_addr = (void *)kallsyms_lookup_name("d_path");
    if (!d_path_addr) {
        pr_err("kpm-frida-hide: d_path not found\n");
        return -1;
    }

    err = hook(d_path_addr, hook_d_path, (void **)&orig_d_path);
    if (err) {
        pr_err("kpm-frida-hide: hook failed %d\n", err);
        return -1;
    }

    pr_info("kpm-frida-hide: d_path hooked at %px\n", d_path_addr);
    return 0;
}

static long kpm_exit(void *__user reserved)
{
    if (d_path_addr)
        unhook(d_path_addr);
    pr_info("kpm-frida-hide: exit\n");
    return 0;
}

KPM_INIT(kpm_init);
KPM_EXIT(kpm_exit);