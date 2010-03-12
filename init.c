/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/reboot.h>
#include <linux/reboot.h>

#include <termios.h>
#include <linux/kd.h>


#include "devices.h"
#include "init.h"
#include "bootchart.h"

#if BOOTCHART
static int   bootchart_count;
#endif

static char console[32];
static char serialno[32];
static char bootmode[32];
static char qemu[32];

static int have_console;
static char *console_name = "/dev/console";
static time_t process_needs_restart;

static const char *ENV[32];

struct init_request {
    int     magic;
    int     cmd;
    int     runlevel;
    int     sleeptime;
    char    data[368];
};

static void init_reboot(int sig)
{
    pid_t pid;
    int rb;

//    sigprocmask_allsigs(SIG_BLOCK);
    ERROR("The system is going down NOW!");
    ERROR("Sending SIGTERM to all processes");
    kill(-1, SIGTERM);
    sync();
    sleep(1);
    INFO("Sending SIGKILL to all processes");
    kill(-1, SIGKILL);
    sync();
    sleep(2);
    INFO("Unmounting filesystems\n");
    system("umount -a -r");
   
    if (sig == SIGTERM)
        rb = RB_AUTOBOOT;
    else if(sig == SIGUSR2)
        rb = RB_POWER_OFF;
    pid = vfork();
    if (pid == 0) { /* child */
        reboot(rb);
        _exit(EXIT_SUCCESS);
    }
    waitpid(pid, NULL, 0);
    for(;;)
	    sleep(1);
}

static void handle_init_fd(int fd)
{
    int sig;
    struct init_request request;
INFO("%d %c", request.cmd, request.runlevel);
    read(fd, &request, sizeof(request));
    if (request.cmd == 1) {
        switch (request.runlevel) {
            case '0':
                sig = SIGUSR2;
                break;
            case '6':
                sig = SIGTERM;
                break;
        }
        init_reboot(sig);
    }
}

/* add_environment - add "key=value" to the current environment */
int add_environment(const char *key, const char *val)
{
    int n;
 
    for (n = 0; n < 31; n++) {
        if (!ENV[n]) {
            size_t len = strlen(key) + strlen(val) + 2;
            char *entry = malloc(len);
            snprintf(entry, len, "%s=%s", key, val);
            ENV[n] = entry;
            return 0;
        }
    }

    return 1;
}

static void zap_stdio(void)
{
    int fd;
    fd = open("/dev/null", O_RDWR);
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    close(fd);
}

static void open_console()
{
    int fd;
    if ((fd = open(console_name, O_RDWR)) < 0) {
        fd = open("/dev/null", O_RDWR);
    }
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    close(fd);
}

/*
 * gettime() - returns the time in seconds of the system's monotonic clock or
 * zero on error.
 */
static time_t gettime(void)
{
    struct timeval ts;
    int ret;

    ret = gettimeofday(&ts, NULL);
    if (ret < 0) {
        ERROR("gettimeofday failed: %s\n", strerror(errno));
        return 0;
    }

    return ts.tv_sec;
}

static void publish_socket(const char *name, int fd)
{
    char key[64] = ANDROID_SOCKET_ENV_PREFIX;
    char val[64];

    strlcpy(key + sizeof(ANDROID_SOCKET_ENV_PREFIX) - 1,
            name,
            sizeof(key) - sizeof(ANDROID_SOCKET_ENV_PREFIX));
    snprintf(val, sizeof(val), "%d", fd);
    add_environment(key, val);

    /* make sure we don't close-on-exec */
    fcntl(fd, F_SETFD, 0);
}

void service_start(struct service *svc, const char *dynamic_args)
{
    struct stat s;
    pid_t pid;
    int needs_console;
    int n;

        /* starting a service removes it from the disabled
         * state and immediately takes it out of the restarting
         * state if it was in there
         */
    svc->flags &= (~(SVC_DISABLED|SVC_RESTARTING));
    svc->time_started = 0;
    
        /* running processes require no additional work -- if
         * they're in the process of exiting, we've ensured
         * that they will immediately restart on exit, unless
         * they are ONESHOT
         */
    if (svc->flags & SVC_RUNNING) {
        return;
    }

    needs_console = (svc->flags & SVC_CONSOLE) ? 1 : 0;
    if (needs_console && (!have_console)) {
        ERROR("service '%s' requires console\n", svc->name);
        svc->flags |= SVC_DISABLED;
        return;
    }

    if (stat(svc->args[0], &s) != 0) {
        ERROR("cannot find '%s', disabling '%s'\n", svc->args[0], svc->name);
        svc->flags |= SVC_DISABLED;
        return;
    }

    if ((!(svc->flags & SVC_ONESHOT)) && dynamic_args) {
        ERROR("service '%s' must be one-shot to use dynamic args, disabling\n",
               svc->args[0]);
        svc->flags |= SVC_DISABLED;
        return;
    }

    NOTICE("starting '%s'\n", svc->name);

    pid = fork();

    if (pid == 0) {
        struct socketinfo *si;
        struct svcenvinfo *ei;
        char tmp[32];
        int fd, sz;

        for (ei = svc->envvars; ei; ei = ei->next)
            add_environment(ei->name, ei->value);

        for (si = svc->sockets; si; si = si->next) {
            int s = create_socket(si->name,
                                  !strcmp(si->type, "dgram") ? 
                                  SOCK_DGRAM : SOCK_STREAM,
                                  si->perm, si->uid, si->gid);
            if (s >= 0) {
                publish_socket(si->name, s);
            }
        }

        if (needs_console) {
            setsid();
            open_console();
        } else {
            zap_stdio();
        }

#if 0
        for (n = 0; svc->args[n]; n++) {
            INFO("args[%d] = '%s'\n", n, svc->args[n]);
        }
        for (n = 0; ENV[n]; n++) {
            INFO("env[%d] = '%s'\n", n, ENV[n]);
        }
#endif

        setpgid(0, getpid());

    /* as requested, set our gid, supplemental gids, and uid */
        if (svc->gid) {
            setgid(svc->gid);
        }
        if (svc->nr_supp_gids) {
            setgroups(svc->nr_supp_gids, svc->supp_gids);
        }
        if (svc->uid) {
            setuid(svc->uid);
        }

        if (!dynamic_args) {
            if (execve(svc->args[0], (char**) svc->args, (char**) ENV) < 0) {
                ERROR("cannot execve('%s'): %s\n", svc->args[0], strerror(errno));
            }
        } else {
            char *arg_ptrs[SVC_MAXARGS+1];
            int arg_idx = svc->nargs;
            char *tmp = strdup(dynamic_args);
            char *next = tmp;
            char *bword;

            /* Copy the static arguments */
            memcpy(arg_ptrs, svc->args, (svc->nargs * sizeof(char *)));

            while((bword = strsep(&next, " "))) {
                arg_ptrs[arg_idx++] = bword;
                if (arg_idx == SVC_MAXARGS)
                    break;
            }
            arg_ptrs[arg_idx] = '\0';
            execve(svc->args[0], (char**) arg_ptrs, (char**) ENV);
        }
        _exit(127);
    }

    if (pid < 0) {
        ERROR("failed to start '%s'\n", svc->name);
        svc->pid = 0;
        return;
    }

    svc->time_started = gettime();
    svc->pid = pid;
    svc->flags |= SVC_RUNNING;

}

void service_stop(struct service *svc)
{
        /* we are no longer running, nor should we
         * attempt to restart
         */
    svc->flags &= (~(SVC_RUNNING|SVC_RESTARTING));

        /* if the service has not yet started, prevent
         * it from auto-starting with its class
         */
    svc->flags |= SVC_DISABLED;

    if (svc->pid) {
        NOTICE("service '%s' is being killed\n", svc->name);
        kill(-svc->pid, SIGTERM);
    } else {
    }
}

#define CRITICAL_CRASH_THRESHOLD    4       /* if we crash >4 times ... */
#define CRITICAL_CRASH_WINDOW       (4*60)  /* ... in 4 minutes, goto recovery*/

static int wait_for_one_process(int block)
{
    pid_t pid;
    int status;
    struct service *svc;
    struct socketinfo *si;
    time_t now;
    struct listnode *node;
    struct command *cmd;

    while ( (pid = waitpid(-1, &status, block ? 0 : WNOHANG)) == -1 && errno == EINTR );
    if (pid <= 0) return -1;
    INFO("waitpid returned pid %d, status = %08x\n", pid, status);

    svc = service_find_by_pid(pid);
    if (!svc) {
        ERROR("untracked pid %d exited\n", pid);
        return 0;
    }

    NOTICE("process '%s', pid %d exited\n", svc->name, pid);

    if (!(svc->flags & SVC_ONESHOT)) {
        kill(-pid, SIGKILL);
        NOTICE("process '%s' killing any children in process group\n", svc->name);
    }

    /* remove any sockets we may have created */
    for (si = svc->sockets; si; si = si->next) {
        char tmp[128];
        snprintf(tmp, sizeof(tmp), ANDROID_SOCKET_DIR"/%s", si->name);
        unlink(tmp);
    }

    svc->pid = 0;
    svc->flags &= (~SVC_RUNNING);

        /* oneshot processes go into the disabled state on exit */
    if (svc->flags & SVC_ONESHOT) {
        svc->flags |= SVC_DISABLED;
    }

        /* disabled processes do not get restarted automatically */
    if (svc->flags & SVC_DISABLED) {
        return 0;
    }

    now = gettime();
    if (svc->flags & SVC_CRITICAL) {
        if (svc->time_crashed + CRITICAL_CRASH_WINDOW >= now) {
            if (++svc->nr_crashed > CRITICAL_CRASH_THRESHOLD) {
                ERROR("critical process '%s' exited %d times in %d minutes; "
                      "rebooting into recovery mode\n", svc->name,
                      CRITICAL_CRASH_THRESHOLD, CRITICAL_CRASH_WINDOW / 60);
                sync();
                /*reboot(LINUX_REBOOT_MAGIC1, LINUX_REBOOT_MAGIC2,
                         LINUX_REBOOT_CMD_RESTART2, "recovery");*/
		reboot(RB_AUTOBOOT);
                return 0;
            }
        } else {
            svc->time_crashed = now;
            svc->nr_crashed = 1;
        }
    }

    svc->flags |= SVC_RESTARTING;

    /* Execute all onrestart commands for this service. */
    list_for_each(node, &svc->onrestart.commands) {
        cmd = node_to_item(node, struct command, clist);
        cmd->func(cmd->nargs, cmd->args);
    }
    return 0;
}

static void restart_service_if_needed(struct service *svc)
{
    time_t next_start_time = svc->time_started + 5;

    if (next_start_time <= gettime()) {
        svc->flags &= (~SVC_RESTARTING);
        service_start(svc, NULL);
        return;
    }

    if ((next_start_time < process_needs_restart) ||
        (process_needs_restart == 0)) {
        process_needs_restart = next_start_time;
    }
}

static void restart_processes()
{
    process_needs_restart = 0;
    service_for_each_flags(SVC_RESTARTING,
                           restart_service_if_needed);
}

static int signal_fd = -1;

static void sigchld_handler(int s)
{
    write(signal_fd, &s, 1);
}

static void msg_start(const char *name)
{
    struct service *svc;
    char *tmp = NULL;
    char *args = NULL;

    if (!strchr(name, ':'))
        svc = service_find_by_name(name);
    else {
        tmp = strdup(name);
        args = strchr(tmp, ':');
        *args = '\0';
        args++;

        svc = service_find_by_name(tmp);
    }
    
    if (svc) {
        service_start(svc, args);
    } else {
        ERROR("no such service '%s'\n", name);
    }
    if (tmp)
        free(tmp);
}

static void msg_stop(const char *name)
{
    struct service *svc = service_find_by_name(name);

    if (svc) {
        service_stop(svc);
    } else {
        ERROR("no such service '%s'\n", name);
    }
}

void handle_control_message(const char *msg, const char *arg)
{
    if (!strcmp(msg,"start")) {
        msg_start(arg);
    } else if (!strcmp(msg,"stop")) {
        msg_stop(arg);
    } else {
        ERROR("unknown control msg '%s'\n", msg);
    }
}


static void import_kernel_nv(char *name, int in_qemu)
{
    char *value = strchr(name, '=');

    if (value == 0) return;
    *value++ = 0;
    if (*name == 0) return;

    if (!in_qemu)
    {
        /* on a real device, white-list the kernel options */
        if (!strcmp(name,"qemu")) {
            strlcpy(qemu, value, sizeof(qemu));
        } else if (!strcmp(name,"androidboot.console")) {
            strlcpy(console, value, sizeof(console));
        } else if (!strcmp(name,"androidboot.mode")) {
            strlcpy(bootmode, value, sizeof(bootmode));
        } else {
            qemu_cmdline(name, value);
        }
    }
   
}

static void import_kernel_cmdline(int in_qemu)
{
    char cmdline[1024];
    char *ptr;
    int fd;

    fd = open("/proc/cmdline", O_RDONLY);
    if (fd >= 0) {
        int n = read(fd, cmdline, 1023);
        if (n < 0) n = 0;

        /* get rid of trailing newline, it happens */
        if (n > 0 && cmdline[n-1] == '\n') n--;

        cmdline[n] = 0;
        close(fd);
    } else {
        cmdline[0] = 0;
    }

    ptr = cmdline;
    while (ptr && *ptr) {
        char *x = strchr(ptr, ' ');
        if (x != 0) *x++ = 0;
        import_kernel_nv(ptr, in_qemu);
        ptr = x;
    }

        /* don't expose the raw commandline to nonpriv processes */
    chmod("/proc/cmdline", 0440);
}


void drain_action_queue(void)
{
    struct listnode *node;
    struct command *cmd;
    struct action *act;
    int ret;

    while ((act = action_remove_queue_head())) {
        INFO("processing action %p (%s)\n", act, act->name);
        list_for_each(node, &act->commands) {
            cmd = node_to_item(node, struct command, clist);
            ret = cmd->func(cmd->nargs, cmd->args);
            INFO("command '%s' r=%d\n", cmd->args[0], ret);
        }
    }
}

void open_devnull_stdio(void)
{
    int fd;
    static const char *name = "/dev/__null__";
    if (mknod(name, S_IFCHR | 0600, (1 << 8) | 3) == 0) {
        fd = open(name, O_RDWR);
        unlink(name);
        if (fd >= 0) {
            dup2(fd, 0);
            dup2(fd, 1);
            dup2(fd, 2);
            if (fd > 2) {
                close(fd);
            }
            return;
        }
    }

    exit(1);
}

int main(int argc, char **argv)
{
    int init_fd = -1;
    int signal_recv_fd = -1;
    int fd_count;
    int s[2];
    int fd;
    struct sigaction act;
    char tmp[PROP_NAME_MAX];
    struct pollfd ufds[4];
    char *tmpdev;
    char* debuggable;

    act.sa_handler = sigchld_handler;
    act.sa_flags = SA_NOCLDSTOP;
    act.sa_restorer = NULL;
    sigemptyset(&act.sa_mask);
    sigaction(SIGCHLD, &act, 0);

    /* clear the umask */
    umask(0);

    mount("tmpfs", "/tmp", "tmpfs", MS_NODEV|MS_NOSUID, "mode=1777");
    system("/sbin/sreadahead -d -t 20 &");
    mount("tmpfs", "/lib/init/rw", "tmpfs", MS_NOSUID, "mode=0755");
    mount("proc", "/proc", "proc", MS_NOEXEC|MS_NODEV|MS_NOSUID, NULL);
    mount("sysfs", "/sys", "sysfs", MS_NOEXEC|MS_NODEV|MS_NOSUID, NULL);
    mount("varrun", "/var/run", "tmpfs", MS_NOSUID, "mode=0755");
    mount("varlock", "/var/lock", "tmpfs", MS_NOEXEC|MS_NODEV|MS_NOSUID, "mode=1777");

    mount("udev", "/dev", "tmpfs", 0, "mode=0755");
    mknod("/dev/null", S_IFCHR | 0666, (1 << 8) | 3);
#if 1
    system("udevd --daemon");
    system("udevadm trigger");
    system("udevadm settle");
#else
    system("/sbin/mdev -s");
#endif

    mkdir("/dev/shm", 1777);
    mount("tmpfs", "/dev/shm", "tmpfs", MS_NODEV|MS_NOSUID, NULL);
    mkdir("/dev/pts", 0755);
    mount("devpts", "/dev/pts", "devpts", MS_NOEXEC|MS_NOSUID, "gid=5,mode=620");
    mkdir("/dev/socket", 0755);

    mknod("/dev/ptmx", S_IFCHR | 0666, (5 << 8) | 2);
    mkfifo("/dev/initctl", 0600);
        /* We must have some place other than / to create the
         * device nodes for kmsg and null, otherwise we won't
         * be able to remount / read-only later on.
         * Now that tmpfs is mounted on /dev, we can actually
         * talk to the outside world.
         */
//    open_devnull_stdio();
    log_init();
    
    INFO("reading config file\n");
    parse_config_file("/init.rc");

    /* pull the kernel commandline and ramdisk properties file in */
    import_kernel_cmdline(0);

    action_for_each_trigger("early-init", action_add_queue_tail);
    drain_action_queue();

    INFO("device init\n");


    if (console[0]) {
        snprintf(tmp, sizeof(tmp), "/dev/%s", console);
        console_name = strdup(tmp);
    }

    fd = open(console_name, O_RDWR);
    if (fd >= 0)
        have_console = 1;
    close(fd);

    if (qemu[0])
        import_kernel_cmdline(1); 
   
        /* execute all the boot actions to get us started */
    action_for_each_trigger("init", action_add_queue_tail);
    drain_action_queue();

     
    /* create a signalling mechanism for the sigchld handler */
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, s) == 0) {
        signal_fd = s[0];
        signal_recv_fd = s[1];
        fcntl(s[0], F_SETFD, FD_CLOEXEC);
        fcntl(s[0], F_SETFL, O_NONBLOCK);
        fcntl(s[1], F_SETFD, FD_CLOEXEC);
        fcntl(s[1], F_SETFL, O_NONBLOCK);
    }

    init_fd = open("/dev/initctl", O_RDONLY|O_NONBLOCK);
    /* make sure we actually have all the pieces we need */
    if((init_fd < 0) ||
        (signal_recv_fd < 0)) {
        ERROR("init startup failure\n");
        return 1;
    }

    system("/sbin/hwclock --systz --localtime --directisa --noadjfile");
    system("mount -n -o remount,rw /");
    system("mount -a");
//    system("/sbin/mingetty --noclear tty1");
    mkdir("/tmp/.X11-unix", 01777);
    mkdir("/tmp/.ICE-unix", 01777);
    umask(0022);
    /* execute all the boot actions to get us started */
    action_for_each_trigger("early-boot", action_add_queue_tail);
    action_for_each_trigger("boot", action_add_queue_tail);
    drain_action_queue();

ERROR("DONE\n");
    ufds[0].fd = init_fd;
    ufds[0].events = POLLIN;
    ufds[1].fd = signal_recv_fd;
    ufds[1].events = POLLIN;
    fd_count = 2;

    ufds[2].events = 0;
    ufds[2].revents = 0;
    ufds[3].events = 0;
    ufds[3].revents = 0;

#if BOOTCHART
    bootchart_count = bootchart_init();
    if (bootchart_count < 0) {
        ERROR("bootcharting init failure\n");
    } else if (bootchart_count > 0) {
        NOTICE("bootcharting started (period=%d ms)\n", bootchart_count*BOOTCHART_POLLING_MS);
    } else {
        NOTICE("bootcharting ignored\n");
    }
#endif

    for(;;) {
        int nr, i, timeout = -1;

        for (i = 0; i < fd_count; i++)
            ufds[i].revents = 0;

        drain_action_queue();
        restart_processes();

        if (process_needs_restart) {
            timeout = (process_needs_restart - gettime()) * 1000;
            if (timeout < 0)
                timeout = 0;
        }

#if BOOTCHART
        if (bootchart_count > 0) {
            if (timeout < 0 || timeout > BOOTCHART_POLLING_MS)
                timeout = BOOTCHART_POLLING_MS;
            if (bootchart_step() < 0 || --bootchart_count == 0) {
                bootchart_finish();
                bootchart_count = 0;
            }
        }
#endif
        nr = poll(ufds, fd_count, timeout);
        if (nr <= 0)
            continue;

        if (ufds[1].revents == POLLIN) {
            /* we got a SIGCHLD - reap and restart as needed */
            read(signal_recv_fd, tmp, sizeof(tmp));
            while (!wait_for_one_process(0))
                ;
            continue;
        }
        if (ufds[0].revents == POLLIN)
            handle_init_fd(init_fd);
    }

    return 0;
}
