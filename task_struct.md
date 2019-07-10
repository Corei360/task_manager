# 进程描述符

进程描述符由task_struct结构体表示，定义在<linux/sched.h>，抽象出来描述进程相关的信息。

## task_struct结构体分析：  

#### 线程描述符

    #ifdef CONFIG_THREAD_INFO_IN_TASK  
    	/*  
    	 * For reasons of header soup (see current_thread_info()), this  
    	 * must be the first element of task_struct.  
    	 */  
    	struct thread_info		thread_info;  
    #endif

#### 进程状态：  

    	/* -1 unrunnable, 0 runnable, >0 stopped: */  
    	volatile long			state; 
	
state可取的值如下：  

	/* include/linux/sched.h */
    /* Used in tsk->state: */  
    #define TASK_RUNNING			0x0000		// 表示进程要么正在执行，要么正要准备执行   
    #define TASK_INTERRUPTIBLE		0x0001		// 表示进程被阻塞（睡眠），直到某个条件变为真，进程的状态就被设置为TASK_RUNNING。  
    #define TASK_UNINTERRUPTIBLE	0x0002		// 表示进程被阻塞，不允许被信号唤醒   
    #define __TASK_STOPPED			0x0004		// 表示进程被停止执行，当进程接收到SIGSTOP、SIGTTIN、SIGTSTP或者SIGTTOU信号之后就会进入该状态
    #define __TASK_TRACED			0x0008 		// 表示进程被debugger等进程监视，进程执行被调试程序所停止，当一个进程被另外的进程所监视，每一个信号都会让进城进入该状态
    /* Used in tsk->exit_state: */  
    #define EXIT_DEAD				0x0010		// 表示进程的最终状态   
    #define EXIT_ZOMBIE				0x0020		// 表示进程的执行被终止，但父进程没有调用wait()等系统调用来获知其终止信息   
    #define EXIT_TRACE				(EXIT_ZOMBIE | EXIT_DEAD)  
    /* Used in tsk->state again: */  
    #define TASK_PARKED				0x0040  
    #define TASK_DEAD				0x0080  
    #define TASK_WAKEKILL			0x0100  
    #define TASK_WAKING				0x0200  
    #define TASK_NOLOAD				0x0400  
    #define TASK_NEW				0x0800  
    #define TASK_STATE_MAX			0x1000

	/* Convenience macros for the sake of set_current_state: */
	#define TASK_KILLABLE			(TASK_WAKEKILL | TASK_UNINTERRUPTIBLE)
	#define TASK_STOPPED			(TASK_WAKEKILL | __TASK_STOPPED)
	#define TASK_TRACED				(TASK_WAKEKILL | __TASK_TRACED)
	
	#define TASK_IDLE				(TASK_UNINTERRUPTIBLE | TASK_NOLOAD)
	
	/* Convenience macros for the sake of wake_up(): */
	#define TASK_NORMAL				(TASK_INTERRUPTIBLE | TASK_UNINTERRUPTIBLE)
	
	/* get_task_state(): */
	#define TASK_REPORT				(TASK_RUNNING | TASK_INTERRUPTIBLE | \
									 TASK_UNINTERRUPTIBLE | __TASK_STOPPED | \
									 __TASK_TRACED | EXIT_DEAD | EXIT_ZOMBIE | \
									 TASK_PARKED)

Linux 内核提供了两种方法将进程置为睡眠状态。

方法一：  
将进程置为睡眠状态的方法是将进程状态设置为 `TASK_INTERRUPTIBLE` 或 `TASK_UNINTERRUPTIBLE` 并调用调度程序的 schedule() 函数。这样会将进程从 CPU 运行队列中移除。

* 如果进程处于可中断模式的睡眠状态（通过将其状态设置为 TASK_INTERRUPTIBLE），那么可以通过显式的唤醒呼叫（wakeup_process()）或需要处理的信号来唤醒它。  
* 如果进程处于非可中断模式的睡眠状态（通过将其状态设置为 TASK_UNINTERRUPTIBLE），那么只能通过显式的唤醒呼叫将其唤醒。除非万不得已，否则我们建议您将进程置为可中断睡眠模式，而不是不可中断睡眠模式（比如说在设备 I/O 期间，处理信号非常困难时）。

方法二：  
将进程设置为 `TASk_KILLABLE`，当进程处于这种可以终止的睡眠状态时，它的运行原理类似于 `TASK_UNINTERRUPTIBLE`，但是可以相应致命信号。

进程切换关系图：

![进程切换](https://ask.qcloudimg.com/http-save/yehe-1233784/ex9er7f98h.png?imageView2/2/w/1620)
   
#### TODO

    	/*
    	 * This begins the randomizable portion of task_struct. Only
    	 * scheduling-critical items should be added above here.
    	 */
    	randomized_struct_fields_start
    
#### 进程内核栈
	
    	void				*stack;

stack用来指向分配给进程的内核栈。  

每个进程，Linux内核都把两个不同的数据结构紧凑的存放在一个单独为进程分配的内存区域中;

一个是内核态的进程堆栈
另一个是紧挨着进程描述符的小数据结构thread_info，叫做线程描述符。

Linux把thread_info（线程描述符）和内核态的线程堆栈存放在一起，这块区域通常是8192K（占两个页框），其实地址必须是8192的整数倍。

	/* linux/arch/x86/include/asm/page_32_types.h */

	#define THREAD_SIZE_ORDER    1
	#define THREAD_SIZE        (PAGE_SIZE << THREAD_SIZE_ORDER)

	/* linux/arch/x86/include/asm/page_64_types.h */

	#ifdef CONFIG_KASAN
	#ifdef CONFIG_KASAN_EXTRA
	#define KASAN_STACK_ORDER 2
	#else
	#define KASAN_STACK_ORDER 1
	#endif
	#else
	#define KASAN_STACK_ORDER 0
	#endif

	#define THREAD_SIZE_ORDER	(2 + KASAN_STACK_ORDER)
	#define THREAD_SIZE  (PAGE_SIZE << THREAD_SIZE_ORDER)

出于效率考虑，内核让这8K空间占据连续的两个页框并让第一个页框的起始地址是213的倍数。

内核态的进程访问处于内核数据段的栈，这个栈不同于用户态的进程所用的栈。

用户态进程所用的栈，是在进程线性地址空间中；

而内核栈是当进程从用户空间进入内核空间时，特权级发生变化，需要切换堆栈，那么内核空间中使用的就是这个内核栈。因为内核控制路径使用很少的栈空间，所以只需要几千个字节的内核态堆栈。

**需要注意的是，内核态堆栈仅用于内核例程，Linux内核另外为中断提供了单独的硬中断栈和软中断栈**
     

下图中显示了在物理内存中存放两种数据结构的方式。线程描述符驻留与这个内存区的开始，而栈顶末端向下增长。 下图摘自ULK3,进程内核栈与进程描述符的关系如下图：  
![](https://ask.qcloudimg.com/http-save/yehe-1233784/l8cl1edwrc.png?imageView2/2/w/1620)

但是较新的内核代码中，进程描述符task_struct结构中没有直接指向thread_info结构的指针，而是用一个void指针类型的成员表示，然后通过类型转换来访问thread_info结构。

	/* include/linux/sched.h */

	#define task_thread_info(task)  ((struct thread_info *)(task)->stack)

在这个图中，esp寄存器是CPU栈指针，用来存放栈顶单元的地址。在80x86系统中，栈起始于顶端，并朝着这个内存区开始的方向增长。从用户态刚切换到内核态以后，进程的内核栈总是空的。因此，esp寄存器指向这个栈的顶端。一旦数据写入堆栈，esp的值就递减。

#### 引用计数
    	refcount_t			usage;
    	
usage：记录有几个进程使用此结构。

#### 进程标志

		/* Per task flags (PF_*), defined further below: */
    	unsigned int			flags;

flags表示进程的状态信息，这里的状态信息不是指运行状态，而是内核用来识别进程当前的状态，flags的取值一般如下：

	/* include/linux/sched.h */
    /*
     * Per process flags
     */
    #define PF_IDLE				0x00000002	/* I am an IDLE thread */
    #define PF_EXITING			0x00000004	/* Getting shut down */
    #define PF_EXITPIDONE		0x00000008	/* PI exit done on shut down */
    #define PF_VCPU				0x00000010	/* I'm a virtual CPU */
    #define PF_WQ_WORKER		0x00000020	/* I'm a workqueue worker */
    #define PF_FORKNOEXEC		0x00000040	/* Forked but didn't exec */
    #define PF_MCE_PROCESS		0x00000080  /* Process policy on mce errors */
    #define PF_SUPERPRIV		0x00000100	/* Used super-user privileges */
    #define PF_DUMPCORE			0x00000200	/* Dumped core */
    #define PF_SIGNALED			0x00000400	/* Killed by a signal */
    #define PF_MEMALLOC			0x00000800	/* Allocating memory */
    #define PF_NPROC_EXCEEDED	0x00001000	/* set_user() noticed that RLIMIT_NPROC was exceeded */
    #define PF_USED_MATH		0x00002000	/* If unset the fpu must be initialized before use */
    #define PF_USED_ASYNC		0x00004000	/* Used async_schedule*(), used by module init */
    #define PF_NOFREEZE			0x00008000	/* This thread should not be frozen */
    #define PF_FROZEN			0x00010000	/* Frozen for system suspend */
    #define PF_KSWAPD			0x00020000	/* I am kswapd */
    #define PF_MEMALLOC_NOFS	0x00040000	/* All allocation requests will inherit GFP_NOFS */
    #define PF_MEMALLOC_NOIO	0x00080000	/* All allocation requests will inherit GFP_NOIO */
    #define PF_LESS_THROTTLE	0x00100000	/* Throttle me less: I clean memory */
    #define PF_KTHREAD			0x00200000	/* I am a kernel thread */
    #define PF_RANDOMIZE		0x00400000	/* Randomize virtual address space */
    #define PF_SWAPWRITE		0x00800000	/* Allowed to write to swap */
    #define PF_MEMSTALL			0x01000000	/* Stalled due to lack of memory */
    #define PF_UMH				0x02000000	/* I'm an Usermodehelper process */
    #define PF_NO_SETAFFINITY	0x04000000	/* Userland is not allowed to meddle with cpus_allowed */
    #define PF_MCE_EARLY		0x08000000  /* Early kill for mce process policy */
    #define PF_MUTEX_TESTER		0x20000000	/* Thread belongs to the rt mutex tester */
    #define PF_FREEZER_SKIP		0x40000000	/* Freezer should not count it as freezable */
    #define PF_SUSPEND_TASK		0x80000000  /* This thread called freeze_processes() and should not be frozen */
    
#### ptrace系统调用

    	unsigned int			ptrace;

#### TODO
    
    #ifdef CONFIG_SMP
    	struct llist_node		wake_entry;
    	int				on_cpu;
    #ifdef CONFIG_THREAD_INFO_IN_TASK
    	/* Current CPU: */
    	unsigned int			cpu;
    #endif
    	unsigned int			wakee_flips;
    	unsigned long			wakee_flip_decay_ts;
    	struct task_struct		*last_wakee;
    
    	/*
    	 * recent_used_cpu is initially set as the last CPU used by a task
    	 * that wakes affine another task. Waker/wakee relationships can
    	 * push tasks around a CPU where each wakeup moves to the next one.
    	 * Tracking a recently used CPU allows a quick search for a recently
    	 * used CPU that may be idle.
    	 */
    	int				recent_used_cpu;
    	int				wake_cpu;
    #endif
    	int				on_rq;
    
#### 进程调度

    	int				prio;
    	int				static_prio;
    	int				normal_prio;
    	unsigned int			rt_priority;
    	
    	const struct sched_class	*sched_class;
    	struct sched_entity		se;
    	struct sched_rt_entity		rt;
    #ifdef CONFIG_CGROUP_SCHED
    	struct task_group		*sched_task_group;
    #endif
    	struct sched_dl_entity		dl;
    
prio：动态优先级  
`static_prio`：静态优先级，可以通过nice进行修改  
`normal_prio`：静态优先级和调度策略  
`rt_priority`：实时优先级  
`sched_class`：调度类
se：进程调度的实体
rt：实时进程调度的实体  
sched_task_group：TODO  
dl：TODO  

#### TODO

    #ifdef CONFIG_PREEMPT_NOTIFIERS
    	/* List of struct preempt_notifier: */
    	struct hlist_head		preempt_notifiers;
    #endif
    
#### TODO

    #ifdef CONFIG_BLK_DEV_IO_TRACE
    	unsigned int			btrace_seq;
    #endif
    
    	unsigned int			policy;
    	int				nr_cpus_allowed;
    	cpumask_t			cpus_allowed;
    
    #ifdef CONFIG_PREEMPT_RCU
    	int				rcu_read_lock_nesting;
    	union rcu_special		rcu_read_unlock_special;
    	struct list_head		rcu_node_entry;
    	struct rcu_node			*rcu_blocked_node;
    #endif /* #ifdef CONFIG_PREEMPT_RCU */
    
    #ifdef CONFIG_TASKS_RCU
    	unsigned long			rcu_tasks_nvcsw;
    	u8				rcu_tasks_holdout;
    	u8				rcu_tasks_idx;
    	int				rcu_tasks_idle_cpu;
    	struct list_head		rcu_tasks_holdout_list;
    #endif /* #ifdef CONFIG_TASKS_RCU */
    
    	struct sched_info		sched_info;
    	
    	struct list_head		tasks;
    #ifdef CONFIG_SMP
    	struct plist_node		pushable_tasks;
    	struct rb_node			pushable_dl_tasks;
    #endif
    
#### 进程地址空间

    	struct mm_struct		*mm;
    	struct mm_struct		*active_mm;

mm：进程的内存描述符，由于内核线程没有进程地址空间，所以对于内核线程来说，mm为空。
`active_mm`：进程运行时的内存描述符。对于一般普通进程，与mm是相同的。内核线程需要初始化该描述符。

#### TODO
  	
    	/* Per-thread vma caching: */
    	struct vmacache			vmacache;
    
    #ifdef SPLIT_RSS_COUNTING
    	struct task_rss_stat		rss_stat;
    #endif

#### 进程结束状态

    	int				exit_state;
    	int				exit_code;
    	int				exit_signal;

两个附加的进程状态既可以被添加到state域中，又可以被添加到exit_state域中。只有当进程终止的时候，才会达到这两种状态，如下：  
`EXIT_ZOMBIE`：进程的执行被终止，但是其父进程还没有使用wait()等系统调用来获知它的终止信息，此时进程成为僵尸进程  
`EXIT_DEAD`：进程的最终状态

#### TODO

    	/* The signal sent when the parent dies: */
    	int				pdeath_signal;
    	/* JOBCTL_*, siglock protected: */
    	unsigned long			jobctl;
    
    	/* Used for emulating ABI behavior of previous Linux versions: */
    	unsigned int			personality;
    	
    	/* Scheduler bits, serialized by scheduler locks: */
    	unsigned			sched_reset_on_fork:1;
    	unsigned			sched_contributes_to_load:1;
    	unsigned			sched_migrated:1;
    	unsigned			sched_remote_wakeup:1;
    #ifdef CONFIG_PSI
    	unsigned			sched_psi_wake_requeue:1;
    #endif
    
    	/* Force alignment to the next boundary: */
    	unsigned			:0;
    	
    	/* Unserialized, strictly 'current' */
    	
    	/* Bit to tell LSMs we're in execve(): */
    	unsigned			in_execve:1;
    	unsigned			in_iowait:1;
    #ifndef TIF_RESTORE_SIGMASK
    	unsigned			restore_sigmask:1;
    #endif
    #ifdef CONFIG_MEMCG
    	unsigned			in_user_fault:1;
    #endif
    #ifdef CONFIG_COMPAT_BRK
    	unsigned			brk_randomized:1;
    #endif
    #ifdef CONFIG_CGROUPS
    	/* disallow userland-initiated cgroup migration */
    	unsigned			no_cgroup_migration:1;
    	/* task is frozen/stopped (used by the cgroup freezer) */
    	unsigned			frozen:1;
    #endif
    #ifdef CONFIG_BLK_CGROUP
    	/* to be used once the psi infrastructure lands upstream. */
    	unsigned			use_memdelay:1;
    #endif
    
    	unsigned long			atomic_flags; /* Flags requiring atomic access. */
    	
    	struct restart_block		restart_block;
    
#### 进程标识符：  

    	pid_t				pid;  // 进程pid  
    	pid_t				tgid; // 进程组的id，所有进程（包括轻量级进程）共同的pid  

getpid()系统调用返回当前进程的tgid值，而不是pid值。 
32位linux可以创建进程数理论上可以是一个int大小，即2^32，考虑到与老版本的兼容性问题，理论最大值为2^16（65535），但是此处没有考虑到符号问题，由于int是有符号的，所以实际可以取值一般为32768个。  
64位linux可以创建进程数一般为131037。

内核默认定义如下：  
在CONFIG_BASE_SMALL配置为0的情况下，PID的取值范围是0到32767，即系统中的进程数最大为32768个。
PID的最大取值可以是4百万个。

	/* include/linux/threads.h */
	#define PID_MAX_DEFAULT (CONFIG_BASE_SMALL ? 0x1000 : 0x8000)  

	/*
	 * A maximum of 4 million PIDs should be enough for a while.
	 * [NOTE: PID/TIDs are limited to 2^29 ~= 500+ million, see futex.h.]
	 */
	#define PID_MAX_LIMIT (CONFIG_BASE_SMALL ? PAGE_SIZE * 8 : \
			(sizeof(long) > 4 ? 4 * 1024 * 1024 : PID_MAX_DEFAULT))

查看

可以使用cat /proc/sys/kernel/pid_max来查看系统中可创建的进程数实际值

    cat /proc/sys/kernel/pid_max

修改

    ulimit -u 65535

设置完以后，虽然设置户创建进程数的硬限制和软限制都是65535，但是还不能创建65535个进程，还需要设置内核参数kernel.pid_max，这个参数默认安装都是32768，所以即使使用root帐户，如果不设置这个内核参数，整个系统最多可以创建的进程数仍然是32768。

    sysctl -w  kernel.pid_max=65535

#### 堆栈保护
    
    #ifdef CONFIG_STACKPROTECTOR
    	/* Canary value for the -fstack-protector GCC feature: */
    	unsigned long			stack_canary;
    #endif

#### 进程父子关系

    	/*
    	 * Pointers to the (original) parent process, youngest child, younger sibling,
    	 * older sibling, respectively.  (p->father can be replaced with
    	 * p->real_parent->pid)
    	 */
    
    	/* Real parent process: */
    	struct task_struct __rcu	*real_parent;
    	
    	/* Recipient of SIGCHLD, wait4() reports: */
    	struct task_struct __rcu	*parent;
    	
    	/*
    	 * Children/sibling form the list of natural children:
    	 */
    	struct list_head		children;
    	struct list_head		sibling;
    	struct task_struct		*group_leader;

`real_parent`：指向父进程的指针，如果父进程不存在，则指向pid为1的进程。fork()子进程的时候更新该值。  
parent：一般在ptrace的时候设置。当有进程ptrace这个进程时，parent就指向该进程，当子进程结束时，SIGCHLD信号就会发送给对应的进程，也就是此处的parent。如果没有进程被跟踪，则与`real_parent`相同。  
children：链表头，指向的链表中所有元素均为其子进程。  
sibling：指向兄弟进程链表下一个元素。  
`group_leader`：指向进程组的第一个进程。  

#### ptrace

    	/*
    	 * 'ptraced' is the list of tasks this task is using ptrace() on.
    	 *
    	 * This includes both natural children and PTRACE_ATTACH targets.
    	 * 'ptrace_entry' is this task's link on the p->parent->ptraced list.
    	 */
    	struct list_head		ptraced;
    	struct list_head		ptrace_entry;
    	
#### TODO

    	/* PID/PID hash table linkage. */
    	struct pid			*thread_pid;
    	struct hlist_node		pid_links[PIDTYPE_MAX];
    	struct list_head		thread_group;
    	struct list_head		thread_node;
    	
    	struct completion		*vfork_done;
    	
    	/* CLONE_CHILD_SETTID: */
    	int __user			*set_child_tid;
    	
    	/* CLONE_CHILD_CLEARTID: */
    	int __user			*clear_child_tid;
    	
    	u64				utime;
    	u64				stime;
    #ifdef CONFIG_ARCH_HAS_SCALED_CPUTIME
    	u64				utimescaled;
    	u64				stimescaled;
    #endif
    	u64				gtime;
    	struct prev_cputime		prev_cputime;
    #ifdef CONFIG_VIRT_CPU_ACCOUNTING_GEN
    	struct vtime			vtime;
    #endif
    
    #ifdef CONFIG_NO_HZ_FULL
    	atomic_t			tick_dep_mask;
    #endif
    	/* Context switch counts: */
    	unsigned long			nvcsw;
    	unsigned long			nivcsw;
    
    	/* Monotonic time in nsecs: */
    	u64				start_time;
    	
    	/* Boot based time in nsecs: */
    	u64				real_start_time;
    	
    	/* MM fault and swap info: this can arguably be seen as either mm-specific or thread-specific: */
    	unsigned long			min_flt;
    	unsigned long			maj_flt;
    
    #ifdef CONFIG_POSIX_TIMERS
    	struct task_cputime		cputime_expires;
    	struct list_head		cpu_timers[3];
    #endif
    
    	/* Process credentials: */
    	
    	/* Tracer's credentials at attach: */
    	const struct cred __rcu		*ptracer_cred;
    	
    	/* Objective and real subjective task credentials (COW): */
    	const struct cred __rcu		*real_cred;
    	
    	/* Effective (overridable) subjective task credentials (COW): */
    	const struct cred __rcu		*cred;
    
#### 进程名称： 

    	/*
    	 * executable name, excluding path.
    	 *
    	 * - normally initialized setup_new_exec()
    	 * - access it with [gs]et_task_comm()
    	 * - lock it with task_lock()
    	 */
    	char				comm[TASK_COMM_LEN];

#### TODO
    
    	struct nameidata		*nameidata;
    
    #ifdef CONFIG_SYSVIPC
    	struct sysv_sem			sysvsem;
    	struct sysv_shm			sysvshm;
    #endif
    #ifdef CONFIG_DETECT_HUNG_TASK
    	unsigned long			last_switch_count;
    	unsigned long			last_switch_time;
    #endif

#### 文件系统信息

    	/* Filesystem information: */
    	struct fs_struct		*fs;
    
    	/* Open file information: */
    	struct files_struct		*files;
    	
fs：程序文件所在的文件系统
files：当前进程打开的文件

#### 命名空间

    	/* Namespaces: */
    	struct nsproxy			*nsproxy;
    	
#### 信号处理

    	/* Signal handlers: */
    	struct signal_struct		*signal;
    	struct sighand_struct		*sighand;
    	sigset_t			blocked;
    	sigset_t			real_blocked;
    	/* Restored if set_restore_sigmask() was used: */
    	sigset_t			saved_sigmask;
    	struct sigpending		pending;
    	unsigned long			sas_ss_sp;
    	size_t				sas_ss_size;
    	unsigned int			sas_ss_flags;
    	
    	struct callback_head		*task_works;
    
#### 进程审计

    #ifdef CONFIG_AUDIT
    #ifdef CONFIG_AUDITSYSCALL
    	struct audit_context		*audit_context;
    #endif
    	kuid_t				loginuid;
    	unsigned int			sessionid;
    #endif
    	struct seccomp			seccomp;
    
#### 线程跟踪

    	/* Thread group tracking: */
    	u32				parent_exec_id;
    	u32				self_exec_id;
    	
#### 保护锁

    	/* Protection against (de-)allocation: mm, files, fs, tty, keyrings, mems_allowed, mempolicy: */
    	spinlock_t			alloc_lock;
    	
    	/* Protection of the PI data structures: */
    	raw_spinlock_t			pi_lock;
    	
    	struct wake_q_node		wake_q;
    
    #ifdef CONFIG_RT_MUTEXES
    	/* PI waiters blocked on a rt_mutex held by this task: */
    	struct rb_root_cached		pi_waiters;
    	/* Updated under owner's pi_lock and rq lock */
    	struct task_struct		*pi_top_task;
    	/* Deadlock detection and priority inheritance handling: */
    	struct rt_mutex_waiter		*pi_blocked_on;
    #endif
    
#### 死锁检测

    #ifdef CONFIG_DEBUG_MUTEXES
    	/* Mutex deadlock detection: */
    	struct mutex_waiter		*blocked_on;
    #endif
    
#### 中断相关

    #ifdef CONFIG_TRACE_IRQFLAGS
    	unsigned int			irq_events;
    	unsigned long			hardirq_enable_ip;
    	unsigned long			hardirq_disable_ip;
    	unsigned int			hardirq_enable_event;
    	unsigned int			hardirq_disable_event;
    	int				hardirqs_enabled;
    	int				hardirq_context;
    	unsigned long			softirq_disable_ip;
    	unsigned long			softirq_enable_ip;
    	unsigned int			softirq_disable_event;
    	unsigned int			softirq_enable_event;
    	int				softirqs_enabled;
    	int				softirq_context;
    #endif
    
#### lockdep

    #ifdef CONFIG_LOCKDEP
    # define MAX_LOCK_DEPTH			48UL
    	u64				curr_chain_key;
    	int				lockdep_depth;
    	unsigned int			lockdep_recursion;
    	struct held_lock		held_locks[MAX_LOCK_DEPTH];
    #endif
    
#### ubsan

    #ifdef CONFIG_UBSAN
    	unsigned int			in_ubsan;
    #endif
    
#### 日志信息

    	/* Journalling filesystem info: */
    	void				*journal_info;
    	
#### 块设备

    	/* Stacked block device info: */
    	struct bio_list			*bio_list;
    
    #ifdef CONFIG_BLOCK
    	/* Stack plugging: */
    	struct blk_plug			*plug;
    #endif
    
#### VM state

    	/* VM state: */
    	struct reclaim_state		*reclaim_state;
    	
    	struct backing_dev_info		*backing_dev_info;
    	
    	struct io_context		*io_context;
    
    #ifdef CONFIG_COMPACTION
    	struct capture_control		*capture_control;
    #endif
    	/* Ptrace state: */
    	unsigned long			ptrace_message;
    	kernel_siginfo_t		*last_siginfo;
    
    	struct task_io_accounting	ioac;
    #ifdef CONFIG_PSI
    	/* Pressure stall state */
    	unsigned int			psi_flags;
    #endif

#### TASK XACCT

    #ifdef CONFIG_TASK_XACCT
    	/* Accumulated RSS usage: */
    	u64				acct_rss_mem1;
    	/* Accumulated virtual memory usage: */
    	u64				acct_vm_mem1;
    	/* stime + utime since last update: */
    	u64				acct_timexpd;
    #endif

#### cpu sets

    #ifdef CONFIG_CPUSETS
    	/* Protected by ->alloc_lock: */
    	nodemask_t			mems_allowed;
    	/* Seqence number to catch updates: */
    	seqcount_t			mems_allowed_seq;
    	int				cpuset_mem_spread_rotor;
    	int				cpuset_slab_spread_rotor;
    #endif

#### cgroups

    #ifdef CONFIG_CGROUPS
    	/* Control Group info protected by css_set_lock: */
    	struct css_set __rcu		*cgroups;
    	/* cg_list protected by css_set_lock and tsk->alloc_lock: */
    	struct list_head		cg_list;
    #endif

    #ifdef CONFIG_X86_CPU_RESCTRL
    	u32				closid;
    	u32				rmid;
    #endif
    #ifdef CONFIG_FUTEX
    	struct robust_list_head __user	*robust_list;
    #ifdef CONFIG_COMPAT
    	struct compat_robust_list_head __user *compat_robust_list;
    #endif
    	struct list_head		pi_state_list;
    	struct futex_pi_state		*pi_state_cache;
    #endif

#### Performance Event 性能诊断
    #ifdef CONFIG_PERF_EVENTS
    	struct perf_event_context	*perf_event_ctxp[perf_nr_task_contexts];
    	struct mutex			perf_event_mutex;
    	struct list_head		perf_event_list;
    #endif

#### TODO

    #ifdef CONFIG_DEBUG_PREEMPT
    	unsigned long			preempt_disable_ip;
    #endif
    #ifdef CONFIG_NUMA
    	/* Protected by alloc_lock: */
    	struct mempolicy		*mempolicy;
    	short				il_prev;
    	short				pref_node_fork;
    #endif
    #ifdef CONFIG_NUMA_BALANCING
    	int				numa_scan_seq;
    	unsigned int			numa_scan_period;
    	unsigned int			numa_scan_period_max;
    	int				numa_preferred_nid;
    	unsigned long			numa_migrate_retry;
    	/* Migration stamp: */
    	u64				node_stamp;
    	u64				last_task_numa_placement;
    	u64				last_sum_exec_runtime;
    	struct callback_head		numa_work;
    
    	struct numa_group		*numa_group;
    	
    	/*
    	 * numa_faults is an array split into four regions:
    	 * faults_memory, faults_cpu, faults_memory_buffer, faults_cpu_buffer
    	 * in this precise order.
    	 *
    	 * faults_memory: Exponential decaying average of faults on a per-node
    	 * basis. Scheduling placement decisions are made based on these
    	 * counts. The values remain static for the duration of a PTE scan.
    	 * faults_cpu: Track the nodes the process was running on when a NUMA
    	 * hinting fault was incurred.
    	 * faults_memory_buffer and faults_cpu_buffer: Record faults per node
    	 * during the current scan window. When the scan completes, the counts
    	 * in faults_memory and faults_cpu decay and these values are copied.
    	 */
    	unsigned long			*numa_faults;
    	unsigned long			total_numa_faults;
    	
    	/*
    	 * numa_faults_locality tracks if faults recorded during the last
    	 * scan window were remote/local or failed to migrate. The task scan
    	 * period is adapted based on the locality of the faults with different
    	 * weights depending on whether they were shared or private faults
    	 */
    	unsigned long			numa_faults_locality[3];
    	
    	unsigned long			numa_pages_migrated;
    #endif /* CONFIG_NUMA_BALANCING */
    
    #ifdef CONFIG_RSEQ
    	struct rseq __user *rseq;
    	u32 rseq_sig;
    	/*
    	 * RmW on rseq_event_mask must be performed atomically
    	 * with respect to preemption.
    	 */
    	unsigned long rseq_event_mask;
    #endif
    
    	struct tlbflush_unmap_batch	tlb_ubc;
    	
    	struct rcu_head			rcu;
    	
    	/* Cache last used pipe for splice(): */
    	struct pipe_inode_info		*splice_pipe;
    	
    	struct page_frag		task_frag;
    
    #ifdef CONFIG_TASK_DELAY_ACCT
    	struct task_delay_info		*delays;
    #endif
    
    #ifdef CONFIG_FAULT_INJECTION
    	int				make_it_fail;
    	unsigned int			fail_nth;
    #endif
    	/*
    	 * When (nr_dirtied >= nr_dirtied_pause), it's time to call
    	 * balance_dirty_pages() for a dirty throttling pause:
    	 */
    	int				nr_dirtied;
    	int				nr_dirtied_pause;
    	/* Start of a write-and-pause period: */
    	unsigned long			dirty_paused_when;
    
    #ifdef CONFIG_LATENCYTOP
    	int				latency_record_count;
    	struct latency_record		latency_record[LT_SAVECOUNT];
    #endif
    	/*
    	 * Time slack values; these are used to round up poll() and
    	 * select() etc timeout values. These are in nanoseconds.
    	 */
    	u64				timer_slack_ns;
    	u64				default_timer_slack_ns;
    
    #ifdef CONFIG_KASAN
    	unsigned int			kasan_depth;
    #endif
    
    #ifdef CONFIG_FUNCTION_GRAPH_TRACER
    	/* Index of current stored address in ret_stack: */
    	int				curr_ret_stack;
    	int				curr_ret_depth;
    
    	/* Stack of return addresses for return function tracing: */
    	struct ftrace_ret_stack		*ret_stack;
    	
    	/* Timestamp for last schedule: */
    	unsigned long long		ftrace_timestamp;
    	
    	/*
    	 * Number of functions that haven't been traced
    	 * because of depth overrun:
    	 */
    	atomic_t			trace_overrun;
    	
    	/* Pause tracing: */
    	atomic_t			tracing_graph_pause;
    #endif
    
    #ifdef CONFIG_TRACING
    	/* State flags for use by tracers: */
    	unsigned long			trace;
    
    	/* Bitmask and counter of trace recursion: */
    	unsigned long			trace_recursion;
    #endif /* CONFIG_TRACING */
    
    #ifdef CONFIG_KCOV
    	/* Coverage collection mode enabled for this task (0 if disabled): */
    	unsigned int			kcov_mode;
    
    	/* Size of the kcov_area: */
    	unsigned int			kcov_size;
    	
    	/* Buffer for coverage collection: */
    	void				*kcov_area;
    	
    	/* KCOV descriptor wired with this task or NULL: */
    	struct kcov			*kcov;
    #endif
    
    #ifdef CONFIG_MEMCG
    	struct mem_cgroup		*memcg_in_oom;
    	gfp_t				memcg_oom_gfp_mask;
    	int				memcg_oom_order;
    
    	/* Number of pages to reclaim on returning to userland: */
    	unsigned int			memcg_nr_pages_over_high;
    	
    	/* Used by memcontrol for targeted memcg charge: */
    	struct mem_cgroup		*active_memcg;
    #endif
    
    #ifdef CONFIG_BLK_CGROUP
    	struct request_queue		*throttle_queue;
    #endif
    
    #ifdef CONFIG_UPROBES
    	struct uprobe_task		*utask;
    #endif
    #if defined(CONFIG_BCACHE) || defined(CONFIG_BCACHE_MODULE)
    	unsigned int			sequential_io;
    	unsigned int			sequential_io_avg;
    #endif
    #ifdef CONFIG_DEBUG_ATOMIC_SLEEP
    	unsigned long			task_state_change;
    #endif
    	int				pagefault_disabled;
    #ifdef CONFIG_MMU
    	struct task_struct		*oom_reaper_list;
    #endif
    #ifdef CONFIG_VMAP_STACK
    	struct vm_struct		*stack_vm_area;
    #endif
    #ifdef CONFIG_THREAD_INFO_IN_TASK
    	/* A live task holds one reference: */
    	refcount_t			stack_refcount;
    #endif
    #ifdef CONFIG_LIVEPATCH
    	int patch_state;
    #endif
    #ifdef CONFIG_SECURITY
    	/* Used by LSM modules for access restriction: */
    	void				*security;
    #endif
    
    #ifdef CONFIG_GCC_PLUGIN_STACKLEAK
    	unsigned long			lowest_stack;
    	unsigned long			prev_lowest_stack;
    #endif
    
    	/*
    	 * New fields for task_struct should be added above here, so that
    	 * they are included in the randomized portion of task_struct.
    	 */
    	randomized_struct_fields_end
    	
    	/* CPU-specific state of this task: */
    	struct thread_struct		thread;
    	
    	/*
    	 * WARNING: on x86, 'thread_struct' contains a variable-sized
    	 * structure.  It *MUST* be at the end of 'task_struct'.
    	 *
    	 * Do not put anything below here!
    	 */


## 参考
[https://cloud.tencent.com/developer/article/1339556](https://cloud.tencent.com/developer/article/1339556)