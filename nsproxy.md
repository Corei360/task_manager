## 命名空间

	/* include/linux/nsproxy.h */
	
	/* 'count' is the number of tasks holding a reference.
	 * The count for each namespace, then, will be the number
	 * of nsproxies pointing to it, not the number of tasks.
	 * The nsproxy is shared by tasks which share all namespaces.
	 * As soon as a single namespace is cloned or unshared, the
	 * nsproxy is copied
	*/
	struct nsproxy
	{
	         atomic_t count;
	         struct uts_namespace *uts_ns;
	         struct ipc_namespace *ipc_ns;
	         struct mnt_namespace *mnt_ns;
	         struct pid_namespace *pid_ns_for_children;
	         struct net             *net_ns;
	};
这里一共定义了5个各自的命名空间结构体，在该结构体中定义了5个指向各个类型namespace的指针，由于多个进程可以使用同一个namespace，所以nsproxy可以共享使用，count字段是该结构的引用计数。

* UTS命名空间包含了运行内核的名称、版本、底层体系结构类型等信息。UTS是UNIX Timesharing System的简称。  
* 保存在struct ipc_namespace中的所有与进程间通信（IPC）有关的信息。
* 已经装载的文件系统的视图，在struct mnt_namespace中给出。
* 有关进程ID的信息，由struct pid_namespace提供。
* struct net_ns包含所有网络相关的命名空间参数。

系统中有一个默认的nsproxy，init_nsproxy，该结构在task初始化是也会被初始，定义在include/linux/init_task.h

	#define INIT_TASK(tsk)  \
	{
	……..
	         .nsproxy   = &init_nsproxy,      
	……..
	}

其中init_nsproxy的定义为：

	struct nsproxy init_nsproxy = {
	         .count                         = ATOMIC_INIT(1),
	         .uts_ns                       = &init_uts_ns,
	#if defined(CONFIG_POSIX_MQUEUE) || defined(CONFIG_SYSVIPC)
	         .ipc_ns                        = &init_ipc_ns,
	#endif
	         .mnt_ns                      = NULL,
	         .pid_ns_for_children        = &init_pid_ns,
	#ifdef CONFIG_NET
	         .net_ns                       = &init_net,
	#endif
	};

对于.mnt_ns没有进行初始化，其余的namespace都进行了系统默认初始化；

## 命名空间的创建

TODO