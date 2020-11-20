#include <linux/init.h>
#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/kernel.h>
#include <linux/iversion.h>

#define dd_print(...)                                                          \
	do {                                                                   \
		printk(KERN_INFO "-------------------[DDFS]: " __VA_ARGS__);   \
	} while (0);

MODULE_LICENSE("Dual BSD/GPL");

static int ddfs_fill_super(struct super_block *sb, void *data, int silent)
{
	return -EINVAL;
}

static struct dentry *ddfs_mount(struct file_system_type *fs_type, int flags,
				 const char *dev_name, void *data)
{
	dd_print("init_ddfs_fs\n");
	// return mount_bdev(fs_type, flags, dev_name, data, ddfs_fill_super);
	return ERR_PTR(-EINVAL);
}

static struct file_system_type ddfs_fs_type = {
	.owner = THIS_MODULE,
	.name = "ddfs",
	.mount = ddfs_mount,
	.kill_sb = kill_block_super,
	.fs_flags = FS_REQUIRES_DEV,
};

static int __init init_ddfs_fs(void)
{
	dd_print("init_ddfs_fs\n");
	return register_filesystem(&ddfs_fs_type);
}

static void __exit exit_ddfs_fs(void)
{
	dd_print("exit_ddfs_fs\n");
	unregister_filesystem(&ddfs_fs_type);
}

MODULE_ALIAS_FS("ddfs");

module_init(init_ddfs_fs);
module_exit(exit_ddfs_fs);
