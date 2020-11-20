#include <linux/init.h>
#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/kernel.h>
#include <linux/iversion.h>

#define DDFS_SUPER_MAGIC 0xddf5

#define dd_print(...)                                                          \
	do {                                                                   \
		printk(KERN_INFO "-------------------[DDFS]: " __VA_ARGS__);   \
	} while (0);

#define dd_error(...)                                                          \
	do {                                                                   \
		printk(KERN_ERR                                                \
		       "-------------------[DDFS ERR]: " __VA_ARGS__);         \
	} while (0);

MODULE_LICENSE("Dual BSD/GPL");

struct ddfs_sb_info {
	unsigned int table_offset; // From begin of partition
	unsigned int table_size; // In bytes
	unsigned int number_of_table_entries;

	unsigned int cluster_size; // In bytes

	unsigned int data_offset; // From begin of partition
};

static const struct super_operations ddfs_sops = {
	.alloc_inode = fat_alloc_inode,
	.free_inode = fat_free_inode,
	.write_inode = fat_write_inode,
	.evict_inode = fat_evict_inode,
	.put_super = fat_put_super,
	.statfs = fat_statfs,
	.remount_fs = fat_remount,

	.show_options = fat_show_options,
};

const struct export_operations fat_export_ops = {
	.fh_to_dentry = fat_fh_to_dentry,
	.fh_to_parent = fat_fh_to_parent,
	.get_parent = fat_get_parent,
};

static const struct inode_operations vfat_dir_inode_operations = {
	.create = vfat_create,
	.lookup = vfat_lookup,
	.unlink = vfat_unlink,
	.mkdir = vfat_mkdir,
	.rmdir = vfat_rmdir,
	.rename = vfat_rename,
	.setattr = fat_setattr,
	.getattr = fat_getattr,
	.update_time = fat_update_time,
};

static const struct dentry_operations vfat_dentry_ops = {
	.d_revalidate = vfat_revalidate,
	.d_hash = vfat_hash,
	.d_compare = vfat_cmp,
};

struct ddfs_boot_sector {
	__u16 sector_size;
	__u8 sectors_per_cluster;
	__u32 number_of_clusters;
};

long ddfs_read_boot_sector(struct super_block *sb, void *data,
			   struct ddfs_boot_sector *boot_sector)
{
	memcpy(boot_sector, data, sizeof(struct ddfs_boot_sector));
	return 0;
}

void log_boot_sector(struct ddfs_boot_sector *boot_sector)
{
	dd_print("sector_size: %u, s/c: %u, number_of_clusters: %u",
		 boot_sector->sector_size, boot_sector->sectors_per_cluster,
		 boot_sector->number_of_clusters);
}

unsigned int calculate_data_offset(struct msdos_sb_info *sbi)
{
	unsigned int first_data_cluster = 1; // 1 for boot sector
	unsigned int table_end = sbi->table_offset + sbi->table_size;

	first_data_cluster += table_end / sbi->cluster_size;

	if (table_end % sbi->cluster_size != 0) {
		++first_data_cluster;
	}

	return first_data_cluster * sbi->cluster_size;
}

static int ddfs_fill_super(struct super_block *sb, void *data, int silent)
{
	struct msdos_sb_info *sbi;
	long error;
	struct buffer_head *bh;
	struct ddfs_boot_sector boot_sector;

	sbi = kzalloc(sizeof(struct ddfs_sb_info), GFP_KERNEL);
	if (!sbi)
		return -ENOMEM;
	sb->s_fs_info = sbi;

	sb->s_flags |= SB_NODIRATIME;
	sb->s_magic = DDFS_SUPER_MAGIC;
	sb->s_op = &fat_sops;
	sb->s_export_op = &fat_export_ops;
	sb->s_time_gran = 1;
	mutex_init(&sbi->nfs_build_inode_lock);
	ratelimit_state_init(&sbi->ratelimit, DEFAULT_RATELIMIT_INTERVAL,
			     DEFAULT_RATELIMIT_BURST);

	error = parse_options(sb, data, isvfat, silent, &debug, &sbi->options);
	if (error) {
		goto out_fail;
	}

	sb->s_fs_info->dir_ops = &vfat_dir_inode_operations;
	sb->s_d_op = &vfat_dentry_ops;

	error = -EIO;
	sb_min_blocksize(sb, 512);
	bh = sb_bread(sb, 0);
	if (bh == NULL) {
		dd_error("unable to read SB");
		goto out_fail;
	}

	error = ddfs_read_boot_sector(sb, bh->b_data, &boot_sector);
	if (error == -EINVAL) {
		dd_error("unable to read boot sector");
		goto out_fail;
	}
	brelse(bh);
	log_boot_sector(&boot_sector);

	sbi->sec_per_clus = boot_sector.sectors_per_cluster;

	mutex_init(&sbi->s_lock);
	sbi->cluster_size = sb->s_blocksize * sbi->sec_per_clus;
	sbi->number_of_table_entries = boot_sector.number_of_clusters;
	sbi->table_start = sbi->cluster_size;
	sbi->table_size =
		boot_sector.number_of_clusters * sizeof(struct ddfs_dir_entry);
	sbi->data_offset = calculate_data_offset(sbi);

	return -EINVAL;

out_fail:
	sb->s_fs_info = NULL;
	kfree(sbi);
	return error;
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
