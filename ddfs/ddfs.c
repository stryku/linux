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

static struct kmem_cache *ddfs_inode_cachep;

static struct inode *ddfs_alloc_inode(struct super_block *sb)
{
	struct msdos_inode_info *ei;
	ei = kmem_cache_alloc(ddfs_inode_cachep, GFP_NOFS);
	if (!ei)
		return NULL;

	init_rwsem(&ei->truncate_lock);
	return &ei->vfs_inode;
}

static void ddfs_free_inode(struct inode *inode)
{
	kmem_cache_free(ddfs_inode_cachep, MSDOS_I(inode));
}

static int __ddfs_write_inode(struct inode *inode, int wait)
{
	struct super_block *sb = inode->i_sb;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	struct buffer_head *bh;
	struct msdos_dir_entry *raw_entry;
	loff_t i_pos;
	sector_t blocknr;
	int err, offset;

	if (inode->i_ino == MSDOS_ROOT_INO)
		return 0;

retry:
	i_pos = fat_i_pos_read(sbi, inode);
	if (!i_pos)
		return 0;

	fat_get_blknr_offset(sbi, i_pos, &blocknr, &offset);
	bh = sb_bread(sb, blocknr);
	if (!bh) {
		fat_msg(sb, KERN_ERR,
			"unable to read inode block "
			"for updating (i_pos %lld)",
			i_pos);
		return -EIO;
	}
	spin_lock(&sbi->inode_hash_lock);
	if (i_pos != MSDOS_I(inode)->i_pos) {
		spin_unlock(&sbi->inode_hash_lock);
		brelse(bh);
		goto retry;
	}

	raw_entry = &((struct msdos_dir_entry *)(bh->b_data))[offset];
	if (S_ISDIR(inode->i_mode))
		raw_entry->size = 0;
	else
		raw_entry->size = cpu_to_le32(inode->i_size);
	raw_entry->attr = fat_make_attrs(inode);
	fat_set_start(raw_entry, MSDOS_I(inode)->i_logstart);
	fat_time_unix2fat(sbi, &inode->i_mtime, &raw_entry->time,
			  &raw_entry->date, NULL);
	if (sbi->options.isvfat) {
		__le16 atime;
		fat_time_unix2fat(sbi, &inode->i_ctime, &raw_entry->ctime,
				  &raw_entry->cdate, &raw_entry->ctime_cs);
		fat_time_unix2fat(sbi, &inode->i_atime, &atime,
				  &raw_entry->adate, NULL);
	}
	spin_unlock(&sbi->inode_hash_lock);
	mark_buffer_dirty(bh);
	err = 0;
	if (wait)
		err = sync_dirty_buffer(bh);
	brelse(bh);
	return err;
}

static int ddfs_write_inode(struct inode *inode, struct writeback_control *wbc)
{
	return __ddfs_write_inode(inode, wbc->sync_mode == WB_SYNC_ALL);
}

static void ddfs_evict_inode(struct inode *inode)
{
	truncate_inode_pages_final(&inode->i_data);
	if (!inode->i_nlink) {
		inode->i_size = 0;
		fat_truncate_blocks(inode, 0);
	} else
		fat_free_eofblocks(inode);

	invalidate_inode_buffers(inode);
	clear_inode(inode);
	fat_cache_inval_inode(inode);
	fat_detach(inode);
}

static void ddfs_put_super(struct super_block *sb)
{
	struct msdos_sb_info *sbi = MSDOS_SB(sb);

	fat_set_state(sb, 0, 0);

	iput(sbi->fsinfo_inode);
	iput(sbi->fat_inode);

	call_rcu(&sbi->rcu, delayed_free);
}

static int ddfs_statfs(struct dentry *dentry, struct kstatfs *buf)
{
	struct super_block *sb = dentry->d_sb;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	u64 id = huge_encode_dev(sb->s_bdev->bd_dev);

	/* If the count of free cluster is still unknown, counts it here. */
	if (sbi->free_clusters == -1 || !sbi->free_clus_valid) {
		int err = fat_count_free_clusters(dentry->d_sb);
		if (err)
			return err;
	}

	buf->f_type = dentry->d_sb->s_magic;
	buf->f_bsize = sbi->cluster_size;
	buf->f_blocks = sbi->max_cluster - FAT_START_ENT;
	buf->f_bfree = sbi->free_clusters;
	buf->f_bavail = sbi->free_clusters;
	buf->f_fsid.val[0] = (u32)id;
	buf->f_fsid.val[1] = (u32)(id >> 32);
	buf->f_namelen =
		(sbi->options.isvfat ? FAT_LFN_LEN : 12) * NLS_MAX_CHARSET_SIZE;

	return 0;
}

static int ddfs_remount(struct super_block *sb, int *flags, char *data)
{
	bool new_rdonly;
	struct msdos_sb_info *sbi = MSDOS_SB(sb);
	*flags |= SB_NODIRATIME | (sbi->options.isvfat ? 0 : SB_NOATIME);

	sync_filesystem(sb);

	/* make sure we update state on remount. */
	new_rdonly = *flags & SB_RDONLY;
	if (new_rdonly != sb_rdonly(sb)) {
		if (new_rdonly)
			fat_set_state(sb, 0, 0);
		else
			fat_set_state(sb, 1, 1);
	}
	return 0;
}

static int ddfs_show_options(struct seq_file *m, struct dentry *root);
static const struct super_operations ddfs_sops = {
	.alloc_inode = ddfs_alloc_inode,
	.free_inode = ddfs_free_inode,
	.write_inode = ddfs_write_inode,
	.evict_inode = ddfs_evict_inode,
	.put_super = ddfs_put_super,
	.statfs = ddfs_statfs,
	.remount_fs = ddfs_remount,

	.show_options = ddfs_show_options,
};

static int ddfs_show_options(struct seq_file *m, struct dentry *root)
{
	struct msdos_sb_info *sbi = MSDOS_SB(root->d_sb);
	struct fat_mount_options *opts = &sbi->options;
	int isvfat = opts->isvfat;

	if (!uid_eq(opts->fs_uid, GLOBAL_ROOT_UID))
		seq_printf(m, ",uid=%u",
			   from_kuid_munged(&init_user_ns, opts->fs_uid));
	if (!gid_eq(opts->fs_gid, GLOBAL_ROOT_GID))
		seq_printf(m, ",gid=%u",
			   from_kgid_munged(&init_user_ns, opts->fs_gid));
	seq_printf(m, ",fmask=%04o", opts->fs_fmask);
	seq_printf(m, ",dmask=%04o", opts->fs_dmask);
	if (opts->allow_utime)
		seq_printf(m, ",allow_utime=%04o", opts->allow_utime);
	if (sbi->nls_disk)
		/* strip "cp" prefix from displayed option */
		seq_printf(m, ",codepage=%s", &sbi->nls_disk->charset[2]);
	if (isvfat) {
		if (sbi->nls_io)
			seq_printf(m, ",iocharset=%s", sbi->nls_io->charset);

		switch (opts->shortname) {
		case VFAT_SFN_DISPLAY_WIN95 | VFAT_SFN_CREATE_WIN95:
			seq_puts(m, ",shortname=win95");
			break;
		case VFAT_SFN_DISPLAY_WINNT | VFAT_SFN_CREATE_WINNT:
			seq_puts(m, ",shortname=winnt");
			break;
		case VFAT_SFN_DISPLAY_WINNT | VFAT_SFN_CREATE_WIN95:
			seq_puts(m, ",shortname=mixed");
			break;
		case VFAT_SFN_DISPLAY_LOWER | VFAT_SFN_CREATE_WIN95:
			seq_puts(m, ",shortname=lower");
			break;
		default:
			seq_puts(m, ",shortname=unknown");
			break;
		}
	}
	if (opts->name_check != 'n')
		seq_printf(m, ",check=%c", opts->name_check);
	if (opts->usefree)
		seq_puts(m, ",usefree");
	if (opts->quiet)
		seq_puts(m, ",quiet");
	if (opts->showexec)
		seq_puts(m, ",showexec");
	if (opts->sys_immutable)
		seq_puts(m, ",sys_immutable");
	if (!isvfat) {
		if (opts->dotsOK)
			seq_puts(m, ",dotsOK=yes");
		if (opts->nocase)
			seq_puts(m, ",nocase");
	} else {
		if (opts->utf8)
			seq_puts(m, ",utf8");
		if (opts->unicode_xlate)
			seq_puts(m, ",uni_xlate");
		if (!opts->numtail)
			seq_puts(m, ",nonumtail");
		if (opts->rodir)
			seq_puts(m, ",rodir");
	}
	if (opts->flush)
		seq_puts(m, ",flush");
	if (opts->tz_set) {
		if (opts->time_offset)
			seq_printf(m, ",time_offset=%d", opts->time_offset);
		else
			seq_puts(m, ",tz=UTC");
	}
	if (opts->errors == FAT_ERRORS_CONT)
		seq_puts(m, ",errors=continue");
	else if (opts->errors == FAT_ERRORS_PANIC)
		seq_puts(m, ",errors=panic");
	else
		seq_puts(m, ",errors=remount-ro");
	if (opts->nfs == FAT_NFS_NOSTALE_RO)
		seq_puts(m, ",nfs=nostale_ro");
	else if (opts->nfs)
		seq_puts(m, ",nfs=stale_rw");
	if (opts->discard)
		seq_puts(m, ",discard");
	if (opts->dos1xfloppy)
		seq_puts(m, ",dos1xfloppy");

	return 0;
}

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
