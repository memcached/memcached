#include <linux/uaccess.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <asm/uaccess.h>

#define PROC_DIR		"ubuntu-host"

#define ESM_TOKEN_FILE		"esm-token"
#define ESM_TOKEN_MAX_SIZE		64

static struct proc_dir_entry *proc_dir;
static char esm_token_buffer[ESM_TOKEN_MAX_SIZE];

static ssize_t esm_token_read(struct file *f, char __user *buf, size_t len,
			      loff_t *off)
{
	return simple_read_from_buffer(buf, len, off, esm_token_buffer,
				       strlen(esm_token_buffer));
}

static ssize_t esm_token_write(struct file *f, const char __user *buf,
			       size_t len, loff_t *off)
{
	ssize_t ret;

	if (len >= ESM_TOKEN_MAX_SIZE - 1)
		return -EINVAL;

	ret = simple_write_to_buffer(esm_token_buffer, ESM_TOKEN_MAX_SIZE - 1,
				     off, buf, len);
	if (ret >= 0)
		esm_token_buffer[ret] = '\0';

	return ret;
}

static const struct proc_ops esm_token_fops = {
	.proc_read = esm_token_read,
	.proc_write = esm_token_write,
};

static void ubuntu_host_cleanup(void)
{
	remove_proc_entry(ESM_TOKEN_FILE, proc_dir);
	proc_remove(proc_dir);
}

static int __init ubuntu_host_init(void)
{
	proc_dir = proc_mkdir(PROC_DIR, NULL);
	if (!proc_dir) {
		pr_err("Failed to create ubuntu-host dir\n");
		return -ENOMEM;
	}

	if (!proc_create_data(ESM_TOKEN_FILE, 0644, proc_dir, &esm_token_fops, NULL)) {
		pr_err("Failed to create esm-tokan file\n");
		ubuntu_host_cleanup();
		return -ENOMEM;
	}

	return 0;
}

module_init(ubuntu_host_init);
module_exit(ubuntu_host_cleanup);
MODULE_LICENSE("GPL");
