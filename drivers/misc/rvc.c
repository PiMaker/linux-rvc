#include <linux/module.h>
#include <linux/printk.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <asm/csr.h>

#define CSR_PLAYER_ID 0x0be

static struct kobject *rvc_kobject;

static ssize_t player_id_show(struct kobject *kobj, struct kobj_attribute *attr,
                              char *buf)
{
    uint32_t player_id = csr_read(CSR_PLAYER_ID);
    return sprintf(buf, "%d", player_id);
}

static ssize_t player_id_store(struct kobject *kobj,
                               struct kobj_attribute *attr,
                               const char *buf, size_t count)
{
    return -EINVAL;
}


static struct kobj_attribute player_id_attribute = __ATTR(player_id, 0444,
                                                          player_id_show,
                                                          player_id_store);

static int __init rvc_sysfs_init(void)
{
    int error;

    rvc_kobject = kobject_create_and_add("rvc", kernel_kobj);
    if(!rvc_kobject)
        return -ENOMEM;

    error = sysfs_create_file(rvc_kobject, &player_id_attribute.attr);
    if (error) {
        pr_err("[_pi_] failed to create rvc sysfs entry 'player_id': %d\n",
               error);
        return error;
    } else {
        pr_info("[_pi_] rvc sysfs entries created\n");
    }

    return 0;
}

static void __exit rvc_sysfs_exit(void)
{
    pr_debug ("[_pi_] rvc sysfs module unloaded\n");
    kobject_put(rvc_kobject);
}

module_init(rvc_sysfs_init);
module_exit(rvc_sysfs_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("_pi_");
