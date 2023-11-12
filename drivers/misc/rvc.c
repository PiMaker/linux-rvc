#include <linux/module.h>
#include <linux/printk.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/random.h>
#include <asm/csr.h>

#define CSR_PLAYER_ID 0x0be
#define CSR_RNG 0x0bf

static struct kobject *rvc_kobject;

// HELPERS

static void add_rng_entropy(void)
{
    uint32_t rvc_rng, i;
    pr_info("[_pi_] adding 16 byte of rvc randomness to entropy pool\n");
    for (i = 0; i < (16 / sizeof(rvc_rng)); i++) {
        rvc_rng = csr_read(CSR_RNG);
        add_hwgenerator_randomness(&rvc_rng, sizeof(rvc_rng), sizeof(rvc_rng), false);
    }
}

// SYSFS ENTRIES

static ssize_t player_id_show(struct kobject *kobj, struct kobj_attribute *attr,
                              char *buf)
{
    uint32_t player_id = csr_read(CSR_PLAYER_ID);
    return sprintf(buf, "%d", player_id);
}
static struct kobj_attribute player_id_attribute = __ATTR_RO(player_id);

static ssize_t sync_rng_store(struct kobject *kobj, struct kobj_attribute *attr,
                              const char *buf, size_t count)
{
    add_rng_entropy();
    return count;
}
static struct kobj_attribute sync_rng_attribute = __ATTR_WO(sync_rng);

// SETUP

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
    }

    error = sysfs_create_file(rvc_kobject, &sync_rng_attribute.attr);
    if (error) {
        pr_err("[_pi_] failed to create rvc sysfs entry 'sync_rng': %d\n",
               error);
    }

    pr_info("[_pi_] rvc sysfs entries created\n");

    // add some at boot
    add_rng_entropy();

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
