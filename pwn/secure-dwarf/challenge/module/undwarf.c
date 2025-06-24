#include <linux/module.h>
#include <linux/printk.h>

int init_module(void) {
    printk("hi!\n");
    return 0;
}

MODULE_LICENSE("GPL");
