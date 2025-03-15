/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include <linux/mutex.h>
#include "aesdchar.h"

int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Your Name Here"); /** TODO: fill in your name **/
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

// void dump(char *ptr,size_t sz)
// {
//     size_t i;
//     for(i=0;i<sz; ++i)
//     {
//         PDEBUG("->%02X '%c'",ptr[i],ptr[i]);   
//     }
// }

static int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *pdev =  container_of(inode->i_cdev,struct aesd_dev,cdev);
    filp->private_data = pdev;
    PDEBUG("open %p %p",filp->private_data, &aesd_device);   
    pdev->rdchar_ofs=0;
    return 0;
}

static int aesd_release(struct inode *inode, struct file *filp)
{
    struct aesd_dev *pdev =container_of(inode->i_cdev,struct aesd_dev,cdev);
    PDEBUG("release");
    pdev->rdchar_ofs=0;
    filp->private_data=NULL;
    
    /**
     * TODO: handle release
     */
    return 0;
}

static ssize_t aesd_read(struct file *filp, char __user *buf, size_t count, loff_t *f_pos)
{
    struct aesd_dev *pdev = (struct aesd_dev *)filp->private_data;
    ssize_t retval = 0;
    size_t ofs,ncu,sz;
    struct aesd_buffer_entry *entry;
    if(pdev==NULL)
        return -EBADF;
    PDEBUG("read %zu bytes with offset %lld %ld",count,*f_pos,pdev->rdchar_ofs);
    mutex_lock(&pdev->lock);
    entry=aesd_circular_buffer_find_entry_offset_for_fpos(&pdev->circbuf,pdev->rdchar_ofs,&ofs);
    if(entry)
    {
        sz=entry->size-ofs;
        PDEBUG("entry esize=%ld ofs=%ld sz=%ld",entry->size,ofs,sz);
        if(count>=sz)
        {
            ncu=copy_to_user(buf,&entry->buffptr[ofs],sz);
            retval=sz;
        }
        else
        {
            ncu=copy_to_user(buf,&entry->buffptr[ofs],count);  
            retval=count; 
        }
        pdev->rdchar_ofs += retval;
    }
    mutex_unlock(&pdev->lock);
    return retval;
}


static ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    struct aesd_dev *pdev = (struct aesd_dev *)filp->private_data;
    ssize_t retval = -ENOMEM;
    size_t sz,inc,ncu,i;
    struct aesd_buffer_entry add_entry;
    char *tmp;
    const char *tofree;
    if(pdev==NULL)
        return -EBADF;
    
    PDEBUG("aesd_write %p %p",filp->private_data, &aesd_device);  
    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);
    mutex_lock(&pdev->lock);
    sz=pdev->szcmdbuf - pdev->cmdidx;
    if(sz < count)
    {
        if((count - sz)< DEF_CMDBUF_SIZE)
        {    
            inc=DEF_CMDBUF_SIZE;
        }
        else
        {
            inc=count - sz;
        }

        tmp=krealloc(pdev->cmdbuff,pdev->szcmdbuf+inc,GFP_KERNEL);
        if(tmp==NULL)
        {
            mutex_unlock(&pdev->lock);
            return -ENOMEM;
        }
        pdev->cmdbuff=tmp;
    }
    PDEBUG("copy_from_user %p %p %ld",&pdev->cmdbuff[pdev->cmdidx], buf, count);  
    ncu=copy_from_user(&pdev->cmdbuff[pdev->cmdidx],buf,count);
    retval=count;
    pdev->cmdidx+=count;

    

    i=0;
    while(i<pdev->cmdidx)
    {
        if(pdev->cmdbuff[i]=='\n')
        {
            sz=i+1;
            tmp=kmalloc(sz,GFP_KERNEL);
            PDEBUG("kmalloc %p %ld",tmp, sz);  
            if(tmp==NULL)
            {
                mutex_unlock(&pdev->lock);
                return -ENOMEM;
            }

            memcpy(tmp,pdev->cmdbuff,sz);
    
            add_entry.size=sz;
            add_entry.buffptr=tmp;
            tofree=aesd_circular_buffer_add_entry(&pdev->circbuf,&add_entry);
            if(tofree!=NULL)
            {
                PDEBUG("kfree");  
                kfree(tofree);
            }
            memcpy(pdev->cmdbuff,&pdev->cmdbuff[sz],pdev->cmdidx -sz); //move remaining string
            pdev->cmdidx -= sz;
            i=0;
        }
        else
            ++i;
    }
    mutex_unlock(&pdev->lock);
    return retval;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



static int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
	PDEBUG("aesd_init_module");
	printk(KERN_ALERT "aesd_init_module\n");
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));
    mutex_init(&aesd_device.lock);
    
    aesd_device.cmdbuff=kmalloc(DEF_CMDBUF_SIZE,GFP_KERNEL);
    if(aesd_device.cmdbuff==NULL)
    {
        printk(KERN_ALERT "NO MEM\n");  
        result=-ENOMEM;
        goto nomem;
    }
    aesd_device.szcmdbuf=DEF_CMDBUF_SIZE;
    aesd_device.cmdidx=0;
    aesd_device.rdchar_ofs=0;
    aesd_circular_buffer_init(&aesd_device.circbuf);

    result = aesd_setup_cdev(&aesd_device);

nomem:
    if( result ) 
    {
        unregister_chrdev_region(dev, 1);
    }
    return result;
}

static void aesd_cleanup_module(void)
{
    dev_t devno = MKDEV(aesd_major, aesd_minor);
    struct aesd_buffer_entry* entry;
    uint8_t index;

    PDEBUG("aesd_cleanup_module");
	printk(KERN_ALERT "aesd_cleanup_module\n");


    cdev_del(&aesd_device.cdev);

    
    
    AESD_CIRCULAR_BUFFER_FOREACH(entry,&aesd_device.circbuf,index) 
    {
        if(entry->buffptr!=NULL)
            kfree(entry->buffptr);
    }
    
    if(aesd_device.cmdbuff)
    {    
        kfree(aesd_device.cmdbuff);
    }

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
