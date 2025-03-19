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
#include "aesd_ioctl.h"

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

static size_t aesd_size(struct aesd_dev * pdev)
{
    struct aesd_buffer_entry* entry;
    uint8_t index;
    size_t size=0;

    AESD_CIRCULAR_BUFFER_FOREACH(entry,&aesd_device.circbuf,index) 
    {
        if(entry->buffptr!=NULL)
            size +=entry->size;
    }
    return size;
}

static int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *pdev =  container_of(inode->i_cdev,struct aesd_dev,cdev);
    filp->private_data = pdev;
    PDEBUG("open %p %p",filp->private_data, &aesd_device);   
    return 0;
}

static int aesd_release(struct inode *inode, struct file *filp)
{
    //struct aesd_dev *pdev =container_of(inode->i_cdev,struct aesd_dev,cdev);
    PDEBUG("release");
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
    size_t ofs,sz;
    struct aesd_buffer_entry *entry;
    if(pdev==NULL)
        return -EBADF;
    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    mutex_lock(&pdev->lock);
    entry=aesd_circular_buffer_find_entry_offset_for_fpos(&pdev->circbuf,*f_pos,&ofs);
    if(entry)
    {
        sz=entry->size-ofs;
        PDEBUG("entry esize=%ld ofs=%ld sz=%ld",entry->size,ofs,sz);
        if(count>=sz)
        {
            if(copy_to_user(buf,&entry->buffptr[ofs],sz)!=0)
            {
                mutex_unlock(&pdev->lock);
                return -EFAULT;
            }
            retval=sz;
        }
        else
        {
            if(copy_to_user(buf,&entry->buffptr[ofs],count)!=0)
            {
                mutex_unlock(&pdev->lock);
                return -EFAULT;
            }
            retval=count; 
        }
        *f_pos+=retval;
    }
    mutex_unlock(&pdev->lock);
    return retval;
}


static ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count, loff_t *f_pos)
{
    struct aesd_dev *pdev = (struct aesd_dev *)filp->private_data;
    ssize_t retval = -ENOMEM;
    size_t sz,inc,i;
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
    if(copy_from_user(&pdev->cmdbuff[pdev->cmdidx],buf,count)!=0)
    {
        mutex_unlock(&pdev->lock);
        return -EFAULT;
    }
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
    *f_pos+=retval;
    mutex_unlock(&pdev->lock);
    return retval;
}

static loff_t aesd_llseek (struct file *filp, loff_t ofs, int whence)
{
    struct aesd_dev *pdev = (struct aesd_dev *)filp->private_data;
    int size=0;
    loff_t oofs=0;
    mutex_lock(&pdev->lock);
    size=aesd_size(pdev);
    PDEBUG("aesd_llseek %d %lld",whence, ofs);  
    oofs=fixed_size_llseek(filp,ofs,whence,size);
    mutex_unlock(&pdev->lock);
    return oofs;
}

static long aesd_adjust_file_offest(struct file *filp,unsigned int write_cmd, unsigned int offset)
{
    struct aesd_dev *pdev = (struct aesd_dev *)filp->private_data;
    struct aesd_buffer_entry* entry;
    uint8_t index;

    unsigned int cmd=0;
    loff_t ofs=0;

    mutex_lock(&pdev->lock);
    PDEBUG("full=%d o=%u i=%u",pdev->circbuf.full, pdev->circbuf.out_offs, pdev->circbuf.in_offs);

    if( pdev->circbuf.full==false && pdev->circbuf.out_offs==pdev->circbuf.in_offs) //empty
    {
        mutex_unlock(&pdev->lock);
		return -EINVAL;
    }

    index=pdev->circbuf.out_offs;

    do
    {
        PDEBUG("while cmd=%u wr=%u idx=%u",cmd, write_cmd, index);
        entry=&pdev->circbuf.entry[index];
        if(cmd==write_cmd)
        {
            if(entry->buffptr!=NULL && offset<entry->size)
            {
                filp->f_pos=ofs+offset; 
                PDEBUG("aesd_adjust_file_offest %llu",filp->f_pos);
                mutex_unlock(&pdev->lock); 
                return 0;
            }   
        }
        ofs+=entry->size;
        index = (index+1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
        ++cmd;
    }while(index!=pdev->circbuf.in_offs);
    mutex_unlock(&pdev->lock);
    return -EINVAL;
}

static long aesd_ioctl (struct file *filp, unsigned int cmd , unsigned long arg)
{
    
    struct aesd_seekto argval;
    long retval=-ENOTTY;
    int err=0;
    /*
	* extract the type and number bitfields, and don't decode
	* wrong cmds: return ENOTTY (inappropriate ioctl) before access_ok()
	*/
	if (_IOC_TYPE(cmd) != AESD_IOC_MAGIC)
        return -ENOTTY;
    if (_IOC_NR(cmd) > AESDCHAR_IOC_MAXNR)
        return -ENOTTY;

    if (_IOC_DIR(cmd) & _IOC_READ)
		err = !access_ok( (void __user *)arg, _IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
		err = !access_ok( (void __user *)arg, _IOC_SIZE(cmd));
	if (err)
		return -EFAULT;

    switch (cmd)
    {
    case AESDCHAR_IOCSEEKTO:
        if(copy_from_user(&argval, (const void __user *)arg, sizeof(argval))!=0)
        {
            return -EFAULT;
        }
        PDEBUG("aesd_ioctl %u %u",argval.write_cmd, argval.write_cmd_offset);
        retval=aesd_adjust_file_offest(filp,argval.write_cmd,argval.write_cmd_offset);
        break;
    
    default:
        retval=-ENOTTY;
        break;
    }
    return retval;
}

struct file_operations aesd_fops = {
    .owner =    THIS_MODULE,
    .read =     aesd_read,
    .write =    aesd_write,
    .open =     aesd_open,
    .release =  aesd_release,
    .llseek =   aesd_llseek,
    .unlocked_ioctl = aesd_ioctl,
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
