#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/semaphore.h>

#define DEVICE_NAME "wgchar"
#define CLASS_NAME  "wgcharClass"
#define PSK_LEN 32 

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Horbury");
MODULE_DESCRIPTION("A character device to push Preshared-Keys to WireGuard");
MODULE_VERSION("0.1");

static int    majorNumber;
static unsigned char   presharedKey[PSK_LEN] = {0};

static struct semaphore readingSemaphore;
static struct semaphore writingSemaphore;

static int    numberOpens = 0;
static struct class*  wgcharClass  = NULL;
static struct device* wgCharDevice = NULL;

// The prototype functions for the character driver -- must come before the struct definition
static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);


static struct file_operations fops = {
	.open = dev_open,
	.read = dev_read,
	.write = dev_write,
	.release = dev_release,
};

//called when initialising the device
static int __init wgChar_init(void){
	printk(KERN_INFO "wgChar: Initializing the wgChar LKM\n");

	// Try to dynamically allocate a major number for the device -- more difficult but worth it
	majorNumber = register_chrdev(0, DEVICE_NAME, &fops);
	if (majorNumber<0){
		printk(KERN_ALERT "wgChar failed to register a major number\n");
		return majorNumber;
	}
	printk(KERN_INFO "wgChar: registered correctly with major number %d\n", majorNumber);

	// Register the device class
	wgcharClass = class_create(THIS_MODULE, CLASS_NAME);
	if (IS_ERR(wgcharClass)){
		unregister_chrdev(majorNumber, DEVICE_NAME);
		printk(KERN_ALERT "Failed to register device class\n");
		return PTR_ERR(wgcharClass);
	}
	printk(KERN_INFO "wgChar: device class registered correctly\n");

	// Register the device driver
	wgCharDevice = device_create(wgcharClass, NULL, MKDEV(majorNumber, 0), NULL, DEVICE_NAME);
	if (IS_ERR(wgCharDevice)){               
		class_destroy(wgcharClass);           
		unregister_chrdev(majorNumber, DEVICE_NAME);
		printk(KERN_ALERT "Failed to create the device\n");
		return PTR_ERR(wgCharDevice);
	}
	printk(KERN_INFO "wgChar: device class created correctly\n");

	//init read/write semaphore
	sema_init(&readingSemaphore, 0);
	sema_init(&writingSemaphore, 1);

	return 0;
}

//cleanup
static void __exit wgChar_exit(void){
	device_destroy(wgcharClass, MKDEV(majorNumber, 0));
	class_unregister(wgcharClass);
	class_destroy(wgcharClass);
	unregister_chrdev(majorNumber, DEVICE_NAME);
	printk(KERN_INFO "wgChar: Shutting down_interruptible!\n");
}

//Called when a user opens the file
static int dev_open(struct inode *inodep, struct file *filep){
	numberOpens++;
	if (numberOpens>1) {
		printk(KERN_ALERT "wgChar: Device has been opened more than once!");
	} else {
		printk(KERN_INFO "wgChar: Device has been opened.\n");   
	}
	
	return 0;
}

//called when read, should not be done as we never read from userspace
static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
	copy_to_user(buffer, "\0", sizeof(char));
	printk(KERN_ALERT "wgChar: User tried to read key!\n");
	return 1;
}

//when the userspace writes to the file
//filep is the file
//buf is what they send, len is the len of what they sent
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
	if(len != PSK_LEN){
		printk(KERN_ALERT "wgChar: Received an incorrect length key\n");
		return 1;
	}
	//try to down the semaphore allowing us to write
	down_interruptible(&writingSemaphore);
	copy_from_user(presharedKey, buffer, PSK_LEN);
	printk(KERN_INFO "wgChar: Received key from the user\n");
	//allow people to read the data we just sabed
	up(&readingSemaphore);

	return len;
}

//when file is closed by userspace
static int dev_release(struct inode *inodep, struct file *filep){
	printk(KERN_INFO "wgChar: Device successfully closed\n");
	return 0;
}


int getPSKfromdev(u8 *out);
EXPORT_SYMBOL(getPSKfromdev);

int getPSKfromdev(u8 *out) {
	printk(KERN_INFO "wgChar: Trying to get the PSK.\n");
	//try to down and read the data
	down_interruptible(&readingSemaphore);
	memcpy(out, presharedKey, PSK_LEN);
	printk(KERN_INFO "wgChar: got the PSK from the device.\n");
	memset(presharedKey, '\x00', PSK_LEN);
	//up to allow a new key to be entered
	up(&writingSemaphore);
	return 0;
}

//must be included
module_init(wgChar_init);
module_exit(wgChar_exit);
