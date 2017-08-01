#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>

#define DEVICE_NAME "wgchar"
#define CLASS_NAME  "wgcharClass"
#define PSK_LEN 32 

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Horbury");
MODULE_DESCRIPTION("A character device to push Preshared-Keys to WireGuard");
MODULE_VERSION("0.1");

static int    majorNumber;
static unsigned char   presharedKey[PSK_LEN] = {0};
static short  size_of_presharedKey; 
static int isFull = 0; //used to ensure that only one key is in the device at a time!

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
	return 0;
}

//cleanup
static void __exit wgChar_exit(void){
	device_destroy(wgcharClass, MKDEV(majorNumber, 0));
	class_unregister(wgcharClass);
	class_destroy(wgcharClass);
	unregister_chrdev(majorNumber, DEVICE_NAME);
	printk(KERN_INFO "wgChar: Shutting down!\n");
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

//called when the userspace reads the file
//simply returns a bool so state if the file is filled or not. If its filled, we do not accept more keys
static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){

	////////////////SHOULD SIMPLY RETURN WHETHER THE FILE HAS OR DOES NOT HAV A KEY
	int size = sizeof(int);
	int error_count = 0;
	// copy_to_user has the format ( * to, *from, size) and returns 0 on success

	//copies boolean to see if there is something in the device or not
	error_count = copy_to_user(buffer, &isFull, sizeof(int));

	
	if (error_count==0){            // if true then have success
		printk(KERN_INFO "wgChar: Sent %d characters to the user\n", size);
		return (size_of_presharedKey=0);  // clear the position to the start and return 0
	}
	else {
		printk(KERN_INFO "wgChar: Failed to send %d characters to the user\n", error_count);
		return -EFAULT;              // Failed -- return a bad address presharedKey (i.e. -14)
	}
}

//when the userspace writes to the file
//filep is the file
//buf is what they send, len is the len of what they sent
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
	if(len != PSK_LEN){
		printk(KERN_ALERT "wgChar: Received an incorrect length key\n");
	}
	if(!isFull){
		copy_from_user(presharedKey, buffer, PSK_LEN);
		size_of_presharedKey = len;                 // store the length of the stored presharedKey
		printk(KERN_INFO "wgChar: Received key from the user\n");
		isFull=1;
	} else {
		printk(KERN_ALERT "wgChar: Received unexpected key from the user\n");
	}
	return len;
}

//when file is closed by userspace
static int dev_release(struct inode *inodep, struct file *filep){
	printk(KERN_INFO "wgChar: Device successfully closed\n");
	return 0;
}

int getPSKfromdev(char *out) {
	memcpy(out, presharedKey, PSK_LEN);
	return 0;
}

//must be included
module_init(wgChar_init);
module_exit(wgChar_exit);
