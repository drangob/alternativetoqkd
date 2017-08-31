#include <linux/init.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <asm/uaccess.h>
#include <linux/semaphore.h>
#include <linux/slab.h>

#define DEVICE_NAME "wgchar"
#define CLASS_NAME  "wgcharClass"
#define PSK_LEN 32 

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Daniel Horbury");
MODULE_DESCRIPTION("A character device to push Preshared-Keys to WireGuard");
MODULE_VERSION("0.2");

static int majorNumber = 0;
static unsigned char presharedKey[PSK_LEN] = {0};
static u32 inputFileNum = 0;
static u64 inputByteOffset = 0;

static struct semaphore userGetVectorSemaphore;
static struct semaphore kernelGetDataSemaphore;

static int isWriteError = 0;

static int    numberOpens = 0;
static struct class*  wgcharClass  = NULL;
static struct device* wgCharDevice = NULL;

// The prototype functions for the character driver -- must come before the struct definition
static int     dev_open(struct inode *, struct file *);
static int     dev_release(struct inode *, struct file *);
static ssize_t dev_read(struct file *, char *, size_t, loff_t *);
static ssize_t dev_write(struct file *, const char *, size_t, loff_t *);

enum requestType {
	KEYANDSTATE,
	KEYFROMSTATE
};

//request vector
struct requestVector {
	enum requestType requestType;
	u32 fileNum;
	u64 byteOffset;
};

static struct requestVector requestVec;


static struct file_operations fops = {
	.open = dev_open,
	.read = dev_read,
	.write = dev_write,
	.release = dev_release,
};


int packRequestVector(struct requestVector *requestVector, unsigned char *buf) {
	int offset = 0;
	memcpy(buf + offset, &requestVector->requestType, sizeof(enum requestType));
	offset += sizeof(enum requestType);
	memcpy(buf + offset, &requestVector->fileNum, sizeof(u32));
	offset += sizeof(u32);
	memcpy(buf + offset, &requestVector->byteOffset, sizeof(u64));

	return 0;
}


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

	sema_init(&userGetVectorSemaphore, 0);
	sema_init(&kernelGetDataSemaphore, 0);
	requestVec.fileNum = 0;
	requestVec.byteOffset = 0;

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

//called when read, should provide a request vector so the userspace knows what to do
static ssize_t dev_read(struct file *filep, char *buffer, size_t len, loff_t *offset){
	if(len != sizeof(struct requestVector)) {
		printk(KERN_ALERT "wgChar: user requested wrong size.");
		return 1;
	}
	printk(KERN_INFO "wgChar: user has requested the request vector");
	//when the requestvector is filled, we can do stuff
	down_interruptible(&userGetVectorSemaphore);

	//send it over
	copy_to_user(buffer, &requestVec, sizeof(requestVec));

	printk(KERN_INFO "wgChar: User got the requestvector!\n");
	return 0;
}

//when the userspace writes to the file
//filep is the file
//buf is what they send, len is the len of what they sent
static ssize_t dev_write(struct file *filep, const char *buffer, size_t len, loff_t *offset){
	int requiredLength = PSK_LEN + sizeof(u32) + sizeof(u64);
	int memcpyOffset;
	unsigned char *inputBuffer;
	//user should give key + state info
	if(len != requiredLength){
		//if there is an error, we can't afford to keep semaphores locked down
		//therefore we set a flag to enable us to release for semaphore for a second run
		printk(KERN_ALERT "wgChar: Received an incorrect length input.\n");
		isWriteError = 1;
		up(&kernelGetDataSemaphore);
		return 1;
	}
	isWriteError = 0;
	//copy in the data
	inputBuffer = kmalloc(requiredLength, GFP_KERNEL);
	copy_from_user(inputBuffer, buffer, requiredLength);

	memcpyOffset = 0;
	memcpy(presharedKey, inputBuffer + memcpyOffset, PSK_LEN);
	memcpyOffset += PSK_LEN;
	memcpy(&inputFileNum, inputBuffer + memcpyOffset, sizeof(u32));
	memcpyOffset += sizeof(u32);
	memcpy(&inputByteOffset, inputBuffer + memcpyOffset, sizeof(u64));

	printk(KERN_INFO "wgChar: Received key + state from the user\n");
	printk(KERN_INFO "wgchar: FILE = %u STATE = %llu \n", inputFileNum, inputByteOffset);
	//allow people to read the data we just saved
	up(&kernelGetDataSemaphore);

	return len;
}

//when file is closed by userspace
static int dev_release(struct inode *inodep, struct file *filep){
	printk(KERN_INFO "wgChar: Device successfully closed\n");
	numberOpens=0;
	//release waiting wireguard query
	up(&kernelGetDataSemaphore);
	return 0;
}


int getKeyAndState(u8 *out, __le32 *fileNum, __le64 *byteOffset);
EXPORT_SYMBOL(getKeyAndState);
int getKeyAndState(u8 *out, __le32 *fileNum, __le64 *byteOffset) {
	//if there is no open, we simply return. 
	if(!numberOpens) return -1;
	printk(KERN_INFO "wgChar: trying to get key and state from userspace.");
	requestVec.requestType = KEYANDSTATE;
	//allow the user to read the requestvector so they can respond accordingly
	up(&userGetVectorSemaphore);

	//make the kernel wait until the user has given data
	down_interruptible(&kernelGetDataSemaphore);
	//if the device is closed or a write error occurred return
	if(!numberOpens || isWriteError) return -1;

	//get the data
	memcpy(out, presharedKey, PSK_LEN);
	*fileNum = cpu_to_le32(inputFileNum);
	*byteOffset = cpu_to_le64(inputByteOffset);

	if(is_empty(presharedKey, PSK_LEN)){
		return 1;
	}

	return 0;
}

int is_empty(char *buf, int size){
	return buf[0] == 0 && !memcmp(buf, buf + 1, size - 1);
}

int getKeyFromState(u8 *out, __le32 *fileNum,  __le64 *byteOffset);
EXPORT_SYMBOL(getKeyFromState);
int getKeyFromState(u8 *out, __le32 *fileNum,  __le64 *byteOffset) {
	//if nobody has us open, we return
	if(!numberOpens) return -1;
	printk(KERN_INFO "wgChar: trying to get key from state, from userspace.");
	requestVec.requestType = KEYFROMSTATE;
	requestVec.fileNum = cpu_to_le32(*fileNum);
	requestVec.byteOffset = cpu_to_le64(*byteOffset);

	//allow the user to read the requestvector so they can respond accordingly
	up(&userGetVectorSemaphore);

	//make the kernel wait until the user has given data
	down_interruptible(&kernelGetDataSemaphore);
	//if the device is closed or a write error occurred return
	if(!numberOpens || isWriteError) return -1;

	//get the data
	memcpy(out, presharedKey, PSK_LEN);
	*fileNum = cpu_to_le32(inputFileNum);
	*byteOffset = cpu_to_le64(inputByteOffset);

	if(is_empty(presharedKey, PSK_LEN)){
		return 1;
	}

	return 0;
}


//must be included
module_init(wgChar_init);
module_exit(wgChar_exit);
