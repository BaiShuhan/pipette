# PIPETTE I/O Stack

This is the source code repository for the paper entitled "PIPETTE: Efficient Fine-Grained Reads for SSDs" in the 2022 Design Automation Conference.

## How to use

* Enable `CONFIG_FINE_GRAINED` (set to y).
* Enable `CONFIG_NVME_CORE` and `CONFIG_BLK_DEV_NVME` (set to y, not module).
* Enable `CONFIG_DEVMEM` and `CONFIG_ARCH_HAS_DEVMEM_IS_ALLOWED` (set to y).
* Disable `CONFIG_STRICT_DEVMEM`.
* Open a file using a `O_FINE_GRAINED` or `040000000` flag. The file should be located in Ext4 file system and in an NVMe SSD.
* Access the file in byte granularity using `read()`.
* Set the parameters of the fine-grained read cache before submitting `read()` in byte granularity.

## Warning

* The current implementation supports only one NVMe SSD at a time. If you have multiple NVMe SSDs, the macro `DEV_INSTANCE` in `drivers/nvme/host/pci.c` should be properly adjusted to specify an NVMe SSD you want to apply fine-grained reads to.
