# Digital Forensics

## Disks/block devices

### MBR

Use hex editor to examine disk's first 512bytes. MBR is divided into:
1. Bootstrapcode (446 bytes) - holds bootloader code
2. Partition table (64 bytes) -  holds data about each of 4 primary partitions (16 bytes each):
   1. Boot indicator (1 byte) - Either `00` or `80`.
   2. Starting CHS Address (3 bytes) - ie. `20 21 00`
   3. Partition type (1 byte) - ie. `07` for NTFS
   4. Ending CHS Address (3 bytes) - ie. `FE FF FF`
   5. Starting LBA Address (4 bytes) - ie. `00 08 00 00`
   6. Number of Sectors (4 bytes) - ie. `00 B0 23 03`
3. MBR Signature (2 bytes) - Magic Number `55 AA` to mark end of MBR

### GPT

GPT is divided into:
1. Protective MBR
   1. Bootloader Code: This bootloader code is not the same as it is in the general MBR. This bootloader code does not perform any function during the boot process. It is just there to look like it's the same standard MBR bootloader. This would be all 00s in most scenarios; however, sometimes, this can contain some placeholder code for legacy compatibility.
   2. Partition Table: This partition table contains only one partition (the first 16 bytes), and this partition has one job; to redirect the system to the EFI Partition (which we will discuss later). The screenshot of the protective MBR above shows that it only has one partition in the table, and the other partitions are labeled with 0s. In this single partition, there is only one important thing: the 4th byte. This byte is set to `EE`, indicating that this is a GPT-formatted disk.
   3. MBR Signature: The MBR signature is the same as in the standard MBR. It is set to `55 AA` and marks the end of the Protective MBR.
2. Primary GPT Header
   1. Signature: This field has a value 45 46 49 20 50 41 52 54 which recognizes it as a GPT header. This value is always at the start of the GPT header.
   2. Revision: The revision number is of 4 bytes and it represents the version of the GPT. Most of the times it would be 00 00 01 00 which means the GPT version is 1.0.
   3. Header Size: This field represents the size of the GPT header. It is typically 5C 00 00 00 in hex and if you convert it to decimal (after reversing the order of bytes as they are in little-endian), it is 92 bytes which is the length of the GPT header.
   4. CRC32 of Header: This is the CRC32 checksum of the GPT header, which if changed, would indicate that either the GPT header is tampered or corrupted.
   5. Reserved: These are reserved bytes. The purpose of having them is to utilize them for any future changes in the GPT header.
   6. Current LBA: The Current Logical Block Address (LBA) indicates the location of the GPT header. We know that its location is in sector 1, and we can verify this by converting the 8 Current LBA bytes 01 00 00 00 00 00 00 00 into decimal.
   7. Backup LBA: In the GPT partitioning scheme, we have a backup of the GPT header as well, which we will be studying later on in this task. This field indicates the LBA of the backup GPT header.
   8. First Usable LBA: This LBA address indicates the first address from which the partition can start on the disk.
   9. Last Usable LBA: This LBA address indicates the last address to which the partitions on the disk can be written. Any partitions cannot occupy the disk space after the last usable LBA.
   10. Disk GUID: This field is of 16 bytes and it presents a Globally Unique Identifier of the disk. The purpose of this GUID is to distinguish the disk from any other disks present in the system. In the current GPT header that we are analyzing, these bytes are 1D F1 B0 D6 43 BE 37 4E B1 E6 38 66 EC B1 73 89. We can convert them to the standard GUID format of the disk by just reformatting them as 1DF1B0D6-43BE-374E-B1E6-3866ECB17389.
   11. Partition Entry Array LBA: This LBA address indicates the start of the Partition Entry Array which we are going to discuss ahead as the 3rd component of the GPT.
   12. Number of Partition Entries: This field indicates the number of partitions that are on the disk. The GPT supports 128 partitions, unlike the MBR, which supports 4 partitions only. The value of this field is 80 00 00 00 which if converted to decimal will be 128.
   13. Size of Each Partition Entry: This field indicates the size occupied by each partition entry array. In this example, it set to 80 00 00 00 which is 128 in decimal. It is important to note that this is not the size of the partition itself. This is just the size of partition entry array that we would be discussing next.
   14. CRC32 of Partition Array: This is the CRC32 checksum of the whole partition entry array, which if changed, would indicate that either the partition entry array is tampered or corrupted.
3. Partition Entry Array - We saw that sector zero was occupied by the Protective MBR, and the GPT header occupied sector 1. Now, from sector 2, the Partition Entry Array starts, just like the partition table present in the MBR, with a few differences. There are a total of 128 partitions on a GPT disk, and this partition entry array contains information about all these partitions.  Below is the screenshot of the Partition Entry Array of a GPT disk. Each partition entry is represented by 128 bytes.  You can only see the 6 partition entries out of the total 128 partition entries of the GPT. This is because there are only six working partitions in this disk. These six partitions would be present in blocks (128 bytes each) in this partition entry array, and after these working partitions, all the remaining 122 partition entries would be marked with `00`.
   1. Partition Type GUID: This is the GUID of the partition type. This GUID will indicate the partition type, i.e., EFI System Partition, Basic Data Partition, etc. The 16 bytes of our partition entry are stored in mixed endian (little-endian and big-endian) format. This means we would have to reverse specific bytes and keep the other ones the same. In this case, we would do the following:
      1. Reverse the first 4 bytes from 28 73 2A C1 to C1 2A 73 28, as they are in little-endian format.
      2. Reverse the next 2 bytes from 1F F8 to F8 1F, as they are in little-endian format.
      3. Reverse the next 2 bytes from D2 11 to 11 D2 as they are in little-endian format.
      4. Keep the next 2 bytes BA 4B as it is, as they are in big-endian format.
      5. Keep the last 6 bytes 00 A0 C9 3E C9 3B as it is, as they are in big-endian format.
   2. Unique Partition GUID: Unique Partition GUID is used to distinguish partitions on a disk. It is a unique GUID that is given to all the partitions on the disk. To convert these hexadecimal bytes into the standard GUID format, you can follow the same steps as we did for the first field (Partition Type GUID), as this is also stored in the mixed endian format.
   3. Starting LBA: The starting LBA address indicates the area from where this partition starts on the disk. 
   4. Ending LBA: The ending LBA address indicates the area at which this partition is ending on the disk.
   5. Attributes: This field contains some flags that indicates some features of the partition, for example, if it is bootable, hidden, or normal.
   6. Partition Name: This is the last field of the partition entry, and its size is 72 bytes. It represents the name of the partition in string format and is UTF-16 encoded. If you decode these bytes using any online hex-to-string decoder, you will get the partition name of this partition.
4. Backup GPT Header
5. Backup Partition Entry Array

### Disk Imaging Tools

#### dc3dd

`dc3dd` is an enhanced version of `dd` with additional features for forensic imaging, including hashing and logging.
Example usage:

`dc3dd if=/dev/loop1 of=example1.img log=imaging_loop1.txt`

#### Other tools

- `dd`: A standard Unix utility for copying and converting files, often used for creating raw disk images
- `ddrescue`: A data recovery tool that efficiently copies data from damaged drives, attempting to rescue as much data as possible
- `Guymager`: A GUI-based imaging tool for Linux systems that supports multiple image formats (e.g. E01, AFF, raw). It provides built-in write-blocking functionality, calculates MD5/SHA1 checksums during acquisition, and logs all imaging steps. Guymager is suitable for both live and offline imaging and is known for its simplicity and speed.
- `FTK Imager`: A widely used forensic imaging and preview tool that supports imaging from various media types (e.g., hard drives, USBs, optical media). FTK Imager allows investigators to preview files and folders before imaging, mount disk images for read-only access, and generate multiple image formats while computing hash values for integrity verification.
- `EWF tools (ewfacquire)`: Tools for creating and handling Expert Witness Format (EWF) images, often used in digital forensics

#### Integrity check:

Calculate MD5 sum of target device and image file to confirm integrity of data:

```
md5sum example1.img
md5sum /dev/loop1
```

#### Mounting image

`mount -o loop example1.img /mnt/example1`

### Disk Image Analysis Tools

- `The Sleuth Kit (TSK)`: A robust set of command-line tools for disk image analysis. It supports parsing of various file systems (FAT, NTFS, EXT) and provides granular access to files, metadata, deleted entries, and unallocated space. Tools like fls, icat, and tsk_recover allow listing files, extracting content, and recovering deleted items. TSK is ideal for scripting and automating analysis tasks in environments without a GUI.
- `Autopsy`: A GUI frontend for The Sleuth Kit that streamlines the analysis process through an intuitive interface. It supports timeline analysis, keyword searching, file carving, hash matching, and more. Autopsy is modular and extendable, offering numerous plugins to parse web artefacts, emails, and user activity. It’s an excellent free alternative to commercial tools, especially for initial triage and investigative workflows. Note: This module has an upcoming room to explore Autopsy in depth with practical demonstrations and show the workflows involved in disk image analysis.
- `EnCase Forensic`: A professional-grade commercial suite for digital investigations. EnCase offers a complete case management system, automated evidence processing, artefact detection, advanced filtering, bookmarking, and comprehensive reporting capabilities. It is widely used in law enforcement and corporate investigations due to its robustness and court-proven reliability.
- `FTK (Forensic Toolkit)`: Known for its indexing engine, FTK pre-processes data to enable rapid keyword searching, email analysis, and file filtering. It supports distributed processing and collaborative investigations, making it a strong candidate for large-scale cases or e-discovery scenarios.
- `Magnet AXIOM`: This commercial tool excels in evidence correlation and analysis across computers, mobile devices, and cloud data. AXIOM provides automated artefact extraction and presents data in an investigator-friendly timeline view, supporting both disk image and logical acquisition sources.

## Filesystems

### FAT32

#### FAT32 Structure

A FAT32 partitioned volume typically consists of the following parts:

- Reserved Area
  - Boot sector, also named Volume Boot Record
  - FSinfo Sector (FS is an acronym for Filesystem)
  - Reserved Sectors
- FAT Area
  - File Allocation Table (FAT1)
  - Backup File Allocation Table (FAT2)
- Data Area
  - Root Directory
  - Data Region

## Files

### PDF files

#### Get basic info

`pdfinfo <document>.pdf`

#### Extract images

1. List images:

   `pdfimages -list <document>.pdf`

2. Extract images:

   `pdfimages -j <document>.pdf ~+/`

### Photo EXIF Data

`exiftool <image>.jpg`
