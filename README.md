

### fs
This is an implementation of a simple file system manager. The file system structure is based on inodes and data blocks. It supports two types of objects: files and directories. Root directory is marked with '+'. Each component in file paths is separated by '/'.

The following information is stored in each inode:
- size
- owner
- group
- permissions
- modification time
- hardlinks count
- 13 direct blocks
- single indirect block
- double indirect block
- triple indirect block

[Click here](./documentation.txt) to read more about the file system structure.

---

**Written in**:  
C

---
The file system is stored in a file and all file system operations are performed by modifications on the file.

Example of creation of a file, on which the file system can be written:
```
$ truncate -s 32M file.bin
$ dd if=/dev/zero of=file.bin bs=1024k count=64
```
## Usage

### Build the program
```
$ make
```

Set the ```FS_FILE``` ENV variable to declare the location of the file, in which the file system will be stored:

```
$ FS_FILE=file.bin
```

### Create file system
```
$ ./fs mkfs
```
### Check file system for errors
```
$ ./fs fsck
```
### Show debug information about the file system
```
$ ./fs debug
```
Shows the content of the superblock and the free blocks bitmap.

### Show metadata about file, similar to 'ls' command
```
$ ./fs lsobj +/path/to/object
```
Example output:
```
drwxr-xr-x root root 0 2022-03-05T12:49:33Z +/path/to/object
```
### List files in directory
```
$ ./fs lsdir +/path/to/directory
```
Example output:
```
drwxr-xr-x root root 0 2022-03-05T12:49:33Z test
drwxr-xr-x root root 0 2022-03-12T20:08:47Z test2
drwxr-xr-x root root 0 2022-03-12T20:08:49Z test3
```
### Show metadata about file, similar to 'stat' command
```
$ ./fs stat +/test
```
Example output:
```
File: +/test
Size: 0
Blocks: 1
Type: directory
Inode: 7
Access: rwxr-xr-x
Owner: (root/0)
Group: (root/0)
Mtime: 2022-03-05T12:49:33Z
Hard links: 1
```
### Create new directory
```
$ ./fs mkdir +/path/to/directory
```
### Remove directory
```
$ ./fs rmdir +/path/to/directory
```
### Copy file
```
$ ./fs cpfile path/to/src/file +/path/to/dest/file
```
This command supports copying files from and into the outside file system. Copying files within the inner file system is also supported - in this case both src and dest paths must begin with '+'.

### Remove file
```
$ ./fs rmfile +/path/to/file
```
### Change access
```
$ ./fs chmod r-xr-xr-x +/path/to/file
```
This command changes the stored information about permissions, but access rule enforcement is not implemented.

### Change owner and group
```
$ ./fs chown ownerName:groupName +/path/to/object
```
This command changes the stored information about ownership, but access rule enforcement is not implemented.

### Create a hard link
```
$ ./fs lnhard +/target/file +/new/filename
```
## Author
Hristo Spasov - [hristo.b.spasov@gmail.com](mailto:hristo.b.spasov@gmail.com)
