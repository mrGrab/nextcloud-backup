# nextcloud-backup
Python script for backup local folders to nextcloud

Main idea:

- get list of already backuped files
- walk through incoming folder
- if file is not  backuped and modify time is different - upload
- if file successfully uploaded remoe it from list

#TODO
1. exclude folder
