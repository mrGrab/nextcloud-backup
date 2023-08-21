# nextcloud-backup
Python script for backup local folders to nextcloud

## Main idea:

- get list of already backuped files
- walk through incoming folder
- if file is not  backuped and modify time is different - upload
- if file successfully uploaded remoe it from list

# TODO
1. exclude folder

# Documentation
- https://pypi.org/project/pyocclient/
- https://docs.nextcloud.com/server/14/developer_manual/index.html
- https://www.rfc-editor.org/rfc/rfc4918
