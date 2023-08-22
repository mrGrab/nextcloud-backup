#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import logging
import click
import gi
import sys
import owncloud
from datetime import datetime, timezone
from systemd.journal import JournalHandler
gi.require_version('Notify', '0.7')
from gi.repository import Notify
from gi.repository import GObject

# Configure logger
logger = logging.getLogger(__name__)
if sys.stdin and sys.stdin.isatty():
    formatter = logging.Formatter('[%(asctime)s] %(levelname)s %(message)s')
    handler = logging.StreamHandler()
    handler.setFormatter(formatter)
    logger.addHandler(handler)
else:
    formatter = logging.Formatter('%(message)s')
    handler = JournalHandler(SYSLOG_IDENTIFIER='nextcloud-backup')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

class Notifier(GObject.Object):

    def __init__(self, app_name):
        super(Notifier, self).__init__()
        Notify.init(app_name)
        self.file_path_to_icon = ""
        self.urgency = 1

    def send_notification(self, title, text):
        n = Notify.Notification.new(title, text, self.file_path_to_icon)
        n.set_urgency = self.urgency
        if not n.show():
            logger.error("Unable to show notification")

class NextCloud(owncloud.Client):

    def __init__(self, url, **kwargs):
        super().__init__(url, **kwargs)

    def mkdir(self, path, parents=False):
        """Creates a remote directory

        :param path: path to the remote directory to create
        :param parents: make parent directories as needed
        :returns: True if the operation succeeded, False otherwise
        :raises: HTTPResponseError in case an HTTP error status was returned
        """
        if not path.endswith('/'):
            path += '/'

        if parents == True:
            folders = [ i for i in path.split("/") if i ]
            for idx, name in enumerate(folders):
                try:
                    dir_list = folders[0:idx+1]
                    root = "/" + os.path.join('', *dir_list) + "/"
                    res = self._make_dav_request('MKCOL', root)
                except owncloud.owncloud.HTTPResponseError:
                    logger.debug(f"Path {root} already exist")
            return res
        else:
            return self._make_dav_request('MKCOL', path)


class Backup():
    """ Work with backuped objects """

    def __init__(self, item_list):
        self.item_list = {"file": [], "dir": []}
        self._classify(item_list)

    def pop(self, path, item_type):
        """ Remove item from item_list

        :param path: what should be removed
        :param item_type: file or dir
        :returns: owncloud FileInfo object or none
        """
        for i in self.item_list[item_type]:
            if path == i.path:
                self.item_list[item_type].remove(i)
                return i
        else:
            return None

    def _classify(self, items):
        for i in items:
            self.item_list[i.file_type].append(i)

def normalize_path(path):
    """ Make sure the path starts and ends with a '/' """
    if len(path) == 0:
        return '/'
    if not path.startswith('/'):
        path = '/' + path
    if not path.endswith('/'):
        path = path + '/'
    return path

def is_hidden(path):
    return os.path.basename(path).startswith(".")

@click.command()    
@click.option("--url", required=True, default=lambda: os.environ.get("url", ""), help="NextCloud url")
@click.option("-u", "--user", required=True, default=lambda: os.environ.get("user", ""), help="User name")
@click.option("-p", "--password", required=True, default=lambda: os.environ.get("password", ""), help="User password")
@click.option("-f", "--folder", required=True, help="Folder for backup")
@click.option("--hidden", is_flag=True, default=False, help="Upload hidden files")
def main(url, user, password, folder, hidden):
    
    counters = {"total": 0,
                "uploaded": 0,
                "failed": 0,
                "removed": 0}
    hostname = os.uname().nodename
    folder = normalize_path(folder)

    logger.info("Initialize notification")
    notifier = Notifier("Backup")
    notifier.file_path_to_icon="nextcloud"

    logger.info(f"Connecting to {url} server")
    nc = NextCloud(url, debug=False)
    nc.login(user, password)

    logger.info("Getting the list of items from server")
    try:
        remote_root = normalize_path(hostname + folder)
        remote_items = nc.list(remote_root, depth="infinity")
    except owncloud.owncloud.HTTPResponseError:
        logger.warning(f"The remote root \"{remote_root}\" does not exist")
        nc.mkdir(remote_root, parents=True)
        remote_items = []

    logger.info(f"Starting backup {folder}")
    bc = Backup(remote_items)
    # Walk through directories from top
    for root, dirs, files in os.walk(folder):
        if not hidden and is_hidden(root):
            logger.debug(f"Folder {root} is hidden. skipping")
            continue
        remote_root = normalize_path(hostname + root)

        # Create folder if it does not exist
        if root != folder and not bc.pop(remote_root, item_type='dir'):
            nc.mkdir(remote_root)
            logger.info(f"Created remote folder: {remote_root}")

        # Upload files
        for filename in files:
            # Local file info
            local_path = normalize_path(root) + filename
            if not hidden and is_hidden(local_path):
                logger.debug(f"File {local_path} is hidden. skipping")
                continue
            mtime = os.path.getmtime(local_path)
            local_mtime = datetime.utcfromtimestamp(mtime).isoformat(timespec='seconds')

            # Remote file info if it exists
            remote_path = remote_root + filename
            remote_file = bc.pop(remote_path, item_type='file')
            if remote_file:
                remote_mtime = remote_file.get_last_modified().isoformat(timespec='seconds')
    
            if remote_file == None or local_mtime != remote_mtime:
                try:
                    nc.put_file(remote_path, local_path, keep_mtime=True)
                    counters["uploaded"] += 1
                    logger.info(f"{local_path} successfully uploaded")
                except (owncloud.owncloud.HTTPResponseError, PermissionError) as err:
                    counters["failed"] +=1
                    logger.error(f"Unable to upload {local_path}: {err}")
            counters["total"] += 1

    # Delete a remote files and directories that are not local
    for item in bc.item_list['file'] + bc.item_list['dir']:
        try:
            nc.delete(item)
            logger.info(f"{item.path} - has been deleted")
            counters["removed"] += 1
        except owncloud.owncloud.HTTPResponseError as err:
            logger.error(f"Unable to delete {item.path}: {err}")
            counters["failed"] += 1
            
    nc.logout()
    logger.info(f"Backup has been completed - {counters}")
    
    # Send notification
    text = '''Result:
    uploaded: {uploaded}
    total: {total}
    removed: {removed}
    failed: {failed}
    '''.format(**counters)
    notifier.send_notification(folder, text)
                
if __name__ == '__main__':
    main()
