#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Based on https://github.com/owncloud/pyocclient

import os
import logging
import requests
import urllib.parse
import six
import click
import xml.etree.ElementTree as ET
import gi
from datetime import datetime
from six.moves.urllib import parse
gi.require_version('Notify', '0.7')
from gi.repository import Notify
from gi.repository import GObject


logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s %(message)s')


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
            logging.error("Unable to show notification")


class FileInfo:
    """File information"""

    _DATE_FORMAT = '%a, %d %b %Y %H:%M:%S %Z'

    def __init__(self, path, file_type='file', attributes=None):
        self.path = path
        if path.endswith('/'):
            path = path[0:-1]
        self.name = os.path.basename(path)
        self.file_type = file_type
        self.attributes = attributes or {}

    def get_name(self):
        """Returns the base name of the file without path

        :returns: name of the file
        """
        return self.name

    def get_path(self):
        """Returns the full path to the file without name and without
        trailing slash

        :returns: path to the file
        """
        return os.path.dirname(self.path)

    def get_size(self):
        """Returns the size of the file

        :returns: size of the file
        """
        if '{DAV:}getcontentlength' in self.attributes:
            return int(self.attributes['{DAV:}getcontentlength'])
        return None

    def get_etag(self):
        """Returns the file etag

        :returns: file etag
        """
        return self.attributes['{DAV:}getetag']

    def get_content_type(self):
        """Returns the file content type

        :returns: file content type
        """
        if '{DAV:}getcontenttype' in self.attributes:
            return self.attributes['{DAV:}getcontenttype']

        if self.is_dir():
            return 'httpd/unix-directory'

        return None

    def get_last_modified(self):
        """Returns the last modified time

        :returns: last modified time
        :rtype: datetime object
        """
        return datetime.datetime.strptime(
            self.attributes['{DAV:}getlastmodified'],
            self._DATE_FORMAT
        )

    def is_dir(self):
        """Returns whether the file info is a directory

        :returns: True if it is a directory, False otherwise
        """
        return self.file_type != 'file'

    def __str__(self):
        return 'File(path=%s,file_type=%s,attributes=%s)' % \
               (self.path, self.file_type, self.attributes)

    def __repr__(self):
        return self.__str__()


class Client:

    """ WebDAV connection to NextCloud instance """

    def __init__(self, url):
        self._session = None
        self.url = url
 
    def login(self, user, password):
        self._session = requests.session()
        self._session.auth = (user, password)
        self._davpath = '/remote.php/dav/files/' + parse.quote(user)
        self._webdav_url = self.url + self._davpath

    def logout(self):
        """Log out the authenticated user and close the session.

        :returns: True if the operation succeeded, False otherwise
        :raises: requests.HTTPError in case an HTTP error status was returned
        """
        # TODO actual logout ?
        self._session.close()
        return True

    def file_info(self, path, properties=None):
        """Returns the file info for the given remote file

        :param path: path to the remote file
        :param properties: a list of properties to request (optional)
        :returns: file info
        :rtype: :class:`FileInfo` object or `None` if file
            was not found
        :raises: HTTPResponseError in case an HTTP error status was returned
        """
        if properties:
            root = ET.Element('d:propfind',
                              {
                                  'xmlns:d': "DAV:",
                                  'xmlns:nc': "http://nextcloud.org/ns",
                                  'xmlns:oc': "http://owncloud.org/ns"
                              })
            prop = ET.SubElement(root, 'd:prop')
            for p in properties:
                ET.SubElement(prop, p)
            data = ET.tostring(root)
        else:
            data = None
        res = self._make_dav_request('PROPFIND', path, headers={'Depth': '0'}, data=data)
        if res:
            return res[0]
        return None

    def list(self, path, depth=1, properties=None):
        """Returns the listing/contents of the given remote directory

        :param path: path to the remote directory
        :param depth: depth of the listing, integer or "infinity"
        :param properties: a list of properties to request (optional)
        :returns: directory listing
        :rtype: array of :class:`FileInfo` objects
        :raises: requests.HTTPError in case an HTTP error status was returned
        """
        if not path.startswith('/'):
            path = '/' + path

        headers = {}
        if isinstance(depth, int) or depth == "infinity":
            headers['Depth'] = str(depth)

        if properties:
            root = ET.Element('d:propfind',
                              {
                                  'xmlns:d': "DAV:",
                                  'xmlns:nc': "http://nextcloud.org/ns",
                                  'xmlns:oc': "http://owncloud.org/ns"
                              })
            prop = ET.SubElement(root, 'd:prop')
            for p in properties:
                ET.SubElement(prop, p)
            data = ET.tostring(root)
        else:
            data = None

        res = self._make_dav_request('PROPFIND', path, headers=headers, data=data)
        return res if res else []

    def get_file(self, remote_path, local_file=None):
        """Downloads a remote file

        :param remote_path: path to the remote file
        :param local_file: optional path to the local file. If none specified,
            the file will be downloaded into the current directory
        :returns: True if the operation succeeded, False otherwise
        :raises: requests.HTTPError in case an HTTP error status was returned
        """
        remote_path = self._normalize_path(remote_path)
        res = self._session.get(
            self._webdav_url + parse.quote(self._encode_string(remote_path)),
            stream=True
        )
        if res.status_code == 200:
            if local_file is None:
                # use downloaded file name from Content-Disposition
                # local_file = res.headers['content-disposition']
                local_file = os.path.basename(remote_path)

            file_handle = open(local_file, 'wb', 8192)
            for chunk in res.iter_content(8192):
                file_handle.write(chunk)
            file_handle.close()
            return True
        elif res.status_code >= 400:
            raise requests.HTTPError(res)
        return False

    def mkdir(self, path):
        """Creates a remote directory

        :param path: path to the remote directory to create
        :returns: True if the operation succeeded, False otherwise
        :raises: requests.HTTPError in case an HTTP error status was returned
        """

        dir_list = []
        for name in path.split("/"):
            if name:
                dir_list.append(name)
                root = "/" + os.path.join('', *dir_list) + "/"
                res = self._make_dav_request('MKCOL', root)
                logging.info(f"{root} folder has been created")
        return res

    def put_file(self, remote_path, local_source_file, **kwargs):
        """Upload a file

        :param remote_path: path to the target file. A target directory can
            also be specified instead by appending a "/"
        :param local_source_file: path to the local file to upload
        :param keep_mtime: (optional) also update the remote file to the same
            mtime as the local one, defaults to True
        :returns: True if the operation succeeded, False otherwise
        :raises: requests.HTTPError in case an HTTP error status was returned
        """

        stat_result = os.stat(local_source_file)

        headers = {}
        if kwargs.get('keep_mtime', True):
            headers['X-OC-MTIME'] = str(int(stat_result.st_mtime))

        if remote_path[-1] == '/':
            remote_path += os.path.basename(local_source_file)
        file_handle = open(local_source_file, 'rb', 8192)
        res = self._make_dav_request(
            'PUT',
            remote_path,
            data=file_handle,
            headers=headers
        )
        file_handle.close()
        return res

    def delete(self, path):
        """Deletes a remote file or directory

        :param path: path to the file or directory to delete
        :returns: True if the operation succeeded, False otherwise
        :raises: requests.HTTPError in case an HTTP error status was returned
        """
        return self._make_dav_request('DELETE', path)

    def _make_dav_request(self, method, path, **kwargs):
        """Makes a WebDAV request

        :param method: HTTP method
        :param path: remote path of the targeted file
        :param \*\*kwargs: optional arguments that ``requests.Request.request`` accepts
        :returns array of :class:`FileInfo` if the response
        contains it, or True if the operation succeeded, False
        if it didn't
        """
        logging.debug('DAV request: %s %s' % (method, path))

        path = self._normalize_path(path)
        res = self._session.request( 
            method = method,
            url = self._webdav_url + parse.quote(self._encode_string(path)),
            **kwargs
        )
        logging.debug('DAV status: %i' % res.status_code)
        if res.status_code in [200, 207]:
            return self._parse_dav_response(res)
        elif res.status_code in [204, 201]:
            return True
        elif res.status_code == 405:
            logging.debug("MKCOL can only be executed on an unmapped URL.")
            return True
        elif res.status_code == 404:
            logging.debug("Not Found - The property does not exist.")
            return False 
        res.raise_for_status()

    def _parse_dav_response(self, res):
        """Parses the DAV responses from a multi-status response

        :param res: DAV response
        :returns array of :class:`FileInfo` or False if
        the operation did not succeed
        """
        if res.status_code == 207:
            tree = ET.fromstring(res.content)
            items = []
            for child in tree:
                items.append(self._parse_dav_element(child))
            return items
        return False

    def _parse_dav_element(self, dav_response):
        """Parses a single DAV element

        :param dav_response: DAV response
        :returns :class:`FileInfo`
        """
   
        href = parse.unquote(
            self._strip_dav_path(dav_response.find('{DAV:}href').text)
        )

        if six.PY2:
            href = href.decode('utf-8')

        file_type = 'file'
        if href[-1] == '/':
            file_type = 'dir'

        file_attrs = {}
        attrs = dav_response.find('{DAV:}propstat')
        attrs = attrs.find('{DAV:}prop')
        for attr in attrs:
            file_attrs[attr.tag] = attr.text

        return FileInfo(href, file_type, file_attrs)

    def _strip_dav_path(self, path):
        """Removes the leading "remote.php/dav/files" path from the given path

        :param path: path containing the remote DAV path "remote.php/dav/files"
        :returns: path stripped of the remote DAV path
        """

        if path.startswith(self._davpath):
            return path[len(self._davpath):]
        return path

    @staticmethod
    def _encode_string(s):
        """Encodes a unicode instance to utf-8. If a str is passed it will
        simply be returned

        :param s: str or unicode to encode
        :returns: encoded output as str
        """
        if six.PY2 and isinstance(s, unicode):  # noqa: F821
            return s.encode('utf-8')
        return s

    @staticmethod
    def _normalize_path(path):
        """Makes sure the path starts with a "/"
        """
        if isinstance(path, FileInfo):
            path = path.path
        if len(path) == 0:
            return '/'
        if not path.startswith('/'):
            path = '/' + path
        return path

def get_list(folder):
    """Create list with all files in folder with full path

    :param folder: start point
    :returns: list of files and directories
    """
    items = []
    for root, dirs, files in os.walk(folder):
        if not root.endswith("/"):
            root += "/"
        root = FileInfo(root, file_type='dir')
        for i in files:
            items.append(FileInfo(f"{root}{i}", file_type='file'))
    #     if not root.endswith("/"):
    #         root += "/"
    #     for i in files:
    #         file_list.append(f"{root}{i}")
    return items

def validate_for_backup(filename, age=86400):
    """ If filename has been modified since age seconds """
    today = datetime.now().timestamp()
    mtime = os.path.getmtime(filename)
    delta = today - mtime
    logging.debug(f"{filename} - modified {round(delta/3600, 1)} hour(s) ago")
    return True if delta <= age else False


@click.command()
@click.option("--url", required=True, default="https://cloud.small-service.com", help="NextCloud url")
@click.option("-u", "--user", required=True, help="user name")
@click.option("-p", "--password", required=True, help="password")
@click.option("-f", "--folder", required=True, help="Folder for backup")
@click.option("-a", "--age", default=86400, help="How old files should be backuped. in sec")
@click.option("--dry-run", is_flag=True, default=False, help="Do not upload anything")
def main(url, user, password, folder, age, dry_run):

    hostname = "/" + os.uname().nodename
    counters = {"total": 0,
                "uploaded": 0,
                "failed": 0,
                "removed": 0}

    # Notification initialization 
    notifier = Notifier("Backup")
    notifier.file_path_to_icon="nextcloud"

    # Connect to nextcloud server
    nc = Client(url)
    nc.login(user, password)

    # Get items list from nextcloud
    remote_list = {"file": [], "dir": []}
    for i in nc.list(hostname + folder, depth="infinity"):
        remote_list[i.file_type].append(i.path)
    logging.debug(f"{len(remote_list['dir'])} - remote folders before backup")
    logging.debug(f"{len(remote_list['file'])} - remote files before backup")
   
    logging.info(f"Starting backup {folder}")
    # Walk through directories from top
    for root, dirs, files in os.walk(folder):
        if not root.endswith("/"):
            root += "/"

        # Create folder if it does not exist
        remote_root = hostname + root
        if nc.file_info(remote_root) == None:
            nc.mkdir(remote_root)
            logging.info(f"Created remote folder: {remote_root}")
        else:
            remote_list["dir"].remove(remote_root)

        # Upload files
        for filename in files:
            counters["total"] += 1
            local_path = root + filename
            remote_path = remote_root + filename
            file_info = nc.file_info(remote_path)

            if file_info == None or validate_for_backup(local_path, age):
                if nc.put_file(remote_path, local_path) == True:
                    counters["uploaded"] += 1
                    logging.info(f"{local_path} successfully uploaded")
                else:
                    counters["failed"] +=1
                    logging.error(f"{local_path} - unable to upload")
            
            if file_info:
                remote_list["file"].remove(remote_path)

    # Delete a remote file and directory that are not local
    for remote_path in remote_list['file'] + remote_list['dir']:
        nc.delete(remote_path)
        counters["removed"] += 1
        logging.debug(f"{remote_path} - has been deleted")

    nc.logout()
    logging.info(f"Backup has been completed - {counters}")
    
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
