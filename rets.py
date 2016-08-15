from hashlib import md5
from urlparse import urlparse, urljoin
import requests
from requests.auth import HTTPDigestAuth
from xml.etree import ElementTree
import logging

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class RetsSession(object):
    """ documentation: http://www.realtor.org/retsorg.nsf/retsproto1.7d6.pdf """

    def __init__(self, login_url, client_name=None, client_password=None, client_version='RETS/1.7'):
        self.login_url = login_url
        self.client_name = client_name
        self.client_password = client_password
        self.client_version = client_version
        self.session = requests.Session()
        self.session_id = None
        self.logout_url = None
        self.metadata_url = None
        self.search_url = None

    @property
    def base_url(self):
        return '{parts.scheme}://{parts.netloc}'.format(parts=urlparse(self.login_url))

    def login(self, username, password):
        headers = {
            'User-Agent': self.client_name,
            'RETS-Version': self.client_version,
            'Accept': "*/*"
        }
        self.session.headers.update(headers)
        self.session.auth = HTTPDigestAuth(username, password)

        headers = {}
        if self.client_password is not None:
            headers['RETS-UA-Authorization'] = self._sign

        self._process_login_response(self.session.get(self.login_url, headers=headers))
        logger.debug('login successful')

    def logout(self):
        self._check_session()
        r = self.session.get(self.logout_url)
        self._parse_response(r)
        logging.debug('logout successful')

    def get_metadata(self):
        self._check_session()
        params = {
            'Type': 'METADATA-SYSTEM',
            'ID': '*',
            'Format': 'STANDARD-XML',
        }
        r = self.session.get(self.metadata_url, params=params)
        return RetsMetadata(self._parse_response(r))

    @property
    def _sign(self):
        # a1 = MD5(user_agent : user_agent_password)
        a1 = md5(self.client_name + ':' + self.client_password).hexdigest()

        session_id = self.session_id if self.session_id is not None else ''
        # MD5(HEX(a1) : RETS-Request-ID : RETS-Session-ID : RETS-Version )
        digest = md5(a1 + ':' + '' + ':' + session_id + ':' + self.client_version).hexdigest()

        return 'Digest ' + digest

    def _check_session(self):
        if not self.session_id:
            raise LoginException('Not logged in')

    def search(self, resource_id, class_id, query, select=None, count_type=1, offset=None, limit=False):
        self._check_session()

        params = {
            'SearchType': resource_id,
            'Class': class_id,
            'Query': query,
            'QueryType': 'DMQL2',
            'Count': count_type,
            # 'Format': 'COMPACT-DECODED',
            'Format': 'COMPACT',
            'Limit': 2,  # limit,
            # 'Offset': offset,
            # 'Select': select,
            'StandardNames': '0'
        }
        logger.debug('performing query: {}, {}, {}'.format(resource_id, class_id, query))
        r = self.session.post(self.search_url, data=params)
        print r.content
        return RetsResultSet(self._parse_response(r))

    def get_object(self):
        pass

    def _check_status_code(self, resp):
        if resp.status_code == 200:
            return
        if resp.status_code == 401:
            raise LoginException(resp.text, resp.status_code)
        raise RetsException(resp.text, resp.status_code)

    def _parse_response(self, resp):
        self._check_status_code(resp)

        doc = ElementTree.fromstring(resp.text)
        reply_code = doc.attrib['ReplyCode']
        reply_text = doc.attrib['ReplyText']

        if reply_code == '0':
            return doc
        if reply_code in ('20041', '20037'):
            raise LoginException(reply_text, reply_code)

        raise RetsException(reply_text, reply_code)

    def _process_login_response(self, resp):
        doc = self._parse_response(resp)

        lines = doc.find('RETS-RESPONSE').text.split('\n')

        print filter(len, lines)

        server_data = dict(map(lambda x: x.strip(), line.split('=', 2)) for line in filter(len, lines))

        self.session_id = self.session.cookies['RETS-Session-ID']

        base_url = self.base_url
        self.logout_url = urljoin(base_url, lines['Logout'])
        self.metadata_url = urljoin(base_url, lines['GetMetadata'])
        self.search_url = urljoin(base_url, lines['Search'])

        # update signature
        if self.client_password is not None:
            self.session.headers.update({'RETS-UA-Authorization': self._sign})

        return lines


class RetsClient(object):

    def __init__(self, login_url, user_name=None, user_password=None, client_name=None, client_password=None):
        self.session = RetsSession(login_url, client_name=client_name, client_password=client_password)
        self.user_name = user_name
        self.user_password = user_password

    def __enter__(self):
        self.session.login(self.user_name, self.user_password)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.logout()

    def get_metadata(self):
        return self.session.get_metadata()

    def search(self, *args, **kwargs):
        return self.session.search(*args, **kwargs)

    def get_data(self, last_time=None):
        pass


class RetsMetadata(object):

    def __init__(self, xmldict):
        self.data = xmldict

    def get_resources(self):
        # print self.data
        return self.data['METADATA']['METADATA-SYSTEM']['System']['METADATA-RESOURCE']
        # for resource in self.data['METADATA']GetAllResources():
        #     res_id = res.GetResourceID()
        #     res_name = res.GetStandardName()
        #     print "Resource name: {} [{}]".format(res_id, res_name)
        #     self.get_classes(metadata, res_id)

    def get_classes(self, metadata, res_id):
        for cls in metadata.GetAllClasses(res_id):
            cls_id = cls.GetClassName()
            cls_name = cls.GetStandardName()
            print "Class name: {} [{}]".format(cls_id, cls_name)
            self.get_tables(metadata, res_id, cls_id)

    def get_tables(self, metadata, res_id, cls_id):
        for tbl in metadata.GetAllTables(res_id, cls_id):
            tbl_id = tbl.GetSystemName()
            tbl_name = tbl.GetStandardName()
            tbl_type = tbl.GetDataType()
            print "Table name: {} [{}] - {}".format(tbl_id, tbl_name, tbl_type)

    def get_lookups(self, metadata, res_id):
        for lookup in metadata.GetAllLookups(res_id):
            print "Resource name: {}".format(res_id)
            lookup_id = lookup.GetLookupName()
            lookup_name = lookup.GetVisibleName()
            print "Lookup name: {} ({})".format(lookup_id, lookup_name)
            self.get_lookup_types(metadata, res_id, lookup_id)

    def get_lookup_types(self, metadata, res_id, lookup_id):
        for type_ in metadata.GetAllLookupTypes(res_id, lookup_id):
            type_val = type_.GetValue()
            type_val_short = type_.GetShortValue()
            type_val_long = type_.GetLongValue()
            print "Lookup value: {} ({}, {})".format(type_val, type_val_short, type_val_long)

    # def get_resources(self):
    #     pass

    def get_classes(self, resource_id):
        pass

    def get_tables(self, resource_id, class_id):
        pass

    def get_lookups(self, resource_id):
        pass

    def get_lookup_type(self, resource_id, lookup_id):
        pass


class RetsResultSet(object):

    def __init__(self, body):
        self.body = body
        self.delimiter = chr(int(body['DELIMITER']['@value']))
        self.count = self.body['COUNT']
        self.columns = map(lambda x: x.strip(), self.body['COLUMNS'].split(self.delimiter))

    def __iter__(self):
        print list(self.body['DATA'])
        exit()
        for values in list(self.body['DATA']):
            print map(lambda x: x.strip(), values.split(self.delimiter))
            data = zip(self.columns, map(lambda x: x.strip(), values))
            print data
            yield data


class RetsException(Exception):

    def __init__(self, message, code=None):
        super(RetsException, self).__init__(message)
        self.code = code


class LoginException(RetsException):
    pass
