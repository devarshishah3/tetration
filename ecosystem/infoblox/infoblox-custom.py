import requests
import json
from requests.auth import HTTPBasicAuth

class Infoblox(object):
    def __init__(self, settings, logger):
        self.server = settings["host"]
        self.wapiver = '/wapi/v' + settings["wapi_version"] + '/'
        self.user = settings["username"]
        self.password = settings["password"]
        self.logger = logger

    def __enter__(self):
        """Start a session with Infoblox

        All requests sent during the session will be authenticated with
        the ibapauth cookie.
        """
        url = 'https://' + self.server + self.wapiver + 'networkview'
        s = requests.Session()
        login = s.get(url, auth=HTTPBasicAuth(self.user, self.password), verify=False)
        print "logging in for the first time."
        self.session = s
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Logout and close the session"""
        print "Closing connection with Infoblox!"
        self.logger.info("Closing connection with Infoblox!")
        url = 'https://' + self.server + self.wapiver + 'logout'
        self.session.post(url)
        self.session.close()
        #raise ValueError('Manually Throwing Exception to close program!')
        print "Connection with Infoblox closed!"
        self.logger.info("Connection with Infoblox closed!")

    def requestMultiple(self, payload):
        url = 'https://' + self.server + "/wapi/v" + self.wapiver + "/requests?_paging=1&_return_as_object=1&_max_results=500"
        resp = self.session.post(url,json_body=json.dumps(payload),verify=False)
        return resp.json()