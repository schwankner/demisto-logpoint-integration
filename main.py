import json
import os

import requests


def is_docker():
    path = '/proc/self/cgroup'
    return (
            os.path.exists('/.dockerenv') or
            os.path.isfile(path) and any('docker' in line for line in open(path))
    )


if not is_docker():
    from config import config


    class Demisto:

        def __init__(self):
            self.username = config.username
            self.password = config.password
            self.hostname = config.hostname
            self.lastRun = {}

        def params(self):
            return {'username': self.username, 'password': self.password, 'hostname': self.hostname,
                    'proxy': config.proxy}

        def command(self):
            # return 'test-module'
            return 'fetch-incidents'

        def results(self, message):
            print('Demisto: Result=' + json.dumps(message))

        def getLastRun(self):
            return self.lastRun

        def setLastRun(self, lastRun):
            self.lastRun = lastRun

        def incidents(self, incidents):
            print(incidents)

        def args(self):
            return {'last': '5c6c1fa8371a8e59dc7a676d'}


    demisto = Demisto()


class Logpoint:
    def __init__(self):
        self.lastRun_id = 0
        self.username = demisto.params().get('username')
        self.password = demisto.params().get('password')

        self.hostname = demisto.params().get('hostname')

        self.session = requests.session()

        self.proxy = demisto.params().get('proxy')

        self.csrf_token = self.login()

    def login(self):
        header = {'Content-Type': 'application/x-www-form-urlencoded'}
        payload = {'username': self.username, 'password': self.password, 'requestType': 'formsubmit',
                   'CSRFToken': 'None', 'id': '', 'url_hash': ''}
        response = self.session.post(self.hostname + "/pluggables/Authentication/LogpointAuthentication/login",
                                     headers=header,
                                     data=payload, proxies=self.proxy, verify=False)
        if response.status_code != 200:
            print('Login failed ' + response.status_code)
            return False

        json_response = json.loads(response.text)
        if 'validationErrors' in json_response:
            print('Login failed ' + json_response['validationErrors'])
            return False

        # second request
        response2 = self.session.get(self.hostname + "/", headers=header, proxies=self.proxy, verify=False)
        start = response2.text.find('App.constants.CSRFToken = "')
        return response2.text[start + 27:start + 63]

    def get_new_incidents(self, last_incident):
        if last_incident is False:
            incidents = self.get_uri(self.hostname + '/uincidents', {})
            return incidents
        else:
            payload = {'kind': 'newer', 'id': last_incident}
            incidents = self.get_uri(self.hostname + '/uincidents', payload)
            return incidents

    def get_uri(self, uri, payload):
        header = {'X-Requested-With': 'XMLHttpRequest',
                  'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'}
        payload['CSRFToken'] = self.csrf_token
        payload['LOGGEDINUSER'] = self.username
        response = self.session.post(uri,
                                     headers=header, data=payload, proxies=self.proxy, verify=False)
        if response.status_code != 200:
            # print('Alert receive failed ' + str(response.status_code))
            return response.status_code
        return json.loads(response.text)

    def test_connection(self):
        # This is the call made when pressing the integration test button.
        if len(logpoint.csrf_token) == 36 and logpoint.csrf_token is not False:
            return 'ok'
        else:
            return 'Failed'

    def fetch_new_incidents_for_demisto(self):

        try:
            lastRun = demisto.getLastRun()
            lastAlert = lastRun['alert']
        except KeyError:
            lastAlert = False

        alerts = logpoint.get_new_incidents(lastAlert)

        incidents = []

        for alert in alerts['rows']:
            wrapper = {
                'name': alert['title'],
                'details': alert['des'],
                'risk': alert['risk'],
                'date': alert['date'],
                'id': alert['id'],
                'incident_id': alert['incident_id']
            }

            incidents.append({"Name": wrapper['name'],
                              "rawJSON": json.dumps(wrapper)})

            demisto.setLastRun({'alert': alert['id']})
        return incidents


logpoint = Logpoint()

try:
    if demisto.command() == 'test-module':
        # Tests connectivity and credentails on login
        demisto.results(logpoint.test_connection())
    elif demisto.command() == 'fetch-incidents':
        demisto.incidents(logpoint.fetch_new_incidents_for_demisto())
except Exception as e:
    print(e.message)
