# --
# File: endgame_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2018
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --

# Standard imports
import json
import time
import requests
from bs4 import BeautifulSoup

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from endgame_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))


class EndgameConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(EndgameConnector, self).__init__()

        self._state = None
        self._base_url = None
        self._username = None
        self._password = None
        self._verify_server_cert = None
        self._token = None
        self._state = {}

    def initialize(self):
        """ This is an optional function that can be implemented by the AppConnector derived class. Since the
        configuration dictionary is already validated by the time this function is called, it's a good place to do any
        extra initialization of any internal modules. This function MUST return a value of either phantom.APP_SUCCESS or
        phantom.APP_ERROR. If this function returns phantom.APP_ERROR, then AppConnector::handle_action will not get
        called.
        """

        self._state = self.load_state()

        if ENDGAME_STATE_TASK_DICT not in self._state:
            self._state[ENDGAME_STATE_TASK_DICT] = {}

        # get the asset config
        config = self.get_config()
        self._token = self._state.get("token")
        # Required values can be accessed directly
        self._base_url = config['url'].strip("/")
        self._username = config['username']
        self._password = config['password']
        self._verify_server_cert = config.get('verify_server_cert', False)

        return phantom.APP_SUCCESS

    def finalize(self):
        """ This function gets called once all the param dictionary elements are looped over and no more handle_action
        calls are left to be made. It gives the AppConnector a chance to loop through all the results that were
        accumulated by multiple handle_action function calls and create any summary if required. Another usage is
        cleanup, disconnect from remote devices etc.
        """

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS

    def _process_empty_response(self, response, action_result):
        """ This function is used to process empty response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"),
                      None)

    def _process_html_response(self, response, action_result):
        """ This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except Exception as e:
            error_text = "Cannot parse error details"
            self.debug_print(error_text, e)

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code, error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, response, action_result):
        """ This function is used to process json response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # Try a json parse
        try:
            resp_json = response.json()
        except Exception as e:
            self.debug_print("Unable to parse the response into a dictionary", e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".
                                                   format(str(e))), None)

        # Please specify the status codes here
        if response.status_code in (200, 201):
            return RetVal(phantom.APP_SUCCESS, resp_json)

        if self.get_action_identifier() == "get_investigation" and response.status_code == 404:
            resp_json["error"]["message"] = "Given investigation not found"

        message = "Error from server. Status Code: {0} Data from server: {1}".format(response.status_code,
                                                                                     response.text.replace('{', '{{').
                                                                                     replace('}', '}}'))

        # Process the error returned in the json
        if resp_json.get('error'):
            message = "Error from server. Status Code: {0} Data from server: {1}".format(
                response.status_code, resp_json['error']['message'])

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, response, action_result):
        """ This function is used to process html response.

        :param response: response data
        :param action_result: object of Action Result
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message)
        """

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': response.status_code})
            action_result.add_debug_data({'r_text': response.text})
            action_result.add_debug_data({'r_headers': response.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in response.headers.get('Content-Type', ''):
            return self._process_json_response(response, action_result)

        # Process an HTML response, Do this no matter what the API talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in response.headers.get('Content-Type', ''):
            return self._process_html_response(response, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not response.text:
            return self._process_empty_response(response, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".\
            format(response.status_code, response.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call_abstract(self, endpoint, action_result, data=None, params=None, method="post", timeout=None):
        """ This method generates a new token if it is not available or if the existing token has expired
        and makes the call using _make_rest_call method.

        :param endpoint: REST endpoint
        :param action_result: object of ActionResult class
        :param data: request body
        :param params: request params
        :param method: GET/POST/PUT/DELETE (Default will be POST)
        :param timeout: timeout for action
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message) and API response
        """

        # Use this object for make_rest_call
        # Final status of action_result would be determined after retry, in case the token is expired
        intermediate_action_result = ActionResult()
        response = None

        # Prepare headers
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

        # Generate new token if not available
        if not self._token:
            ret_code = self._generate_api_token(action_result)
            if phantom.is_fail(ret_code):
                return action_result.get_status(), response

        # Update headers with token
        headers['Authorization'] = "JWT {}".format(self._token)

        # Make REST call
        rest_ret_code, response = self._make_rest_call(endpoint=endpoint, action_result=intermediate_action_result,
                                                       headers=headers, params=params, data=data, method=method,
                                                       timeout=timeout)

        # If token is invalid in case of API call, generate new token and retry
        if phantom.is_fail(rest_ret_code) and "401" in str(intermediate_action_result.get_message()):
            ret_code = self._generate_api_token(action_result)
            if phantom.is_fail(ret_code):
                return action_result.get_status(), response

            # Update headers with token
            headers['Authorization'] = "JWT {}".format(self._token)

            # Retry the REST call with new token generated
            rest_ret_code, response = self._make_rest_call(endpoint, intermediate_action_result, headers,
                                                           params, data, method)

            # Assigning intermediate action_result to action_result,
            # since no further invocation required
        if phantom.is_fail(rest_ret_code):
            action_result.set_status(rest_ret_code, intermediate_action_result.get_message())
            return action_result.get_status(), response

        return phantom.APP_SUCCESS, response

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="post", timeout=None):
        """ Function that makes the REST call to the device. It's a generic function that can be called from various
        action handlers.

        :param endpoint: REST endpoint that needs to appended to the service address
        :param action_result: object of ActionResult class
        :param headers: request headers
        :param params: request parameters
        :param data: request body
        :param method: GET/POST/PUT/DELETE (Default will be POST)
        :return: status phantom.APP_ERROR/phantom.APP_SUCCESS(along with appropriate message),
        response obtained by making an API call
        """

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            self.debug_print(ENDGAME_ERR_API_UNSUPPORTED_METHOD.format(method))
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + endpoint

        try:
            response = request_func(url, data=data, headers=headers, params=params, verify=self._verify_server_cert,
                                    timeout=timeout)
        except Exception as e:
            self.debug_print(ENDGAME_EXCEPTION_OCCURRED)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Error Connecting to server. Details: {0}".
                                                   format(str(e))), resp_json)

        return self._process_response(response, action_result)

    def _generate_api_token(self, action_result):
        """ Generate new token based on the credentials provided. Token generated is valid for 60 minutes.

        :param action_result: object of ActionResult class
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        # Request headers
        headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }

        timeout = 30 if self.get_action_identifier() == "test_connectivity" else None

        # Request body
        payload = {'username': self._username, 'password': self._password}

        response_status, response = self._make_rest_call(ENDGAME_LOGIN_ENDPOINT, action_result, headers=headers,
                                                         data=json.dumps(payload), timeout=timeout)

        if phantom.is_fail(response_status):
            return action_result.get_status()

        # Get token from response
        token = response.get("metadata", {}).get("token", "")

        if not token:
            self.debug_print("Failed to generate token")
            return action_result.set_status(phantom.APP_ERROR, "Failed to generate token")

        # Saving the state of token to be used during subsequent actions
        self._state['token'] = self._token = token
        return phantom.APP_SUCCESS

    def _handle_test_connectivity(self, param):
        """ This function tests the connectivity of an asset with given credentials.

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        self.save_progress("Connecting to endpoint")

        response_status = self._generate_api_token(action_result)

        if phantom.is_fail(response_status):
            self.save_progress(ENDGAME_TEST_CONNECTIVITY_FAILURE_MSG)
            return action_result.get_status()

        self.save_progress(ENDGAME_TEST_CONNECTIVITY_SUCCESS_MSG)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_endpoints(self, param):
        """ This function lists all the endpoints/sensors configured on the device.

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # creating parameters dictionary to pass in API call
        params_temp_dict = {
            "tags": None,
            "display_operating_system": None,
            "name": None,
            "ip_address": None,
            "core_os": None
        }

        params_dict = dict()

        for key in params_temp_dict.keys():
            if param.get(key):
                params_dict[key] = param.get(key)

        # Get limit parameter
        limit = int(float(param.get('limit', '50')))

        if limit <= 0:
            self.debug_print(ENDGAME_ERR_INVALID_LIMIT.format(limit=limit))
            return action_result.set_status(phantom.APP_ERROR, ENDGAME_ERR_INVALID_LIMIT.format(limit=limit)), None

        endpoint = ENDGAME_LIST_ENDPOINTS_ENDPOINT

        # For pagination
        while True:

            # If limit is less than 50 modify per_page parameter
            if limit < 50:
                params_dict['per_page'] = limit

            response_status, response = self._make_rest_call_abstract(endpoint=endpoint, action_result=action_result,
                                                                      params=params_dict, method="get")

            if phantom.is_fail(response_status):
                return action_result.get_status()

            # Add data into action_result
            for item in response['data']:
                action_result.add_data(item)

            # Get the endpoint for next page
            endpoint = response['metadata']['next_url']

            limit = limit - response['metadata']['per_page']

            # If limit is reached, break
            if limit <= 0:
                break

            # If next URL is not available, break
            if not endpoint:
                break

        summary = action_result.update_summary({})
        summary['num_endpoints'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_users(self, param):
        """ This function lists all the users configured on the device.

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        response_status, response = self._make_rest_call_abstract(ENDGAME_LIST_USERS_ENDPOINT, action_result, method="get")

        if phantom.is_fail(response_status):
            return action_result.get_status()

        for result in response.get('data', []):
            action_result.add_data(result)

        summary = action_result.update_summary({})
        summary['num_users'] = len(response['data'])

        return action_result.set_status(phantom.APP_SUCCESS)

    def _get_task_id(self, action_result, task):

        spl_task = task.split('_')
        task_name = spl_task[0]
        platform = spl_task[1]

        ret_val, resp_json = self._make_rest_call_abstract(ENDGAME_TASK_DESCRIPTIONS_ENDPOINT, action_result, method='get')

        if phantom.is_fail(ret_val):
            return ret_val

        found = False
        for description in resp_json['data']:
            if description.get('name') == task_name and description.get('sensor_type') == platform:
                found = True
                break

        if not found:
            return action_result.set_status(phantom.APP_ERROR, "Could not find task ID")

        self._state[ENDGAME_STATE_TASK_DICT][task] = description['id']

        return description['id']

    def _launch_investigation(self, action_result, request_body, result_scope, task):
        """ This function launches, then grabs the results of an investigation.

        :param request_body: body of request to launch investigation
        :param action_result: object of ActionResult class
        :param result_scope: the type of results to retrieve
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        ret_val, resp_json = self._make_rest_call_abstract(ENDGAME_LAUNCH_INVESTIGATION_ENDPOINT, action_result, data=json.dumps(request_body))

        if phantom.is_fail(ret_val):

            if ENDGAME_ERR_BAD_TASK_ID in action_result.get_message() or ENDGAME_ERR_BAD_TASK_PARAMS in action_result.get_message():
                self._state[ENDGAME_STATE_TASK_DICT][task] = None
                action_result.append_to_message('\nRefreshed bad task ID. Please try again.')
            else:
                return ret_val

        investigation_id = resp_json.get('data', {}).get('id')

        if not investigation_id:
            return action_result.set_status(phantom.APP_ERROR, "Could not find investigation ID in response")

        while True:

            time.sleep(ENDGAME_SLEEP_TIME)

            ret_val, resp_json = self._make_rest_call_abstract(ENDGAME_LAUNCH_INVESTIGATION_ENDPOINT + '/{0}'.format(investigation_id),
                    action_result, method='get', params={'investigation_id': investigation_id})

            if phantom.is_fail(ret_val):
                return ret_val

            if resp_json.get('data', {}).get('task_completion', {}).get('completed_tasks', 1) == resp_json.get('data', {}).get('task_completion', {}).get('total_tasks', 2):
                break

        while True:

            time.sleep(ENDGAME_SLEEP_TIME)

            ret_val, resp_json = self._make_rest_call_abstract(ENDGAME_GET_COLLECTION_ENDPOINT.format(investigation_id),
                    action_result, method='get', params={'investigation_id': investigation_id})

            if phantom.is_fail(ret_val):
                return ret_val

            try:
                collection_id = resp_json['data'][0]['id']
            except:
                continue

            if collection_id:
                break

        ret_val, resp_json = self._make_rest_call_abstract(ENDGAME_GET_COLLECTION_RESULTS.format(collection_id, result_scope), action_result, method='get')

        if phantom.is_fail(ret_val):
            return ret_val

        results = resp_json.get('data', {'data': {}}).pop('data').get('results', [])
        for result in results:
            action_result.add_data(result)

        action_result.set_summary({'num_results': len(results)})

        return phantom.APP_SUCCESS

    def _handle_hunt_user(self, param):
        """ This function launches an investigation to hunt a specific registry.

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        task = '{0}_{1}'.format(ENDGAME_HUNT_IOC_TASK_NAME, param['platform'])

        task_id = self._state[ENDGAME_STATE_TASK_DICT].get(task)

        if not task_id:
            task_id = self._get_task_id(action_result, task)

        if phantom.is_fail(task_id):
            return task_id

        users = param['user'].split(',')

        task_params = {"find_username": users}

        if 'domain' in param:
            task_params['domain'] = param['domain']

        body = {
            "sensor_ids": param['sensors'].split(','),
            "name": param['name'],
            "tasks": {task_id: {"task_list": [{"username_search": task_params}]}},
            "assign_to": param['assignee'],
            "core_os": param['platform']
        }

        if phantom.is_fail(self._launch_investigation(action_result, body, 'user_sessions', task)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_hunt_registry(self, param):
        """ This function launches an investigation to hunt a specific registry.

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        task = '{0}_{1}'.format(ENDGAME_HUNT_IOC_TASK_NAME, 'windows')

        task_id = self._state[ENDGAME_STATE_TASK_DICT].get(task)

        if not task_id:
            task_id = self._get_task_id(action_result, task)

        if phantom.is_fail(task_id):
            return task_id

        keys = param['key'].split(',')

        task_params = {
            "hive": param['hive'],
            "key": keys
        }

        body = {
            "sensor_ids": param['sensors'].split(','),
            "name": param['name'],
            "tasks": {task_id: {"task_list": [{"registry_search": task_params}]}},
            "assign_to": param['assignee'],
            "core_os": 'windows'
        }

        if phantom.is_fail(self._launch_investigation(action_result, body, 'values', task)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_hunt_ip(self, param):
        """ This function launches an investigation to hunt a specific ip.

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        task = '{0}_{1}'.format(ENDGAME_HUNT_IOC_TASK_NAME, param['platform'])

        task_id = self._state[ENDGAME_STATE_TASK_DICT].get(task)

        if not task_id:
            task_id = self._get_task_id(action_result, task)

        if phantom.is_fail(task_id):
            return task_id

        ips = param['ip'].split(',')

        task_params = {
            "with_state": "ANY",
            "protocol": "ALL",
            "find_remote_ip_address": ips
        }

        body = {
            "sensor_ids": param['sensors'].split(','),
            "name": param['name'],
            "tasks": {task_id: {"task_list": [{"network_search": task_params}]}},
            "assign_to": param['assignee'],
            "core_os": param['platform']
        }

        if phantom.is_fail(self._launch_investigation(action_result, body, 'connections', task)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_hunt_process(self, param):
        """ This function launches an investigation to hunt a specific process.

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        task = '{0}_{1}'.format(ENDGAME_HUNT_IOC_TASK_NAME, param['platform'])

        task_id = self._state[ENDGAME_STATE_TASK_DICT].get(task)

        if not task_id:
            task_id = self._get_task_id(action_result, task)

        if phantom.is_fail(task_id):
            return task_id

        processes = param['process'].split(',')

        if len(processes) == 1 and not phantom.is_hash(processes[0]):
            task_params = {"find_process": processes[0]}

        else:

            md5s = []
            sha1s = []
            sha256s = []

            for process in processes:
                process = process.strip()
                if phantom.is_md5(process):
                    md5s.append(process)
                elif phantom.is_sha1(process):
                    sha1s.append(process)
                elif phantom.is_sha256(process):
                    sha256s.append(process)
                else:
                    return action_result.set_status(phantom.APP_ERROR, "{0} does not appear to be a valid hash".format(process))

            task_params = {
                "with_sha256_hash": sha256s,
                "with_sha1_hash": sha1s,
                "with_md5_hash": md5s
            }

        body = {
            "sensor_ids": param['sensors'].split(','),
            "name": param['name'],
            "tasks": {task_id: {"task_list": [{"process_search": task_params}]}},
            "assign_to": param['assignee'],
            "core_os": param['platform']
        }

        if phantom.is_fail(self._launch_investigation(action_result, body, 'processes', task)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_hunt_file(self, param):
        """ This function launches an investigation to hunt a specific file.

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        task = '{0}_{1}'.format(ENDGAME_HUNT_IOC_TASK_NAME, param['platform'])

        task_id = self._state[ENDGAME_STATE_TASK_DICT].get(task)

        if not task_id:
            task_id = self._get_task_id(action_result, task)

        if phantom.is_fail(task_id):
            return task_id

        md5s = []
        sha1s = []
        sha256s = []
        regexes = []
        files = param['file'].split(',')

        for file_ioc in files:
            file_ioc = file_ioc.strip()
            if phantom.is_md5(file_ioc):
                md5s.append(file_ioc)
            elif phantom.is_sha1(file_ioc):
                sha1s.append(file_ioc)
            elif phantom.is_sha256(file_ioc):
                sha256s.append(file_ioc)
            else:
                regexes.append(file_ioc)

        task_params = {
            "directory": param['directory'],
            "regexes": regexes,
            "with_sha256_hash": sha256s,
            "with_sha1_hash": sha1s,
            "with_md5_hash": md5s
        }

        body = {
            "sensor_ids": param['sensors'].split(','),
            "name": param['name'],
            "tasks": {task_id: {"task_list": [{"file_search": task_params}]}},
            "assign_to": param['assignee'],
            "core_os": param['platform']
        }

        if phantom.is_fail(self._launch_investigation(action_result, body, 'file_list', task)):
            return action_result.get_status()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _launch_task(self, action_result, request_body, task):
        """ This function launches, then grabs the results of a task.

        :param action_result: object of ActionResult class
        :param request_body: body of request to launch task
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        ret_val, resp_json = self._make_rest_call_abstract(ENDGAME_TASKS_ENDPOINT, action_result, data=json.dumps(request_body))

        if phantom.is_fail(ret_val):
            if ENDGAME_ERR_BAD_TASK_ID in action_result.get_message() or ENDGAME_ERR_BAD_TASK_PARAMS in action_result.get_message():
                self._state[ENDGAME_STATE_TASK_DICT][task] = None
                action_result.append_to_message('\nRefreshed bad task ID. Please try again.')
            else:
                return RetVal(ret_val, None)

        bulk_task_id = resp_json.get('data', {}).get('bulk_task_id')

        if not bulk_task_id:
            return action_result.set_status(phantom.APP_ERROR, "Could not get bulk task ID from response")

        while True:

            time.sleep(ENDGAME_SLEEP_TIME)

            ret_val, resp_json = self._make_rest_call_abstract(ENDGAME_TASKS_ENDPOINT, action_result, params={'bulk_task_id': bulk_task_id}, method='get')

            if phantom.is_fail(ret_val):
                return RetVal(ret_val, None)

            collection_id = resp_json.get('data', [{}])[0].get('metadata', {}).get('collection_id')

            if collection_id:
                break

        return self._make_rest_call_abstract(ENDGAME_GET_COLLECTION_RESULTS.format(collection_id, ''), action_result, method='get')

    def _handle_kill_process(self, param):
        """ This function launches an investigation to hunt a specific file.

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        action_result = self.add_action_result(ActionResult(dict(param)))

        task = '{0}_{1}'.format(ENDGAME_HUNT_KILL_PROCESS_TASK_NAME, param['platform'])

        task_id = self._state[ENDGAME_STATE_TASK_DICT].get(task)

        if not task_id:
            task_id = self._get_task_id(action_result, task)

        if phantom.is_fail(task_id):
            return task_id

        body = {
            "description_id": task_id,
            "sensor_ids": param['sensors'].split(','),
            "task": {"pid": int(param['pid'])},
            "core_os": param['platform'].lower()
        }

        ret_val, resp = self._launch_task(action_result, body, task)

        if phantom.is_fail(ret_val):
            return ret_val

        action_result.add_data(resp)

        if resp['data']['status'] == 'failure':
            return action_result.set_status(phantom.APP_ERROR, "Could not kill process. It is possible that the process was not running.")

        return action_result.set_status(phantom.APP_SUCCESS, "Successfully killed process")

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'list_endpoints': self._handle_list_endpoints,
            'list_users': self._handle_list_users,
            'hunt_user': self._handle_hunt_user,
            'hunt_registry': self._handle_hunt_registry,
            'hunt_ip': self._handle_hunt_ip,
            'hunt_process': self._handle_hunt_process,
            'hunt_file': self._handle_hunt_file,
            'kill_process': self._handle_kill_process
        }

        action = self.get_action_identifier()

        try:
            run_action = action_mapping[action]
        except Exception:
            raise ValueError("action {action} is not supported".format(action=action))

        return run_action(param)


if __name__ == '__main__':

    import sys
    # import pudb
    # pudb.set_trace()

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = EndgameConnector()
        connector.print_progress_message = True
        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
