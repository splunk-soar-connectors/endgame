# --
# File: endgame_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2017
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
import requests
from bs4 import BeautifulSoup

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
from endgame_consts import *


class RetVal(tuple):
    def __new__(cls, val1, val2):
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

        # get the asset config
        config = self.get_config()
        self._token = self._state.get("token")
        # Required values can be accessed directly
        self._base_url = config['url'].strip("/")
        self._username = config['username']
        self._password = config['password']
        self._verify_server_cert = config.get('verify_server_cert', False)

        return phantom.APP_SUCCESS

    def _process_empty_response(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"),
                      None)

    def _process_html_response(self, response, action_result):

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

        # Try a json parse
        try:
            resp_json = response.json()
        except Exception as e:
            self.debug_print("Unable to parse the response into a dictionary", e)
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".
                                                   format(str(e))), None)

        # Please specify the status codes here
        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, resp_json)

        message = "Error from server. Status Code: {0} Data from server: {1}".format(response.status_code,
                                                                                     response.text.replace('{', '{{').
                                                                                     replace('}', '}}'))

        # Process the error returned in the json
        if resp_json.get('error'):
            message = "Error from server. Status Code: {0} Data from server: {1}".format(
                response.status_code, resp_json['error']['message'])

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, response, action_result):

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

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="post",
                        timeout=None):
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
        summary['total_endpoints'] = action_result.get_data_size()

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_investigation(self, param):
        """ This function lists all the endpoints/sensors configured on the device.

        :param param: dictionary of input parameters
        :return: status phantom.APP_SUCCESS/phantom.APP_ERROR (along with appropriate message)
        """

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        investigation_id = param['investigation_id']

        response_status, response = self._make_rest_call_abstract(ENDGAME_GET_INVESTIGATION_ENDPOINT.format(
            investigation_id=investigation_id), action_result, method="get")

        if phantom.is_fail(response_status):
            return action_result.get_status()

        action_result.add_data(response['data'])

        return action_result.set_status(phantom.APP_SUCCESS, "Investigation found")

    def handle_action(self, param):
        """ This function gets current action identifier and calls member function of its own to handle the action.

        :param param: dictionary which contains information about the actions to be executed
        :return: status success/failure
        """

        # Dictionary mapping each action with its corresponding actions
        action_mapping = {
            'test_connectivity': self._handle_test_connectivity,
            'list_endpoints': self._handle_list_endpoints,
            'get_investigation': self._handle_get_investigation
        }

        action = self.get_action_identifier()

        try:
            run_action = action_mapping[action]
        except Exception:
            raise ValueError("action {action} is not supported".format(action=action))

        return run_action(param)

    def finalize(self):
        """ This function gets called once all the param dictionary elements are looped over and no more handle_action
        calls are left to be made. It gives the AppConnector a chance to loop through all the results that were
        accumulated by multiple handle_action function calls and create any summary if required. Another usage is
        cleanup, disconnect from remote devices etc.
        """

        # Save the state, this data is saved across actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import sys
    import pudb
    pudb.set_trace()

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
