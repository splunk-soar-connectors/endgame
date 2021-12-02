# File: endgame_consts.py
#
# Copyright (c) 2018 Splunk Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software distributed under
# the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific language governing permissions
# and limitations under the License.
#
#
# of Phantom Cyber Corporation.
# Define your constants here
ENDGAME_TASKS_ENDPOINT = "/api/v1/tasks"
ENDGAME_LIST_USERS_ENDPOINT = "/api/v1/users"
ENDGAME_LOGIN_ENDPOINT = "/api/v1/auth/login/"
ENDGAME_LIST_ENDPOINTS_ENDPOINT = "/api/v1/endpoints"
ENDGAME_GET_COLLECTION_ENDPOINT = "/api/v1/activities"
ENDGAME_LAUNCH_INVESTIGATION_ENDPOINT = "/api/v1/investigations"
ENDGAME_TASK_DESCRIPTIONS_ENDPOINT = "/api/v1/task-descriptions"
ENDGAME_GET_AGGREGATION_RESULTS = "/api/v1/collections/aggregations"
ENDGAME_GET_COLLECTION_RESULTS = "/api/v1/collections/{0}?scope={1}"
ENDGAME_GET_INVESTIGATION_ENDPOINT = "/api/v1/collections/query-rows"

ENDGAME_TEST_CONNECTIVITY_SUCCESS_MSG = "Test Connectivity Passed"
ENDGAME_TEST_CONNECTIVITY_FAILURE_MSG = "Test Connectivity Failed"

ENDGAME_EXCEPTION_OCCURRED = "Exception occurred"
ENDGAME_ERR_INVALID_LIMIT = "Invalid limit : {limit}"
ENDGAME_ERR_API_UNSUPPORTED_METHOD = "Unsupported method {method}"

ENDGAME_ERR_BAD_TASK_ID = "taskName UNKNOWN"
ENDGAME_ERR_BAD_TASK_PARAMS = "Invalid tasking payload"

ENDGAME_HUNT_IOC_TASK_NAME = "iocSearchRequest"
ENDGAME_HUNT_KILL_PROCESS_TASK_NAME = "killProcessRequest"

ENDGAME_STATE_TASK_DICT = "tasks"

ENDGAME_SLEEP_TIME = 5
