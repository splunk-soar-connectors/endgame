# --
# File: endgame_consts.py
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
