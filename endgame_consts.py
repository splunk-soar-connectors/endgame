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
ENDGAME_GET_AGGREGATION_RESULTS = "/api/v1/collections/aggregations"
ENDGAME_GET_COLLECTION_RESULTS = "/api/v1/collections/{0}?scope={1}"
ENDGAME_GET_INVESTIGATION_ENDPOINT = "/api/v1/collections/query-rows"

ENDGAME_TEST_CONNECTIVITY_SUCCESS_MSG = "Test Connectivity Passed"
ENDGAME_TEST_CONNECTIVITY_FAILURE_MSG = "Test Connectivity Failed"

ENDGAME_EXCEPTION_OCCURRED = "Exception occurred"
ENDGAME_ERR_INVALID_LIMIT = "Invalid limit : {limit}"
ENDGAME_ERR_API_UNSUPPORTED_METHOD = "Unsupported method {method}"

ENDGAME_HUNT_IOC_TASK_ID = "c1186c30-2781-5bf7-8a8a-fd0e811419b6"
ENDGAME_HUNT_USERS_TASK_ID = "e9aa0e0d-567a-5f71-afb9-6098d038be36"
ENDGAME_HUNT_MEDIA_TASK_ID = "7a0480f1-2d87-5747-a98a-0017c6d3f857"
ENDGAME_HUNT_DRIVERS_TASK_ID = "ccd9c719-f163-53e4-add2-8c312c94c40f"
ENDGAME_HUNT_SYS_CONFIG_TASK_ID = "995d9565-3498-557d-a9e6-b5b8e445d004"
ENDGAME_HUNT_FILE_SYSTEM_TASK_ID = "f5917193-5769-5c1a-adf6-02080a83fc5f"
ENDGAME_HUNT_APPLICATIONS_TASK_ID = "ac384faa-c67d-5987-9137-7030f843d27b"
ENDGAME_HUNT_KILL_PROCESS_TASK_ID = "5b2690be-0681-595a-93ef-c82a71526177"
ENDGAME_HUNT_FIREWALL_RULES_TASK_ID = "b09c4cd2-359c-5981-9124-d8621ace2684"

ENDGAME_SLEEP_TIME = 5
