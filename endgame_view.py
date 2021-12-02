# File: endgame_view.py
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
from dateutil import parser


def _get_ctx_result(provides, result):
    """  This function get's called for every result object. The result object represents every ActionResult object that
    you've added in the action handler. Usually this is one per action. This function converts the result object into a
    context dictionary.

    :param provides: Action name
    :param result: ActionResult object
    :return: context dictionary
    """
    ctx_result = {}

    param = result.get_param()
    summary = result.get_summary()
    data = result.get_data()

    ctx_result['param'] = param

    if summary:
        ctx_result['summary'] = summary

    if not data:
        ctx_result['data'] = {}
        return ctx_result
    if provides == "list endpoints":
        ctx_result['data'] = data
    elif provides == "get investigation":
        ctx_result['data'] = data[0]
        ctx_result['data']['total_endpoints'] = len(ctx_result['data']['endpoints'])

        investigation_breakdown = int((ctx_result['data']['task_completion']['completed_tasks'] /
                                       ctx_result['data']['task_completion']['total_tasks']) * 100)
        ctx_result['data']['investigation_breakdown'] = "{investigation_breakdown}%".format(
            investigation_breakdown=investigation_breakdown)

        formatted_time = parser.parse(ctx_result['data']['created_at'])
        ctx_result['data']['created_at'] = "{} UTC".format(formatted_time.strftime('%b %d, %Y %I:%M:%S %p'))

    return ctx_result


def display_action_details(provides, all_app_runs, context):
    """  This function is used to create the context dictionary that the template code can use to render the data.

    :param provides: Action name
    :param all_app_runs: app run
    :param context: context dictionary
    :return HTML file
    """
    context['results'] = results = []

    for summary, action_results in all_app_runs:
        for result in action_results:
            ctx_result = _get_ctx_result(provides, result)
            if not ctx_result:
                continue
            results.append(ctx_result)

    if provides == "list endpoints":
        return 'endgame_list_endpoints.html'

    return "endgame_get_investigation.html"
