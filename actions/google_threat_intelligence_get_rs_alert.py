# File: google_threat_intelligence_get_rs_alert.py
#
# Copyright 2025-2026 Google LLC
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

import phantom.app as phantom

import google_threat_intelligence_consts as consts
from actions import BaseAction


class GetRSAlert(BaseAction):
    """Class to handle get RS alert action."""

    def execute(self):
        """Execute get RS alert action.

        Step 1: Validate parameters
        Step 2: Get project ID from asset config
        Step 3: Get request url
        Step 4: Invoke API
        Step 5: Handle the response
        """
        self._connector.save_progress(consts.EXECUTION_START_MSG.format("get_rs_alert"))

        ret_val = self.__validate_params()
        if phantom.is_fail(ret_val):
            return self._action_result.get_status()

        alert_id = self._param.get("alert_id")
        project_id = self._connector.get_config().get("project-id-rs")

        endpoint = consts.GET_RS_ALERT_ENDPOINT.format(project=project_id, alert=alert_id)
        method = "get"
        headers = {
            "Content-Type": "application/json",
            "x-goog-user-project": project_id,
        }

        ret_val, response = self._make_rest_call(url=endpoint, method=method, headers=headers)

        return self.__handle_response(ret_val, response)

    def __validate_params(self):
        """Validate parameters of the action.

        Args:
            self (object): This object

        Returns:
            bool: True if validation is successful, False otherwise
        """

        # Get project ID from asset configuration
        project_id = self._connector.get_config().get("project-id-rs")
        if not project_id:
            return self._action_result.set_status(
                phantom.APP_ERROR,
                consts.ERROR_MISSING_PROJECT_ID,
            )

        # Validate alert_id format (UUID v4)
        alert_id = self._param.get("alert_id")
        ret_val, _ = self._connector.validator.validate_alert_id_uuid(self._action_result, alert_id)
        if phantom.is_fail(ret_val):
            return ret_val

        return True

    def _make_rest_call(self, url, method, headers=None):
        """
        Make a REST call to the API.

        Args:
            url (str): The URL of the API endpoint
            method (str): The HTTP method to use (e.g. "get", "post")
            headers (dict, optional): A dictionary of headers to send with the request
            param (dict, optional): A dictionary of query parameters to send with the request
            body (dict, optional): A dictionary of data to send as the request body

        Returns:
            tuple: A tuple containing the status of the request and the response
        """
        args = {
            "endpoint": url,
            "action_result": self._action_result,
            "method": method.lower(),
            "headers": headers or {},
        }

        return self._connector.util.make_rest_call_rs(**args)

    def __handle_response(self, ret_val, response):
        """
        Handle the response from the API call

        Args:
            ret_val (RetVal): The return value of the API call
            response (dict or list): The response from the API call

        Returns:
            int: The status of the request
        """
        if phantom.is_fail(ret_val):
            return self._action_result.get_status()

        if isinstance(response, dict) and response.get("name"):
            alert_id = self._connector.util._extract_alert_id(response.get("name", ""))
            response["alert_id"] = alert_id
            self._action_result.add_data(response)
        else:
            self._action_result.add_data(response)

        return self._action_result.set_status(
            phantom.APP_SUCCESS,
            consts.ACTION_GET_RS_ALERT_SUCCESS_RESPONSE,
        )
