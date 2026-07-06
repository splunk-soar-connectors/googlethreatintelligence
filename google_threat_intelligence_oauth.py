# File: google_threat_intelligence_oauth.py
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
import requests

import google_threat_intelligence_consts as consts


class GoogleThreatIntelligenceOAuth:
    """Handles OAuth 2.0 authentication for Google Threat Intelligence API."""

    def __init__(self, connector):
        """Initialize OAuth handler.

        Args:
            connector: The connector instance
        """
        self._connector = connector

    def generate_and_save_token(self, action_result):
        """Generate a new OAuth access token and save it to state.

        This function generates a new token from the API key and saves it directly
        to the connector state using save_state method.

        Args:
            action_result: The action result object

        Returns:
            tuple: (status, access_token) where status is phantom.APP_SUCCESS or phantom.APP_ERROR
        """
        config = self._connector.get_config()
        api_key = config.get("x-apikey")

        if not api_key:
            return (
                action_result.set_status(
                    phantom.APP_ERROR,
                    consts.ERROR_MISSING_OAUTH_API_KEY,
                ),
                None,
            )

        try:
            self._connector.save_progress("Requesting OAuth token from Google Threat Intelligence API")

            payload = {"api_key": api_key}
            headers = {"Content-Type": "application/json", "User-Agent": "SplunkSoar"}

            response = requests.post(consts.OAUTH_TOKEN_ENDPOINT, headers=headers, json=payload)

            ret_val, token_response = self._connector.util._process_response(response, action_result)
            if phantom.is_fail(ret_val):
                return ret_val, None

            access_token = token_response.get("access_token")

            if not access_token:
                return (
                    action_result.set_status(
                        phantom.APP_ERROR,
                        consts.ERROR_INVALID_OAUTH_RESPONSE,
                    ),
                    None,
                )

            # Encrypt and save token to state
            self._connector._state["oauth_token_data"] = {"access_token": access_token, "is_encrypted": False}

            state = self._connector.util.encrypt_state(self._connector._state, self._connector.get_asset_id())
            self._connector.save_state(state)

            self._connector.debug_print("OAuth token encrypted and saved to state")
            return phantom.APP_SUCCESS, access_token

        except Exception as e:
            error_msg = self._connector.util._get_error_message_from_exception(e)
            return (
                action_result.set_status(
                    phantom.APP_ERROR,
                    f"Error generating OAuth token: {error_msg}",
                ),
                None,
            )

    def get_auth_headers(self, action_result):
        """Get authorization headers with OAuth token from state.

        Retrieves the access token from connector state, decrypts it, and returns auth headers.
        If no token is present, generates one first.

        Returns:
            tuple: (status, headers) where status is phantom.APP_SUCCESS or phantom.APP_ERROR
                   and headers is a dict with Authorization Bearer token, or None on failure
        """
        state = self._connector.util.decrypt_state(self._connector._state, self._connector.get_asset_id())
        access_token = state.get("oauth_token_data", {}).get("access_token")
        if not access_token:
            self._connector.debug_print("Access Token not found in the state")
            ret_val, access_token = self.generate_and_save_token(action_result)
            if phantom.is_fail(ret_val):
                return ret_val, None

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}",
        }

        return phantom.APP_SUCCESS, headers
