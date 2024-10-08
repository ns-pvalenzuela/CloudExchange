"""
BSD 3-Clause License

Copyright (c) 2021, Netskope OSS
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

CTE Maltiverse Plugin.
"""
import traceback, json, ipaddress, re
from typing import Dict, List, Tuple
from datetime import datetime

from netskope.integrations.cte.models import (
    Indicator,
    IndicatorType,
    SeverityType,
)

from netskope.integrations.cte.models.business_rule import (
    Action,
    ActionWithoutParams,
)

from netskope.integrations.cte.plugin_base import (
    PluginBase,
    PushResult,
    ValidationResult,
)

from .utils.maltiverse_constants import (
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
)

from .utils.maltiverse_helper import (
    MaltiversePluginHelper
)


class MaltiversePlugin(PluginBase):
    """Maltiverse Plugin class template implementation."""

    def __init__(
            self,
            name,
            *args,
            **kwargs,
    ):
        """Initialize Plugin class."""
        super().__init__(
            name,
            *args,
            **kwargs,
        )
        self.plugin_name, self.plugin_version = self._get_plugin_info()
        self.log_prefix = f"{MODULE_NAME} {self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"
        self.maltiverse_helper = MaltiversePluginHelper(
            logger=self.logger,
            log_prefix=self.log_prefix,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version
        )

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from metadata.
        """
        try:
            metadata_json = MaltiversePlugin.metadata
            plugin_name = metadata_json.get("name", PLATFORM_NAME)
            plugin_version = metadata_json.get("version", PLUGIN_VERSION)
            return plugin_name, plugin_version
        except Exception as exp:
            self.logger.error(
                message=(
                    "{} {}: Error occurred while"
                    " getting plugin details. Error: {}".format(
                        MODULE_NAME, PLATFORM_NAME, exp
                    )
                ),
                details=traceback.format_exc(),
            )
        return PLATFORM_NAME, PLUGIN_VERSION

    def pull(self) -> List[Indicator]:
        """Pull indicators from Maltiverse plugin."""
        indicators = []
        feeds = []

        if self.configuration.get("feedids", "value"):
            feeds += self.configuration.get("feedids", "value")
        if self.configuration.get("otherfeeds", ""):
            otherfeeds = self.configuration.get("otherfeeds", "")
            feeds += otherfeeds.split(',')
            feeds = map(str.strip, feeds)

        temp_feeds = ''.join(feeds)
        self.logger.debug(
            f"Pulling indicators from: {temp_feeds}. "
        )
        for feed in feeds:
            if not feed:
                continue
            url = ("https://api.maltiverse.com/collection/" +
                   feed +
                   "/download")

            try:
                response = self.maltiverse_helper.api_helper(
                    url=url,
                    method="GET",
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg="pulling IOC(s)",
                    headers={"accept": "application/json",
                             "Authorization": f"Bearer {self.configuration['apikey']}"
                             }
                )
                indicators, indicator_count = self.extract_indicators(
                    response, indicators
                )

                self.logger.debug(
                    f"Pull Stat: {indicator_count} indicator(s) were fetched. "
                )
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{indicator_count} IOC(s) "
                    f"from feed ID {feed}"
                )
            except Exception as exp:
                err_msg = "Error occurred while pulling indicators."
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {err_msg} Error: {str(exp)}"
                    ),
                    details=str(traceback.format_exc()),
                )
                raise exp

        return indicators

    def extract_indicators(self, response, indicators) -> tuple[list, int]:
        """
        Extract indicators from a given response based on the specified indicator types.

        Args:
            response (str): The response from which to extract indicators.
            indicators (list): current indicator list

        Returns:
            Tuple[list[dict], int]: A tuple containing a set of extracted \
                                    indicators and the number of indicators.
        """
        indicator_count = 0

        json_response = json.loads(response)
        for registry in json_response:
            if registry['classification'] not in self.configuration.get("classifications", "value"):
                classlist = self.configuration.get("classifications", "value")
                self.logger.debug(
                    f"Skipping: {registry['classification']}. "
                    f"List: {classlist}"
                )
                continue

            if registry['type'] == 'sample':
                current_type = IndicatorType.SHA256
                current_indicator_value = registry['sha256']
            elif registry['type'] == 'ip':
                current_indicator_value = registry['ip_addr']
                current_type = getattr(IndicatorType, "IPV4", IndicatorType.URL)
            elif registry['type'] == 'ipv6':
                current_indicator_value = registry['ip_addr']
                current_type = getattr(IndicatorType, "IPV6", IndicatorType.URL)
            elif registry['type'] == 'url':
                current_type = IndicatorType.URL
                current_indicator_value = registry['url']
            elif registry['type'] == 'hostname':
                current_type = getattr(IndicatorType, "DOMAIN", IndicatorType.URL)
                current_indicator_value = registry['hostname']
            else:
                err_msg = "Error converting indicator type " + registry['type']
                self.logger.error(
                    message=(
                        f"{self.log_prefix}: {err_msg}"
                    )
                )
                continue

            malicious_severity, suspicious_severity, neutral_severity = self._severity_convert()
            if registry['classification'] == 'malicious':
                current_risk = malicious_severity
            elif registry['classification'] == 'suspicious':
                current_risk = suspicious_severity
            elif registry['classification'] == 'neutral':
                current_risk = neutral_severity
            else:
                current_risk = SeverityType.UNKNOWN

            indicators.append(
                Indicator(
                    value=current_indicator_value,
                    type=current_type,
                    severity=current_risk
                )
            )
            indicator_count += 1

        return indicators, indicator_count

    def _severity_convert(self) -> Tuple:
        if self.configuration.get("malicious_severity", "value") == "critical":
            malicious_severity = SeverityType.CRITICAL
        elif self.configuration.get("malicious_severity", "value") == "high":
            malicious_severity = SeverityType.HIGH
        elif self.configuration.get("malicious_severity", "value") == "medium":
            malicious_severity = SeverityType.MEDIUM
        else:
            malicious_severity = SeverityType.LOW

        if self.configuration.get("suspicious_severity", "value") == "critical":
            suspicious_severity = SeverityType.CRITICAL
        elif self.configuration.get("suspicious_severity", "value") == "high":
            suspicious_severity = SeverityType.HIGH
        elif self.configuration.get("suspicious_severity", "value") == "medium":
            suspicious_severity = SeverityType.MEDIUM
        else:
            suspicious_severity = SeverityType.LOW

        if self.configuration.get("neutral_severity", "value") == "critical":
            neutral_severity = SeverityType.CRITICAL
        elif self.configuration.get("neutral_severity", "value") == "high":
            neutral_severity = SeverityType.HIGH
        elif self.configuration.get("neutral_severity", "value") == "medium":
            neutral_severity = SeverityType.MEDIUM
        else:
            neutral_severity = SeverityType.LOW

        return malicious_severity, suspicious_severity, neutral_severity

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.
        Args:
            configuration (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidationResult: ValidationResult object with
            success flag and message.
        """
        apikey = configuration.get("apikey", "")
        validation_err = "Validation error occurred."
        if not apikey:
            err_msg = "API Key is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {validation_err} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        feedids = configuration.get("otherfeeds", "")
        customfeeds = configuration.get("feedids", "")
        if not feedids and not customfeeds:
            err_msg = "Either Standard or Custom Feedids are required."
            self.logger.error(f"{self.log_prefix}: {validation_err} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        return ValidationResult(success=True, message="Validation Successful for Maltiverse plugin")

    def push(self, indicators: List[Indicator], action_dict: Dict):
        """Push the Indicator list to Maltiverse.

        Args:
            indicators (List[cte.models.Indicators]): List of Indicator
            objects to be pushed.
            action_dict (Dict): Business rule action tags
        Returns:
            cte.plugin_base.PushResult: PushResult object with success
            flag and Push result message.
        """

        # Convert IOCs to Maltiverse format
        generated_payload = []
        total_ioc_count = 0
        skipped_ioc = 0

        for indicator in indicators:
            total_ioc_count += 1
            first_seen = indicator.firstSeen
            last_seen = indicator.lastSeen

            ioc_payload = '{"blacklist": [{'
            if indicator.comments:
                ioc_payload += '"description": "' + indicator.comments + '"'
            else:
                ioc_payload += '"description": "malicious sample indicator from Netskope Cloud Threat Exchange"'
            ioc_payload += (',"first_seen": "' + first_seen.strftime("%Y-%m-%d %H:%M:%S") +
                            '","last_seen": "' + last_seen.strftime("%Y-%m-%d %H:%M:%S") +
                            '","source": "Netskope Cloud Threat Exchange"}]')

            action_params = action_dict.get("parameters", {})
            if indicator.severity in action_params.get("malicious", []):
                ioc_payload += ',"classification": "malicious"'
            elif indicator.severity in action_params.get("suspicious", []):
                ioc_payload += ',"classification": "suspicious"'
            elif indicator.severity in action_params.get("neutral", []):
                ioc_payload += ',"classification": "neutral"'
            else:
                skipped_ioc += 1
                continue

            ioc_value = indicator.value.lower()
            if indicator.type == IndicatorType.SHA256:
                ioc_payload += ',"type": "sample", "sha256": "' + ioc_value + '"'
            elif indicator.type == IndicatorType.MD5:
                ioc_payload += ',"type": "sample", "md5": "' + ioc_value + '"'
            else:
                if '/' in ioc_value:
                    ioc_payload += ',"type": "url", "url": "' + ioc_value + '"'
                elif re.match(
                        r"^(?!.{255}|.{253}[^.])([a-z0-9](?:[-a-z-0-9]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?[.]?$",
                        ioc_value,
                        re.IGNORECASE,
                ):
                    ioc_payload += ',"type": "hostname", "hostname": "' + ioc_value + '"'
                elif ipaddress.IPv4Address(ioc_value):
                    ioc_payload += ',"type": "ip", "ip_addr": "' + ioc_value + '"'
                elif ipaddress.IPv6Address(ioc_value):
                    ioc_payload += ',"type": "ip", "ip_addr": "' + ioc_value + '"'
                else:
                    skipped_ioc += 1
                    continue
            ioc_payload += '}'

            # Multiple requests with a maximum element limit
            if total_ioc_count % 7000 == 0:
                # Share indicators with Maltiverse.
                try:
                    self.maltiverse_helper.api_helper(
                        url="https://api.maltiverse.com/bulk",
                        method="POST",
                        verify=self.ssl_validation,
                        proxies=self.proxy,
                        logger_msg="pushing IOC(s)",
                        headers={"accept": "application/json",
                                 "Authorization": f"Bearer {self.configuration['apikey']}"
                                 },
                        json=generated_payload
                    )

                    self.logger.debug(
                        f"Pull Stat: {len(generated_payload)} indicator(s) were sent. "
                    )

                except Exception as exp:
                    err_msg = "Error occurred while pushing indicators."
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {err_msg} Error: {str(exp)}"
                        ),
                        details=str(traceback.format_exc()),
                    )
                    raise exp
                generated_payload = []
            else:
                generated_payload.append(json.loads(ioc_payload))

        log_msg = (
            f"{self.log_prefix}: Successfully pushed "
            f"{total_ioc_count - skipped_ioc} indicators out of {total_ioc_count}"
        )
        return PushResult(
            success=True,
            message=log_msg,
        )

    def get_actions(self):
        """Get available actions.
        Returns:
        List[ActionWithoutParams]: List of ActionWithoutParams objects that are supported by the plugin.
        """
        return [
            ActionWithoutParams(label="Send IOCs", value="send"),
        ]

    def get_action_fields(self, action: Action):
        """
        Get fields required for an action.

        Args:
            action (Action): Action to perform on IoCs.
        """
        action_value = action.value
        if action_value == "send":
            return [
                {
                    "label": "Send as Malicious IOCs",
                    "key": "malicious",
                    "type": "multichoice",
                    "choices": [
                        {
                            "key": "Include Critical IOCs",
                            "value": SeverityType.CRITICAL,
                        },
                        {
                            "key": "Include High IOCs",
                            "value": SeverityType.HIGH,
                        },
                        {
                            "key": "Include Medium IOCs",
                            "value": SeverityType.MEDIUM,
                        },
                        {
                            "key": "Include Low IOCs",
                            "value": SeverityType.LOW,
                        },
                    ],
                    "default": [SeverityType.HIGH, SeverityType.CRITICAL],
                    "mandatory": True,
                    "description": (
                        "What severities to include as malicious when sending IOCs"
                    ),
                },
                {
                    "label": "Send as Suspicious IOCs",
                    "key": "suspicious",
                    "type": "multichoice",
                    "choices": [
                        {
                            "key": "Include Critical IOCs",
                            "value": SeverityType.CRITICAL,
                        },
                        {
                            "key": "Include High IOCs",
                            "value": SeverityType.HIGH,
                        },
                        {
                            "key": "Include Medium IOCs",
                            "value": SeverityType.MEDIUM,
                        },
                        {
                            "key": "Include Low IOCs",
                            "value": SeverityType.LOW,
                        },
                    ],
                    "default": SeverityType.MEDIUM,
                    "mandatory": True,
                    "description": (
                        "What severities to include as malicious when sending IOCs"
                    ),
                },
                {
                    "label": "Send as Neutral IOCs",
                    "key": "neutral",
                    "type": "multichoice",
                    "choices": [
                        {
                            "key": "Include Critical IOCs",
                            "value": SeverityType.CRITICAL,
                        },
                        {
                            "key": "Include High IOCs",
                            "value": SeverityType.HIGH,
                        },
                        {
                            "key": "Include Medium IOCs",
                            "value": SeverityType.MEDIUM,
                        },
                        {
                            "key": "Include Low IOCs",
                            "value": SeverityType.LOW,
                        },
                    ],
                    "default": SeverityType.LOW,
                    "mandatory": True,
                    "description": (
                        "What severities to include as malicious when sending IOCs"
                    ),
                }
            ]

    def validate_action(self, action: Action) -> ValidationResult:
        action_params = action.parameters
        for list_malicious in action_params.get("malicious", []):
            for list_suspicious in action_params.get("suspicious", []):
                if (
                        list_malicious == list_suspicious
                        or list_malicious in action_params.get("neutral", [])
                        or list_suspicious in action_params.get("neutral", [])
                ):
                    return ValidationResult(
                        success=False,
                        message="A severity can't be in two Maltiverse classifications at the same time."
                    )

        return ValidationResult(success=True, message="Validation successful.")
