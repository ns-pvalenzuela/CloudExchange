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

CTE Recorded Future IOC Plugin.
"""
import traceback
from typing import List

from netskope.integrations.cte.models import Indicator, IndicatorType, SeverityType

from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
)

from .utils.recorded_future_ioc_constants import (
    MODULE_NAME,
    PLATFORM_NAME,
    PLUGIN_VERSION,
)

from .utils.recorded_future_ioc_helper import (
    RecordedFutureIOCPluginException,
    RecordedFutureIOCPluginHelper
)


class RecordedFutureIOCPlugin(PluginBase):
    """Recorded Future IOC Plugin class template implementation."""

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
        self.recorded_future_ioc_helper = RecordedFutureIOCPluginHelper(
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
            metadata_json = RecordedFutureIOCPlugin.metadata
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
        """Pull indicators from Recorded Future IOC plugin."""
        indicators = []
        risklists = self.configuration.get("risklists", "")

        self.logger.info(f"{self.log_prefix}: Pulling IOC(s) of the risklist(s) {risklists}")
        for risklist in risklists:
            url = ("https://api.recordedfuture.com/v2/" +
                   risklist +
                   "/risklist?format=csv%2Fsplunk&gzip=false&list=default")

            try:
                response = self.recorded_future_ioc_helper.api_helper(
                    url=url,
                    method="GET",
                    verify=self.ssl_validation,
                    proxies=self.proxy,
                    logger_msg="pulling IOC(s)",
                    headers={"X-RFToken": self.configuration['apikey'],
                             "Content-Type": "application/json",
                             "accept": "application/json"}
                )
                indicators, indicator_count = self.extract_indicators(
                    response, risklist, indicators
                )

                self.logger.debug(
                    f"Pull Stat: {indicator_count} indicator(s) were fetched. "
                )
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{indicator_count} IOC(s) "
                    f"from the {risklist} risklist'"
                )

            except RecordedFutureIOCPluginException as exp:
                err_msg = "Error occurred while pulling indicators."
                self.logger.error(
                    message=(f"{self.log_prefix}: {err_msg} Error: {str(exp)}"),
                    details=str(traceback.format_exc()),
                )
                raise exp
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

    def extract_indicators(self, response, risklist, indicators) -> tuple[list, int]:
        """
        Extract indicators from a given response based on the specified indicator types.

        Args:
            response (str): The response from which to extract indicators.
            indicator_type (string): the type of IOC fetching

        Returns:
            Tuple[List[dict], int]: A tuple containing a list of extracted \
                                    indicators and the number of indicators.
        """
        indicator_count = 0
        headers = True

        for line in response.splitlines():
            if not headers:
                values = line.split('","')

                # convert risklist into netskope types.
                if risklist == 'ip':
                    if ":" in values[0]:
                        current_type = getattr(IndicatorType, "IPV6", IndicatorType.URL)
                    else:
                        current_type = getattr(IndicatorType, "IPV4", IndicatorType.URL)
                elif risklist == 'hash':
                    if values[1] == 'SHA-256':
                        current_type = IndicatorType.SHA256
                    elif values[1] == 'MD5':
                        current_type = IndicatorType.MD5
                    else:
                        self.logger.debug(f"Hash type not found: {values[1]}")
                        continue
                elif risklist == 'domain':
                    current_type = getattr(IndicatorType, "DOMAIN", IndicatorType.URL)
                elif risklist == 'url':
                    current_type = IndicatorType.URL
                else:
                    err_msg = "Error converting indicator type" + risklist
                    self.logger.error(
                        message=(
                            f"{self.log_prefix}: {err_msg}"
                        )
                    )
                    continue

                current_indicator_value=values[0][1:]
                if risklist == 'hash':
                    current_risk_score = int(values[2])
                    current_evidences = values[4]
                else:
                    current_risk_score = int(values[1])
                    current_evidences = values[3]
                if self.configuration.get("fetchevidences", "") == "yes":
                    current_evidences = ''.join(current_evidences)
                else:
                    current_evidences = ''
                if type(current_risk_score) is not int or current_risk_score == 0:
                    current_risk = SeverityType.UNKNOWN
                elif current_risk_score <= 39:
                    current_risk = SeverityType.LOW
                elif current_risk_score <= 69:
                    current_risk = SeverityType.MEDIUM
                elif current_risk_score <= 89:
                    current_risk = SeverityType.HIGH
                else:
                    current_risk = SeverityType.CRITICAL

                indicators.append(
                    Indicator(
                        value=current_indicator_value,
                        type=current_type,
                        severity=current_risk,
                        comments=current_evidences.replace('"','')
                    )
                )
                indicator_count += 1
            else:
                headers = False

        return indicators, indicator_count

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidationResult: ValidationResult object with
            success flag and message.
        """
        apikey =  configuration.get("apikey", "")
        validation_err = "Validation error occurred."
        if not apikey:
            err_msg = "API Key is a required configuration parameter."
            self.logger.error(f"{self.log_prefix}: {validation_err} {err_msg}")
            return ValidationResult(success=False, message=err_msg)

        return ValidationResult(success=True, message="Validation Successful for Recoded Future IOC plugin")