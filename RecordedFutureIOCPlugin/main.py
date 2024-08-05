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

from netskope.integrations.cte.models import Indicator, IndicatorType

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
        indicator_count = 0
        for risklist in self.configuration.get("risklists", ""):
            url = ("https://api.recordedfuture.com/v2/" +
                   risklist +
                   "/risklist?format=csv%2Fsplunk&gzip=false&list=default")

            try:
                self.logger.info(f"{self.log_prefix}: Pulling IOC(s) from {url}.")
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
                    response, risklist, indicators, indicator_count
                )

                self.logger.debug(
                    f"Pull Stat: {indicator_count} indicator(s) were fetched. "
                )
                self.logger.info(
                    f"{self.log_prefix}: Successfully fetched "
                    f"{indicator_count} IOC(s) "
                    f"from '{url}'."
                    f"of type '{risklist}'"
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

    def extract_indicators(self, response, indicator_type, indicators, indicator_count) -> tuple[list, int]:
        """
        Extract indicators from a given response based on the specified indicator types.

        Args:
            response (str): The response from which to extract indicators.
            indicator_type (string): the type of IOC fetching

        Returns:
            Tuple[List[dict], int]: A tuple containing a list of extracted \
                                    indicators and the number of indicators.
        """
        headers = True

        for line in response.splitlines():
            if not headers:
                values = line.split(",")
                indicators.append(
                    Indicator(value=values[0], type=indicator_type)
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