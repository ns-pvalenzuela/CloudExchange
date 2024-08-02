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
import re
import traceback
from ipaddress import IPv4Address, IPv6Address, ip_address
from typing import Dict, List

from urllib.parse import urlparse
from pydantic import ValidationError

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


class RecordedFutureIOC(PluginBase):
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
        """Pull indicators from Web Page IOC Scraper Plugin."""
        url = ("https://api.recordedfuture.com/v2/" +
               self.configuration['risklist'] +
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
                response, self.configuration['risklist']
            )

            self.logger.debug(
                f"Pull Stat: {indicator_count} indicator(s) were fetched. "
            )
            self.logger.info(
                f"{self.log_prefix}: Successfully fetched "
                f"{indicator_count} IOC(s) "
                f"from '{url}'."
            )

            return indicators

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

    def extract_indicators(self, response, indicator_type) -> tuple[list, int]:
        """
        Extract indicators from a given response based on the specified indicator types.

        Args:
            response (str): The response from which to extract indicators.
            indicator_type (string): the type of IOC fetching

        Returns:
            Tuple[List[dict], int]: A tuple containing a list of extracted \
                                    indicators and the number of indicators.
        """
        indicators = []
        indicator_count = 0
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

    def _validate_url(self, url):
        """
        Validate the URL provided in configuration parameters.

        Args:
            url (str): The URL to validate.

        Returns:
            ValidationResult: The result of the validation.
        """
        try:
            self.logger.debug(
                f"{self.log_prefix}: Validating URL provided in configuration parameters."
            )
            self.recorded_future_ioc_helper.api_helper(
                url=url,
                method="GET",
                verify=self.ssl_validation,
                proxies=self.proxy,
                logger_msg=f"verifying the connectivity with {url}.",
                is_validation=True
            )

            validation_msg = f"Validation successful for {MODULE_NAME} {self.plugin_name} Plugin."
            self.logger.debug(f"{self.log_prefix}: {validation_msg}")
            return ValidationResult(
                success=True,
                message=validation_msg,
            )
        except RecordedFutureIOCPluginException as exp:
            err_msg = f"Validation error occurred. Error: {exp}"
            self.logger.error(
                message=f"{self.log_prefix}: {err_msg}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(success=False, message=str(exp))
        except Exception as exp:
            validation_err = "Validation error occurred."
            err_msg = f"{validation_err} Check logs for more details."
            self.logger.error(
                message=f"{self.log_prefix}: {validation_err} Error: {exp}",
                details=str(traceback.format_exc()),
            )
            return ValidationResult(success=False, message=err_msg)
