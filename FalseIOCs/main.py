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

False IOCs Plugin.
"""
import traceback, random, string, hashlib
from typing import List

from netskope.integrations.cte.models import Indicator, IndicatorType, SeverityType

from netskope.integrations.cte.plugin_base import (
    PluginBase,
    ValidationResult,
)


class FalseIOCsPlugin(PluginBase):
    """False IOCs class template implementation."""

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
        self.log_prefix = f"{self.plugin_name}"
        if name:
            self.log_prefix = f"{self.log_prefix} [{name}]"

    def _get_plugin_info(self) -> tuple:
        """Get plugin name and version from metadata.

        Returns:
            tuple: Tuple of plugin's name and version fetched from metadata.
        """
        try:
            plugin_name = "FalseIOC"
            plugin_version = "1.0.0"
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
        ioc_types = ["urls", "hosts", "md5", "sha256", "ipv4", "ipv6"]

        for ioc_type in ioc_types:
            if int(self.configuration.get(ioc_type, "value")) > 0:
                for i in range(1,int(self.configuration.get(ioc_type, "value"))):
                    current_type, current_value = self._get_data(self.configuration.get(ioc_type, "key"))
                    indicators.append(
                        Indicator(
                            value=current_value,
                            type=current_type,
                            severity=SeverityType.HIGH
                        )
                    )

        return indicators

    def _get_data(self, ioc_type) -> tuple[str, str]:
        """
        Extract indicators from a given response based on the specified indicator types.

        Args:
            ioc_type (str): the type of IOC for data generation

        Returns:
            Tuple[str,str]: A tuple containing the IOC type and a value.
        """
        letters = string.ascii_lowercase
        word = ''.join(random.choice(letters) for i in range(8)) + '.com'
        if ioc_type == "urls":
            current_type = IndicatorType.URL
            current_value = 'https://' + word + '/' + word
        elif ioc_type == "hosts":
            current_type = getattr(IndicatorType, "DOMAIN", IndicatorType.URL)
            current_value = word
        elif ioc_type == "md5":
            current_type = IndicatorType.MD5
            current_value = hashlib.md5(word.encode("utf")).hexdigest()
        elif ioc_tyupe == "sha256":
            current_type = IndicatorType.SHA256
            current_value = hashlib.sha256(word.encode("utf")).hexdigest()
        elif ioc_type == "ipv4":
            current_type = getattr(IndicatorType, "IPV4", IndicatorType.URL)
            current_value = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))
        else:
            current_type = getattr(IndicatorType, "IPV6", IndicatorType.URL)
            current_value = ':'.join('{:x}'.format(random.randint(0, 2**16 - 1)) for i in range(8))

        return current_type, current_value

    def validate(self, configuration) -> ValidationResult:
        """Validate the Plugin configuration parameters.

        Args:
            configuration (dict): Dict object having all the Plugin
            configuration parameters.
        Returns:
            cte.plugin_base.ValidationResult: ValidationResult object with
            success flag and message.
        """

        return ValidationResult(success=True, message="Validation Successful for False IOC plugin")
