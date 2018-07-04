# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You may not
# use this file except in compliance with the License. A copy of the License is
# located at
#     http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is distributed on
# an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
# express or implied. See the License for the specific language governing
# permissions and limitations under the License.

from gg_group_setup import GroupType


class MockGroupType(GroupType):
    MOCK_TYPE = 'mock'

    def __init__(self, config, region='us-west-2'):
        super(MockGroupType, self).__init__(
            config, region=region, type_name=MockGroupType.MOCK_TYPE
        )

    def get_core_definition(self, config):
        return [{
            "ThingArn": config['core']['thing_arn'],
            "CertificateArn": config['core']['cert_arn'],
            "Id": "{0}_00".format(self.type_name),
            "SyncShadow": True
        }]

    def get_device_definition(self, config):
        if 'GGD_example' in config['devices']:
            thing_arn = config['devices']['GGD_example']['thing_arn']
            cert_arn = config['devices']['GGD_example']['cert_arn']
            print("#### thing_arn:{0}".format(thing_arn))
            print("####  cert_arn:{0}".format(cert_arn))

            return [{
                "Id": "{0}_10".format(self.type_name),
                "ThingArn": thing_arn,
                "CertificateArn": cert_arn,
                "SyncShadow": False
            }]
        else:
            return None

    def get_subscription_definition(self, config):
        d = config['devices']
        lamb = config['lambda_functions']
        s = config['subscriptions']

        if 'GGD_example' in config['devices']:
            thing_arn = config['devices']['GGD_example']['thing_arn']

            return [
                {
                    "Id": "1",
                    "Source": thing_arn,
                    "Subject": s['telemetry'],
                    "Target": lamb['MockDevice']['arn']
                },
                {
                    "Id": "4",
                    "Source": thing_arn,
                    "Subject": s['telemetry'],
                    "Target": "cloud"
                },
                {
                    "Id": "14",
                    "Source": lamb['MockDevice']['arn'],
                    "Subject": s['errors'],
                    "Target": "cloud"
                }
            ]
        else:
            return None
